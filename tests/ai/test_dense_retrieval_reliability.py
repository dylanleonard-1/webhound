"""CONTROL-2D: dense retrieval reproducibility/reliability tests.

CI-safe: reads committed config + drives scripts via subprocess. The dense
*vectors* are never required (gitignored); only the build/fallback CONTRACT is
asserted. The actual embedding build is SKIPPED when sentence-transformers is
absent (e.g. the minimal ai-knowledge CI job).
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS = ROOT / "scripts" / "ai"
INDEX = ROOT / "corpus" / "index"
DENSE_BUILD = SCRIPTS / "build_dense_brain_embeddings.py"
CANON_BUILD = SCRIPTS / "build_canonical_brain_index.py"
TRACE = SCRIPTS / "check_brain_traceability.py"
CONFIG = INDEX / "retrieval_config.json"

_HAS_ST = importlib.util.find_spec("sentence_transformers") is not None


def _run(*args, timeout=300):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True,
                          cwd=str(ROOT), timeout=timeout)


@pytest.fixture(scope="module", autouse=True)
def _canonical_built():
    # Fresh-clone flow: regenerate the canonical chunk set (stdlib only, no network).
    # IMPORTANT: clean up afterward so this module's build artifacts don't pollute
    # other test modules (e.g. test_hybrid_retrieval, which expects the doc-index
    # fallback when no canonical dense embeddings exist).
    import shutil
    canon = INDEX / "canonical_chunks.jsonl"
    dense = INDEX / "dense"
    pre_canon, pre_dense = canon.exists(), dense.exists()
    r = _run(str(CANON_BUILD))
    assert r.returncode == 0, r.stderr
    yield
    if not pre_canon and canon.exists():
        canon.unlink()
    if not pre_dense and dense.exists():
        shutil.rmtree(dense, ignore_errors=True)


def test_dense_build_script_exists():
    assert DENSE_BUILD.exists()


def test_dense_dry_run_works():
    r = _run(str(DENSE_BUILD), "--dry-run")
    assert r.returncode == 0, r.stderr
    assert "chunks to embed:" in r.stdout
    assert "[dry-run]" in r.stdout


def test_retrieval_config_exposes_modes():
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    assert set(cfg["modes"]) == {"lexical", "dense", "hybrid"}
    assert "fallback_behavior" in cfg
    assert "dense_rebuild_cmd" in cfg


def test_traceability_supports_mode_flags():
    r = _run(str(TRACE), "--mode", "lexical", "--json")
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout.strip().splitlines()[-1])
    assert payload["requested_mode"] == "lexical"
    assert "counts" in payload and len(payload["results"]) == 10


def test_lexical_needs_no_dense_artifact():
    # Remove any local dense dir; lexical traceability must still run.
    import shutil
    dense = INDEX / "dense"
    if dense.exists():
        shutil.rmtree(dense, ignore_errors=True)
    r = _run(str(TRACE), "--mode", "lexical", "--json")
    assert r.returncode == 0, r.stderr


def test_missing_dense_warns_and_require_dense_fails():
    import shutil
    dense = INDEX / "dense"
    if dense.exists():
        shutil.rmtree(dense, ignore_errors=True)
    # hybrid without dense → warn + lexical fallback (exit 0)
    r = _run(str(TRACE), "--mode", "hybrid")
    assert r.returncode == 0
    assert "WARNING" in r.stderr and "build_dense_brain_embeddings" in r.stderr
    # --require-dense → hard fail (exit 2), no silent lexical
    r2 = _run(str(TRACE), "--mode", "dense", "--require-dense")
    assert r2.returncode == 2
    assert "ERROR" in r2.stderr


def test_no_dense_vectors_committed():
    tracked = subprocess.run(["git", "ls-files", "corpus/index/"], capture_output=True,
                             text=True, cwd=str(ROOT)).stdout
    for line in tracked.splitlines():
        assert not line.endswith(".npy"), f"vector blob committed: {line}"
        assert "canonical_chunks.jsonl" not in line, f"large chunk blob committed: {line}"


@pytest.mark.skipif(not _HAS_ST, reason="sentence-transformers not installed (minimal CI)")
def test_limited_dense_build_succeeds():
    r = _run(str(DENSE_BUILD), "--limit", "25", "--output-dir", "corpus/index/_dense_test")
    assert r.returncode == 0, r.stderr
    out = INDEX / "_dense_test"
    assert (out / "chunk_embeddings.npy").exists()
    man = json.loads((out / "embeddings_manifest.json").read_text())
    assert man["chunk_count"] == 25 and man["embedding_dim"] == 384
    import shutil
    shutil.rmtree(out, ignore_errors=True)


@pytest.mark.skipif(not _HAS_ST, reason="sentence-transformers not installed (minimal CI)")
def test_hybrid_quality_gate_on_seeded_shard():
    """CONTROL-2D CI gate: a concept-seeded shard must yield >=8/10 concepts found
    (top-k) under HYBRID. Concept-level (rank-robust), not exact ordering."""
    import shutil
    shard = INDEX / "_ci_shard_test"
    try:
        b = _run(str(DENSE_BUILD), "--seed-modules", "CI", "--sample", "1200",
                 "--output-dir", str(shard))
        assert b.returncode == 0, b.stderr
        assert (shard / "canonical_chunks.jsonl").exists() and (shard / "chunk_embeddings.npy").exists()
        g = _run(str(TRACE), "--index-dir", str(shard), "--mode", "hybrid",
                 "--min-found", "8", "--json")
        assert g.returncode == 0, f"gate failed: {g.stdout}\n{g.stderr}"
        payload = json.loads(g.stdout.strip().splitlines()[-1])
        assert payload["found"] >= 8, payload
        assert payload["dense_available"] is True
    finally:
        shutil.rmtree(shard, ignore_errors=True)
