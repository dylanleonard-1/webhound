"""CONTROL-2F: brain reality verification harness tests.

CI-safe: the dense retrieval run self-skips where sentence-transformers is absent;
the script-contract assertions run regardless. No network/Neo4j/Ollama required.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "scripts" / "ai" / "verify_brain_reality.py"
_HAS_ST = importlib.util.find_spec("sentence_transformers") is not None
_HAS_NP = importlib.util.find_spec("numpy") is not None


def _run(*args, timeout=600):
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True, cwd=str(ROOT), timeout=timeout)


@pytest.fixture(scope="module", autouse=True)
def _no_pollute():
    # Clean up canonical build artifacts this module may create so they don't
    # break other modules' doc-fallback dense tests (test_hybrid_retrieval).
    import shutil
    idx = ROOT / "corpus" / "index"
    canon, dense = idx / "canonical_chunks.jsonl", idx / "dense"
    pre_canon, pre_dense = canon.exists(), dense.exists()
    yield
    if not pre_canon and canon.exists():
        canon.unlink()
    if not pre_dense and dense.exists():
        shutil.rmtree(dense, ignore_errors=True)


def test_script_exists():
    assert SCRIPT.exists()


def test_required_concepts_covered():
    src = SCRIPT.read_text(encoding="utf-8")
    for concept in ("cookie_scanner", "domain_classifier", "tls_checker",
                    "wade", "auth", "verification", "threat_intel", "report"):
        assert concept in src.lower(), f"reality script missing concept: {concept}"


def test_no_network_imports():
    src = SCRIPT.read_text(encoding="utf-8")
    for banned in ("import requests", "urllib.request", "http.client", "socket.",
                   "openai", "anthropic"):
        assert banned not in src, f"reality script must be offline; found {banned}"


@pytest.mark.skipif(not (_HAS_ST and _HAS_NP),
                    reason="sentence-transformers/numpy not installed (minimal CI)")
def test_script_runs_and_reports_verdicts():
    # Fresh-clone flow: canonical chunks + dense vectors so verify runs in HYBRID
    # (its intended mode), not lexical fallback.
    subprocess.run([sys.executable, str(ROOT / "scripts/ai/build_canonical_brain_index.py")],
                   cwd=str(ROOT), check=True, capture_output=True, timeout=300)
    subprocess.run([sys.executable, str(ROOT / "scripts/ai/build_dense_brain_embeddings.py")],
                   cwd=str(ROOT), check=True, capture_output=True, timeout=600)
    r = _run("--json")
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout.strip().splitlines()[-1])
    assert len(payload["results"]) == 10
    verdicts = {x["verdict"] for x in payload["results"]}
    assert verdicts <= {"PASS", "PARTIAL", "FAIL"}
    # The code-lookup questions must at least be answerable (PASS or PARTIAL).
    by_id = {x["id"]: x["verdict"] for x in payload["results"]}
    for qid in ("cookie_impl", "tls_impl", "verify_flow"):
        assert by_id[qid] in ("PASS", "PARTIAL"), f"{qid} -> {by_id[qid]}"
