"""CONTROL-2C: canonical code-aware brain index tests.

Reads the COMMITTED deterministic manifests (no embeddings, no network, no Ollama)
and asserts the brain index represents production code. Also runs the builder in
--dry-run to prove a fresh clone can regenerate.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
INDEX = ROOT / "corpus" / "index"
SOURCES = INDEX / "brain_sources_manifest.json"
CHUNKS = INDEX / "code_chunks_manifest.jsonl"


def _sources():
    return json.loads(SOURCES.read_text(encoding="utf-8"))


def _chunk_paths() -> set[str]:
    out = set()
    for line in CHUNKS.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.add(json.loads(line)["source_path"])
    return out


def test_manifests_exist():
    assert SOURCES.exists(), "brain_sources_manifest.json missing"
    assert CHUNKS.exists(), "code_chunks_manifest.jsonl missing"


def test_sources_manifest_shape():
    m = _sources()
    assert m["schema"] == "webhound.brain.sources.v1"
    assert m["deterministic"] is True
    assert m["counts"]["included"] > 0
    for s in m["sources"][:5]:
        assert {"source_id", "path", "status", "category"} <= set(s)


def test_scanner_included():
    paths = _chunk_paths()
    assert any(p.startswith("scanner/webhound/") for p in paths)


def test_api_included():
    paths = _chunk_paths()
    assert any(p.startswith("apps/api/") for p in paths)


def test_web_included():
    # CONTROL-2C closes the 2B gap: apps/web TS/TSX is indexed (regex symbol-level).
    paths = _chunk_paths()
    web = [p for p in paths if p.startswith("apps/web/")]
    assert web, "apps/web not represented in canonical index"


def test_key_modules_indexed():
    paths = _chunk_paths()
    required = [
        "scanner/webhound/engines/cookies/cookie_scanner.py",
        "scanner/webhound/threat_intel/domain_classifier.py",
        "scanner/webhound/engines/tls_dns/tls_checker.py",
        "scanner/webhound/core/orchestrator.py",
        "apps/api/routers/auth.py",
        "apps/api/services/verification.py",
    ]
    missing = [r for r in required if r not in paths]
    assert not missing, f"missing from canonical index: {missing}"


def test_production_wade_indexed():
    paths = _chunk_paths()
    assert any(p.startswith("scanner/webhound/wade/") for p in paths)


def test_no_secrets_or_local_artifacts_indexed():
    m = _sources()
    inc = [s["path"] for s in m["sources"] if s["status"] == "include"]
    forbidden_suffix = (".env", ".env.local", ".pem", ".key")
    forbidden_substr = ("node_modules/", "__pycache__/", ".venv", "/.next/",
                        "package-lock.json", "lightrag_storage/", "ruvector.db")
    for p in inc:
        low = p.lower()
        assert not low.endswith(forbidden_suffix), f"secret-like file indexed: {p}"
        assert not any(s in low for s in forbidden_substr), f"local artifact indexed: {p}"


def test_rebuild_dry_run_succeeds():
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "ai" / "build_canonical_brain_index.py"), "--dry-run"],
        capture_output=True, text=True, cwd=str(ROOT), timeout=300,
    )
    assert r.returncode == 0, r.stderr
    assert "code chunks:" in r.stdout
    assert "[dry-run] no files written" in r.stdout
