"""CONTROL-2G: retrieval intent routing (code vs knowledge vs mixed).

Rank-robust: assert the TYPE of the top result (code/doc) and presence-in-top-k,
never absolute scores. Intent classification is pure (no index) and always tested;
the retrieval assertions self-skip without sentence-transformers (minimal CI).
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from scripts.ai.hybrid_retrieval import (  # noqa: E402
    INTENT_CODE, INTENT_KNOWLEDGE, INTENT_MIXED, classify_intent,
)

_HAS_ST = importlib.util.find_spec("sentence_transformers") is not None
_HAS_NP = importlib.util.find_spec("numpy") is not None


# ── Intent classification (pure; always runs) ──────────────────────────────────
@pytest.mark.parametrize("q", [
    "where is WADE implemented", "what handles threat intelligence",
    "which module performs TLS checking", "where does scanner orchestrator live",
    "which file handles API authentication", "where is report rendering implemented",
])
def test_classify_code_lookup(q):
    assert classify_intent(q) == INTENT_CODE


@pytest.mark.parametrize("q", [
    "how does HSTS prevent downgrade attacks", "what does CSP help prevent",
    "how should webhook signatures be validated",
    "what causes Cloudflare challenge pages to block scanners",
    "how should threat-intel shared hosting false positives be handled",
])
def test_classify_knowledge(q):
    assert classify_intent(q) == INTENT_KNOWLEDGE


@pytest.mark.parametrize("q", [
    "where is CSP handled and what does it prevent",
    "where is webhook verification implemented and how should signatures be validated",
])
def test_classify_mixed(q):
    assert classify_intent(q) == INTENT_MIXED


# ── Routed retrieval (needs the dense index) ───────────────────────────────────
@pytest.fixture(scope="module")
def retr():
    import shutil
    idx = ROOT / "corpus" / "index"
    canon, dense = idx / "canonical_chunks.jsonl", idx / "dense"
    pre_c, pre_d = canon.exists(), dense.exists()
    subprocess.run([sys.executable, str(ROOT / "scripts/ai/build_canonical_brain_index.py")],
                   cwd=str(ROOT), check=True, capture_output=True, timeout=300)
    subprocess.run([sys.executable, str(ROOT / "scripts/ai/build_dense_brain_embeddings.py")],
                   cwd=str(ROOT), check=True, capture_output=True, timeout=600)
    from scripts.ai.hybrid_retrieval import load_retriever
    yield load_retriever()
    if not pre_c and canon.exists():
        canon.unlink()
    if not pre_d and dense.exists():
        shutil.rmtree(dense, ignore_errors=True)


pytestmark_retr = pytest.mark.skipif(not (_HAS_ST and _HAS_NP),
                                     reason="sentence-transformers/numpy not installed")


@pytestmark_retr
@pytest.mark.parametrize("q", [
    "where is WADE implemented", "what handles threat intelligence",
    "which module performs TLS checking", "where does scanner orchestrator live",
    "which file handles API authentication", "where is report rendering implemented",
])
def test_code_lookup_top_is_code(retr, q):
    assert retr.retrieve(q, k=5, mode="hybrid")[0]["chunk_type"] == "code", q


@pytestmark_retr
@pytest.mark.parametrize("q", [
    "how does HSTS prevent downgrade attacks", "what does CSP help prevent",
    "how should webhook signatures be validated",
    "what causes Cloudflare challenge pages to block scanners",
    "how should threat-intel shared hosting false positives be handled",
])
def test_knowledge_top_is_doc(retr, q):
    assert retr.retrieve(q, k=5, mode="hybrid")[0]["chunk_type"] == "doc", q


@pytestmark_retr
@pytest.mark.parametrize("q", [
    "where is CSP handled and what does it prevent",
    "where is webhook verification implemented and how should signatures be validated",
])
def test_mixed_top5_has_both(retr, q):
    types = {h["chunk_type"] for h in retr.retrieve(q, k=5, mode="hybrid")}
    assert "code" in types and "doc" in types, f"{q} -> {types}"
