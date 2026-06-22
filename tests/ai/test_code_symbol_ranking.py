"""CONTROL-2E: code-symbol ranking — exact module/symbol queries prefer CODE.

Robust by design: asserts a code chunk ranks ABOVE the best doc chunk (and that
the expected module is top-ranked) rather than checking absolute float scores,
so it does not flake across torch/BLAS builds. Requires the canonical index +
dense embeddings; self-skips if sentence-transformers is unavailable (minimal CI).
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

_HAS_ST = importlib.util.find_spec("sentence_transformers") is not None
_HAS_NP = importlib.util.find_spec("numpy") is not None
pytestmark = pytest.mark.skipif(not (_HAS_ST and _HAS_NP),
                                reason="sentence-transformers/numpy not installed (minimal CI)")

CODE = "production_code"


@pytest.fixture(scope="module")
def retr():
    # Fresh-clone flow: ensure canonical chunks + dense vectors exist. Clean up
    # afterward so this module's build artifacts don't pollute other test modules
    # (e.g. test_hybrid_retrieval's doc-fallback dense tests).
    import shutil
    idx = ROOT / "corpus" / "index"
    canon, dense = idx / "canonical_chunks.jsonl", idx / "dense"
    pre_canon, pre_dense = canon.exists(), dense.exists()
    subprocess.run([sys.executable, str(ROOT / "scripts/ai/build_canonical_brain_index.py")],
                   cwd=str(ROOT), check=True, capture_output=True, timeout=300)
    subprocess.run([sys.executable, str(ROOT / "scripts/ai/build_dense_brain_embeddings.py")],
                   cwd=str(ROOT), check=True, capture_output=True, timeout=600)
    from scripts.ai.hybrid_retrieval import load_retriever
    yield load_retriever()
    if not pre_canon and canon.exists():
        canon.unlink()
    if not pre_dense and dense.exists():
        shutil.rmtree(dense, ignore_errors=True)


def _top(retr, query, k=8):
    return retr.retrieve(query, k=k, mode="hybrid")


def _first_code_rank(hits, stem):
    for i, h in enumerate(hits):
        if h.get("chunk_type") == "code" and stem in h.get("file_path", ""):
            return i
    return None


def _first_doc_rank(hits):
    for i, h in enumerate(hits):
        if h.get("chunk_type") == "doc":
            return i
    return None


@pytest.mark.parametrize("query,stem", [
    ("tls checker certificate", "tls_checker"),
    ("cookie scanner security flags", "cookie_scanner"),
    ("domain classifier threat reputation", "domain_classifier"),
])
def test_code_outranks_docs(retr, query, stem):
    hits = _top(retr, query)
    code_rank = _first_code_rank(hits, stem)
    doc_rank = _first_doc_rank(hits)
    assert code_rank is not None, f"{stem} code not in top-k for {query!r}"
    if doc_rank is not None:
        assert code_rank < doc_rank, f"{stem}: code rank {code_rank} !< doc rank {doc_rank}"


def test_tls_checker_top_is_code(retr):
    hits = _top(retr, "tls checker certificate")
    assert hits[0].get("chunk_type") == "code"
    assert "tls_checker" in hits[0].get("file_path", "")


def test_orchestrator_top_is_code(retr):
    hits = _top(retr, "scanner orchestrator run scan engines")
    assert hits[0].get("chunk_type") == "code"
    assert "orchestrator" in hits[0].get("file_path", "")


def test_production_wade_top_is_code(retr):
    hits = _top(retr, "WADE baseline diff anomaly scorer")
    assert hits[0].get("chunk_type") == "code"
    assert "webhound/wade" in hits[0].get("file_path", "")


def test_exact_symbol_lookup_prefers_code(retr):
    # An exact module-name query must surface the real module as a code chunk #1.
    for stem in ("cookie_scanner", "tls_checker", "domain_classifier"):
        hits = _top(retr, stem.replace("_", " "))
        assert hits[0].get("chunk_type") == "code", f"{stem}: top is not code"
        assert stem in hits[0].get("file_path", ""), f"{stem}: top file mismatch"


# ── CONTROL-2E knowledge-query guard ───────────────────────────────────────────
# Prose/NL security questions must rank DOCUMENTATION/KNOWLEDGE first — the
# code-symbol/source-tier boost must NOT over-apply to them.
_PROSE_QUERIES = [
    "how does HSTS prevent downgrade attacks",
    "what does Content Security Policy help prevent",
    "how should webhook signatures be validated",
    "what causes Cloudflare challenge pages to block scanners",
    "how should threat-intel shared hosting false positives be handled",
]


@pytest.mark.parametrize("query", _PROSE_QUERIES)
def test_prose_query_is_not_code_seeking(query):
    # The symbol/source-tier code bias must be GATED OFF for prose questions.
    from scripts.ai.hybrid_retrieval import _is_symbol_like_query
    assert _is_symbol_like_query(query) is False, f"prose query wrongly treated as code-seeking: {query!r}"


@pytest.mark.parametrize("query", _PROSE_QUERIES)
def test_prose_query_top_is_doc(retr, query):
    # Top result for a natural-language guidance question must be docs/knowledge,
    # not arbitrary production code.
    hits = _top(retr, query)
    assert hits, f"no hits for {query!r}"
    assert hits[0].get("chunk_type") == "doc", (
        f"prose query returned CODE at top: {query!r} -> {hits[0].get('file_path')}")
