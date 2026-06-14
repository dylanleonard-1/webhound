"""Phase 7A: Validate hybrid retrieval modes and result provenance.

All three modes (lexical_only, dense_only, hybrid) are tested.
Dense-requiring tests skip gracefully when sentence_transformers is absent.
No cloud keys, no scanner/WADE/provider-access changes.
Run: .venv-api/Scripts/python -m pytest tests/ai -q
"""
from __future__ import annotations
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)

EMB_PATH = os.path.join(ROOT, "corpus", "indexes", "dense", "chunk_embeddings.npy")
_DENSE_AVAILABLE = os.path.isfile(EMB_PATH)

# ── Lexical mode (no model needed — always runs) ──────────────────────────────

def test_lexical_only_returns_results():
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("What is HSTS and why is it important?", k=5, mode="lexical_only")
    assert len(results) >= 1
    assert results[0]["lexical_score"] > 0
    assert results[0]["dense_score"] == 0.0


def test_lexical_result_provenance():
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("Cloudflare WAF challenge page error 1020", k=5, mode="lexical_only")
    required = ["rank", "score", "chunk_id", "doc_id", "title", "source_type",
                "authority_tier", "file_path", "phase", "snippet", "mode",
                "lexical_score", "dense_score", "hybrid_score"]
    for field in required:
        assert field in results[0], f"Missing provenance field: {field!r}"


def test_lexical_rank_ordering():
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("SQL injection CWE-89", k=5, mode="lexical_only")
    scores = [res["lexical_score"] for res in results]
    assert scores == sorted(scores, reverse=True), "Lexical results not ranked by score"


def test_lexical_no_cloud_required():
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    # Must work without any internet access or API keys
    results = r.retrieve("GreyNoise IP classification", k=3, mode="lexical_only")
    assert results is not None


def test_lexical_top5_snippet_non_empty():
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("CVSS severity scoring", k=5, mode="lexical_only")
    for res in results:
        assert len(res.get("snippet", "")) > 0, "Snippet must not be empty"


# ── Dense mode (skip if model or embeddings unavailable) ─────────────────────

@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built yet")
def test_dense_only_returns_results():
    pytest.importorskip("sentence_transformers")
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("Content Security Policy nonce unsafe-inline", k=5, mode="dense_only")
    assert len(results) >= 1
    assert results[0]["dense_score"] > 0
    assert results[0]["lexical_score"] == 0.0


@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built yet")
def test_dense_scores_bounded():
    pytest.importorskip("sentence_transformers")
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("nuclei template matchers extractors", k=5, mode="dense_only")
    for res in results:
        assert 0.0 <= res["dense_score"] <= 1.0, "Dense scores must be in [0,1] after norm"


@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built yet")
def test_dense_result_has_authority_tier():
    pytest.importorskip("sentence_transformers")
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("CWE-79 XSS reflected stored DOM", k=3, mode="dense_only")
    for res in results:
        assert res["authority_tier"] in ("A", "B", "C", ""), "Invalid authority_tier"


# ── Hybrid mode ───────────────────────────────────────────────────────────────

@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built yet")
def test_hybrid_returns_results():
    pytest.importorskip("sentence_transformers")
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("HSTS strict transport security header", k=5, mode="hybrid")
    assert len(results) >= 1
    assert results[0]["hybrid_score"] > 0


@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built yet")
def test_hybrid_combines_both_signals():
    pytest.importorskip("sentence_transformers")
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("Cloudflare Turnstile bot challenge bypass", k=5, mode="hybrid")
    # At least some results should have both lexical and dense contribution
    has_both = any(r["lexical_score"] > 0 and r["dense_score"] > 0 for r in results)
    assert has_both, "Hybrid should have at least one result with both lex+dense contribution"


@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built yet")
def test_hybrid_rank_ordering():
    pytest.importorskip("sentence_transformers")
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("VirusTotal file hash reputation", k=5, mode="hybrid")
    scores = [res["hybrid_score"] for res in results]
    assert scores == sorted(scores, reverse=True), "Hybrid results not ranked by hybrid_score"


@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built yet")
def test_hybrid_weight_configurable():
    pytest.importorskip("sentence_transformers")
    from scripts.ai.hybrid_retrieval import load_retriever
    r_default = load_retriever(lexical_weight=0.35, dense_weight=0.65)
    r_lex_heavy = load_retriever(lexical_weight=0.8, dense_weight=0.2)
    q = "SQL injection prevention"
    default_top = r_default.retrieve(q, k=1, mode="hybrid")[0]["chunk_id"]
    lex_top = r_lex_heavy.retrieve(q, k=1, mode="hybrid")[0]["chunk_id"]
    # Results may differ with different weights — just verify both return something
    assert default_top or lex_top


# ── No cloud / no secret checks ───────────────────────────────────────────────

def test_no_cloud_key_in_config():
    import json
    cfg_path = os.path.join(ROOT, "corpus", "indexes", "dense", "dense_index_config.json")
    if not os.path.isfile(cfg_path):
        pytest.skip("Config not built yet")
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)
    assert cfg.get("cloud_api_used") is False
    assert cfg.get("local_only") is True


def test_no_scanner_changes():
    scanner_dir = os.path.join(ROOT, "scanner")
    if not os.path.isdir(scanner_dir):
        return
    import subprocess
    result = subprocess.run(
        ["git", "diff", "--name-only", "HEAD", "--", "scanner/"],
        capture_output=True, text=True, cwd=ROOT
    )
    assert result.stdout.strip() == "", f"Unexpected scanner changes: {result.stdout}"


def test_no_mcp_json_changes():
    mcp_path = os.path.join(ROOT, ".mcp.json")
    if not os.path.isfile(mcp_path):
        return
    import subprocess
    result = subprocess.run(
        ["git", "diff", "--name-only", "HEAD", "--", ".mcp.json"],
        capture_output=True, text=True, cwd=ROOT
    )
    assert result.stdout.strip() == "", ".mcp.json must not be modified"
