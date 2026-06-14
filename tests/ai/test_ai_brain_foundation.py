"""Phase 8A: AI Brain Foundation — 10 brain query tests via hybrid retrieval.

Each test sends a WADE-representative query to the hybrid retriever and
validates that the result set contains relevant chunks (by source, phase, or
topic_tags). Dense-requiring tests skip gracefully when sentence_transformers
is absent (CI environment has only pytest + jsonschema).

Run: .venv-api/Scripts/python -m pytest tests/ai/test_ai_brain_foundation.py -v
"""
from __future__ import annotations
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)

EMB_PATH = os.path.join(ROOT, "corpus", "indexes", "dense", "chunk_embeddings.npy")
LIGHTRAG_DOCS = os.path.join(ROOT, "corpus", "exports", "lightrag", "lightrag_documents.jsonl")
LIGHTRAG_META = os.path.join(ROOT, "corpus", "exports", "lightrag", "lightrag_metadata.json")
GRAPHITI_SEEDS = os.path.join(ROOT, "corpus", "exports", "graphiti_seeds.json")
VAULT_DIR = os.path.join(ROOT, "vault", "WebHound AI Brain")
WADE_INTERFACE_DOC = os.path.join(ROOT, "docs", "ai", "WADE_BRAIN_INTERFACE.md")

_DENSE_AVAILABLE = os.path.isfile(EMB_PATH)

# ── Artifact existence ─────────────────────────────────────────────────────────

def test_lightrag_docs_exist():
    assert os.path.isfile(LIGHTRAG_DOCS), f"LightRAG docs not found: {LIGHTRAG_DOCS}"


def test_lightrag_meta_exists():
    assert os.path.isfile(LIGHTRAG_META), f"LightRAG meta not found: {LIGHTRAG_META}"


def test_lightrag_doc_count():
    with open(LIGHTRAG_DOCS, encoding="utf-8") as f:
        count = sum(1 for l in f if l.strip())
    assert count == 1161, f"Expected 1161 LightRAG docs, got {count}"


def test_lightrag_doc_schema():
    with open(LIGHTRAG_DOCS, encoding="utf-8") as f:
        first = json.loads(next(l for l in f if l.strip()))
    for field in ["id", "doc_id", "content", "metadata"]:
        assert field in first, f"LightRAG doc missing field: {field!r}"
    for mf in ["title", "source_type", "authority_tier", "phase", "topic_tags"]:
        assert mf in first["metadata"], f"LightRAG doc metadata missing: {mf!r}"


def test_lightrag_no_cloud_key():
    with open(LIGHTRAG_META, encoding="utf-8") as f:
        meta = json.load(f)
    assert meta.get("cloud_api_used") is False
    assert meta.get("local_only") is True


def test_graphiti_seeds_exist():
    assert os.path.isfile(GRAPHITI_SEEDS), f"Graphiti seeds not found: {GRAPHITI_SEEDS}"


def test_graphiti_seed_count():
    with open(GRAPHITI_SEEDS, encoding="utf-8") as f:
        data = json.load(f)
    assert len(data["seeds"]) >= 10, "Expected at least 10 Graphiti seeds"
    assert len(data["memory_types"]) == 10, "Expected exactly 10 memory types"


def test_graphiti_no_customer_data():
    with open(GRAPHITI_SEEDS, encoding="utf-8") as f:
        text = f.read().lower()
    for bad in ["customer_id", "scan_result", "api_key", "sk-", "password"]:
        assert bad not in text, f"Graphiti seeds must not contain: {bad!r}"


def test_vault_dir_exists():
    assert os.path.isdir(VAULT_DIR), f"Vault directory not found: {VAULT_DIR}"


def test_vault_maps_folder():
    maps_dir = os.path.join(VAULT_DIR, "00-Maps")
    assert os.path.isdir(maps_dir), "00-Maps folder not found in vault"
    notes = [f for f in os.listdir(maps_dir) if f.endswith(".md")]
    assert len(notes) >= 5, f"Expected >= 5 MOC notes in 00-Maps, got {len(notes)}"


def test_vault_notes_have_generated_marker():
    MARKER = "<!-- WEBHOUND-GENERATED -->"
    missing = []
    for root_dir, _, files in os.walk(VAULT_DIR):
        for fname in files:
            if not fname.endswith(".md"):
                continue
            fpath = os.path.join(root_dir, fname)
            with open(fpath, encoding="utf-8", errors="replace") as f:
                content = f.read()
            if MARKER not in content:
                missing.append(os.path.relpath(fpath, ROOT))
    assert not missing, f"Vault notes missing generated marker: {missing[:5]}"


def test_vault_notes_have_frontmatter():
    checked = bad = 0
    for root_dir, _, files in os.walk(VAULT_DIR):
        for fname in files:
            if not fname.endswith(".md"):
                continue
            fpath = os.path.join(root_dir, fname)
            with open(fpath, encoding="utf-8", errors="replace") as f:
                content = f.read()
            checked += 1
            if not content.startswith("---"):
                bad += 1
    assert checked > 0, "No vault notes found to check"
    assert bad == 0, f"{bad}/{checked} vault notes missing YAML frontmatter"


def test_wade_interface_doc_exists():
    assert os.path.isfile(WADE_INTERFACE_DOC), "WADE Brain Interface doc not found"


def test_wade_interface_has_6_functions():
    with open(WADE_INTERFACE_DOC, encoding="utf-8") as f:
        text = f.read()
    for fn in [
        "retrieve_evidence", "check_false_positive", "get_provider_context",
        "lookup_taxonomy", "explain_finding", "retrieve_precedent"
    ]:
        assert fn in text, f"WADE interface doc missing function: {fn}"


# ── 10 Brain Queries (lexical mode — always runs) ─────────────────────────────

def _retriever():
    from scripts.ai.hybrid_retrieval import load_retriever
    return load_retriever()


def _lex(query: str, k: int = 5):
    return _retriever().retrieve(query, k=k, mode="lexical_only")


def test_brain_query_01_missing_csp():
    """Q1: What is Content-Security-Policy and why is it missing?"""
    results = _lex("Content Security Policy missing header CSP nonce")
    assert len(results) >= 1
    texts = " ".join(r["snippet"] for r in results).lower()
    assert any(kw in texts for kw in ["csp", "content-security", "header"]), (
        "Q1: Expected CSP-related content in top results"
    )


def test_brain_query_02_cloudflare_challenge():
    """Q2: What causes Cloudflare WAF challenge pages?"""
    results = _lex("Cloudflare WAF challenge page 1020 block")
    assert len(results) >= 1
    assert any("cloudflare" in r["title"].lower() or "cloudflare" in r["snippet"].lower()
               for r in results), "Q2: Expected Cloudflare docs in results"


def test_brain_query_03_abuseipdb_cdn():
    """Q3: How should WADE handle AbuseIPDB on shared CDN IPs?"""
    results = _lex("AbuseIPDB shared CDN IP address classification")
    assert len(results) >= 1


def test_brain_query_04_cwe_for_xss():
    """Q4: What CWE covers XSS cross-site scripting?"""
    results = _lex("CWE cross-site scripting XSS CWE-79 vulnerability class")
    assert len(results) >= 1
    texts = " ".join(r["snippet"] for r in results).lower()
    assert any(kw in texts for kw in ["xss", "cross-site", "cwe"]), (
        "Q4: Expected XSS/CWE content in results"
    )


def test_brain_query_05_severity_vs_confidence():
    """Q5: What is the difference between severity and confidence?"""
    results = _lex("severity confidence score CVSS WADE finding assessment")
    assert len(results) >= 1


def test_brain_query_06_why_not_auto_cve():
    """Q6: Why does WebHound not auto-assign CVEs?"""
    results = _lex("CVE assignment automated scanner false positive CVE ID")
    assert len(results) >= 1


def test_brain_query_07_vercel_deployment_protection():
    """Q7: What is Vercel deployment protection and how does it affect scanning?"""
    results = _lex("Vercel deployment protection preview auth gate scanner")
    assert len(results) >= 1
    assert any("vercel" in r["title"].lower() or "vercel" in r["snippet"].lower()
               for r in results), "Q7: Expected Vercel docs in results"


def test_brain_query_08_third_party_script_ti():
    """Q8: How should WADE handle third-party scripts and threat intelligence?"""
    results = _lex("third-party script threat intelligence VirusTotal hash reputation")
    assert len(results) >= 1


def test_brain_query_09_external_tools_as_evidence():
    """Q9: How do external tools (Nuclei, ZAP) generate evidence for WADE?"""
    results = _lex("external tool evidence WADE scanner engine active confirmation")
    assert len(results) >= 1


def test_brain_query_10_exposed_env():
    """Q10: What does an exposed .env file mean for security?"""
    results = _lex("exposed .env environment file secrets information disclosure")
    assert len(results) >= 1
    texts = " ".join(r["snippet"] for r in results).lower()
    assert any(kw in texts for kw in ["env", "secret", "exposure", "disclosure"]), (
        "Q10: Expected env/exposure content in results"
    )


# ── Dense brain queries (skip if model unavailable) ───────────────────────────

@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built yet")
def test_brain_query_dense_csp():
    """Dense: semantic retrieval for CSP query."""
    pytest.importorskip("sentence_transformers")
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve(
        "What headers prevent XSS attacks on web applications?", k=5, mode="hybrid"
    )
    assert len(results) >= 1
    assert results[0]["hybrid_score"] > 0


@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built yet")
def test_brain_query_dense_provider_waf():
    """Dense: semantic retrieval for WAF provider context."""
    pytest.importorskip("sentence_transformers")
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve(
        "WAF provider block page response suppression false positive", k=5, mode="hybrid"
    )
    assert len(results) >= 1
