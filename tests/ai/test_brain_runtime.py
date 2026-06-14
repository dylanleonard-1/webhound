"""Phase 8C: Brain runtime query validation — ≥25 tests.

Validates source attribution, authority tiers, provenance, retrieval
consistency, and WADE advisory context across representative queries.

Dense/hybrid tests skip gracefully when numpy/sentence_transformers absent.

Run: .venv-api/Scripts/python -m pytest tests/ai/test_brain_runtime.py -v
"""
from __future__ import annotations
import json
import os
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)

EMB_PATH = os.path.join(ROOT, "corpus", "indexes", "dense", "chunk_embeddings.npy")
_DENSE_AVAILABLE = os.path.isfile(EMB_PATH)

HEALTH_JSON = os.path.join(ROOT, "docs", "ai", "brain_health.json")
VAULT_DIR = os.path.join(ROOT, "vault", "WebHound AI Brain")

# ── Retrieval helpers ─────────────────────────────────────────────────────────

def _retriever():
    from scripts.ai.hybrid_retrieval import load_retriever
    return load_retriever()


def _lex(query: str, k: int = 5) -> list[dict]:
    return _retriever().retrieve(query, k=k, mode="lexical_only")


def _context(finding_type: str, provider: str | None = None):
    from scripts.wade.context_builder import build_reasoning_context
    return build_reasoning_context(finding_type, provider=provider)


# ── 1. Retrieval: missing_csp ─────────────────────────────────────────────────

def test_query_01_missing_csp_hits():
    results = _lex("Content Security Policy CSP missing header XSS")
    assert len(results) >= 1
    texts = " ".join(r["snippet"] for r in results).lower()
    assert any(k in texts for k in ["csp", "content-security", "header"])


def test_query_01_missing_csp_authority_tier():
    results = _lex("Content Security Policy CSP missing header", k=3)
    if results:
        assert all("authority_tier" in r for r in results)


def test_query_01_missing_csp_source_attribution():
    results = _lex("Content Security Policy CSP missing header", k=3)
    if results:
        assert all(r.get("title") for r in results), "All results should have title"


# ── 2. Retrieval: Cloudflare challenge ────────────────────────────────────────

def test_query_02_cloudflare_challenge_context():
    results = _lex("Cloudflare WAF challenge page 1020 block bot protection")
    assert len(results) >= 1
    combined = " ".join(r.get("snippet", "") + r.get("title", "") for r in results).lower()
    assert "cloudflare" in combined


def test_query_02_cloudflare_wade_context():
    ctx = _context("cloudflare_challenge_page", provider="cloudflare")
    assert ctx.finding_type == "cloudflare_challenge_page"
    assert ctx.taxonomy_context.get("cwe") == "CWE-693"
    assert len(ctx.false_positive_patterns) >= 1


# ── 3. Retrieval: AbuseIPDB shared CDN ───────────────────────────────────────

def test_query_03_abuseipdb_cdn_rules():
    results = _lex("AbuseIPDB shared CDN IP address GreyNoise classification false positive")
    assert len(results) >= 1


def test_query_03_threat_intel_context():
    ctx = _context("threat_intel_match")
    assert ctx.taxonomy_context.get("cwe") == "CWE-200"
    assert any("CDN" in p or "shared" in p.lower() for p in ctx.false_positive_patterns)


# ── 4. Retrieval: CWE for XSS ────────────────────────────────────────────────

def test_query_04_cwe_xss_taxonomy():
    results = _lex("CWE-79 cross-site scripting XSS vulnerability classification")
    assert len(results) >= 1
    texts = " ".join(r["snippet"] for r in results).lower()
    assert any(k in texts for k in ["xss", "cross-site", "cwe"])


def test_query_04_xss_wade_taxonomy():
    ctx = _context("suspicious_javascript")
    assert ctx.taxonomy_context.get("cwe") == "CWE-79"
    owasp = ctx.taxonomy_context.get("owasp", "")
    assert owasp and len(owasp) > 3, f"OWASP field should be set, got: {owasp!r}"


# ── 5. Retrieval: evidence from external tools ────────────────────────────────

def test_query_05_external_tools_evidence():
    results = _lex("external tool evidence WADE scanner engine active confirmation Nuclei ZAP")
    assert len(results) >= 1


def test_query_05_dalfox_active_confirmation():
    results = _lex("DalFox XSS active confirmation engine confidence score")
    assert len(results) >= 1


# ── 6. Retrieval: exposed .env ────────────────────────────────────────────────

def test_query_06_exposed_env_critical():
    results = _lex("exposed .env environment file secrets credentials information disclosure")
    assert len(results) >= 1
    texts = " ".join(r["snippet"] for r in results).lower()
    assert any(k in texts for k in ["env", "secret", "credential", "disclosure"])


def test_query_06_exposed_env_severity():
    ctx = _context("exposed_env")
    assert "Critical" in ctx.taxonomy_context.get("severity_guidance", "")


def test_query_06_exposed_env_remediation():
    ctx = _context("exposed_env")
    lang = ctx.customer_safe_language
    assert "rotate" in lang.get("remediation", "").lower()


# ── 7. Retrieval: provider blocked scan ──────────────────────────────────────

def test_query_07_provider_blocked_scan():
    results = _lex("WAF CDN blocked scanner access denied coverage gap")
    assert len(results) >= 1


def test_query_07_provider_context_cloudflare():
    ctx = _context("provider_blocked_scan", provider="cloudflare")
    assert ctx.provider_name is not None
    assert isinstance(ctx.provider_context, list)


# ── 8. Retrieval: HSTS downgrade ─────────────────────────────────────────────

def test_query_08_hsts_downgrade():
    results = _lex("HSTS strict transport security downgrade attack MITM protocol")
    assert len(results) >= 1
    texts = " ".join(r["snippet"] for r in results).lower()
    assert any(k in texts for k in ["hsts", "strict", "transport", "downgrade"])


def test_query_08_hsts_taxonomy():
    ctx = _context("missing_hsts")
    assert ctx.taxonomy_context.get("cwe") == "CWE-319"


# ── 9. Retrieval: vercel deployment protection ────────────────────────────────

def test_query_09_vercel_deployment_protection():
    results = _lex("Vercel deployment protection preview auth gate scanner")
    assert len(results) >= 1
    combined = " ".join(r.get("title", "") + r.get("snippet", "") for r in results).lower()
    assert "vercel" in combined


def test_query_09_vercel_context():
    ctx = _context("vercel_deployment_protection", provider="vercel")
    assert "preview" in ctx.reasoning_summary.lower() or "vercel" in ctx.reasoning_summary.lower()


# ── 10. Retrieval: third-party script supply chain ───────────────────────────

def test_query_10_third_party_script_supply_chain():
    results = _lex("third-party script supply chain CDN SRI integrity check risk")
    assert len(results) >= 1


def test_query_10_third_party_cwe():
    ctx = _context("third_party_script_risk")
    assert ctx.taxonomy_context.get("cwe") == "CWE-829"


# ── 11. Retrieval: TLS/certificate ───────────────────────────────────────────

def test_query_11_tls_expiry():
    results = _lex("TLS certificate expiry expired HTTPS browser warning")
    assert len(results) >= 1


def test_query_11_tls_remediation():
    ctx = _context("tls_expiry")
    assert len(ctx.customer_safe_language.get("remediation", "")) > 20


# ── 12. Retrieval: GraphQL introspection ─────────────────────────────────────

def test_query_12_graphql_introspection():
    results = _lex("GraphQL introspection API schema exposure unauthorized")
    assert len(results) >= 1


# ── 13. Retrieval: WordPress XML-RPC ─────────────────────────────────────────

def test_query_13_wordpress_xmlrpc():
    results = _lex("WordPress XML-RPC xmlrpc.php brute force disable")
    assert len(results) >= 1


# ── 14. Source attribution and provenance ────────────────────────────────────

def test_query_14_source_attribution_fields():
    results = _lex("WADE scoring confidence threshold reporting", k=5)
    for r in results:
        assert "chunk_id" in r, "chunk_id required for provenance"
        assert "doc_id" in r, "doc_id required for provenance"
        assert "phase" in r, "phase required for provenance"


def test_query_14_authority_tier_values():
    results = _lex("CWE OWASP security standard vulnerability classification", k=5)
    tiers = {r.get("authority_tier", "") for r in results}
    assert len(tiers) >= 1
    # All tiers should be non-empty strings
    assert all(isinstance(t, str) for t in tiers)


# ── 15. Retrieval consistency ─────────────────────────────────────────────────

def test_query_15_deterministic_lexical():
    q = "Content Security Policy CSP missing header"
    r1 = _lex(q, k=3)
    r2 = _lex(q, k=3)
    ids1 = [r["chunk_id"] for r in r1]
    ids2 = [r["chunk_id"] for r in r2]
    assert ids1 == ids2, "Lexical retrieval must be deterministic"


def test_query_15_score_ordering():
    results = _lex("exposed .env secrets credentials", k=5)
    scores = [r["score"] for r in results]
    assert scores == sorted(scores, reverse=True), "Results must be sorted by score"


# ── 16. ReasoningContext completeness ────────────────────────────────────────

def test_query_16_context_all_fields_present():
    ctx = _context("missing_csp")
    assert ctx.brain_version == "8B"
    assert ctx.created_at.endswith("Z")
    assert ctx.finding_type == "missing_csp"
    assert isinstance(ctx.retrieved_sources, list)
    assert isinstance(ctx.taxonomy_context, dict)
    assert isinstance(ctx.customer_safe_language, dict)
    assert isinstance(ctx.false_positive_patterns, list)
    assert isinstance(ctx.supporting_chunks, list)
    assert isinstance(ctx.authority_tiers, list)
    assert isinstance(ctx.retrieval_confidence, float)
    assert 0.0 <= ctx.retrieval_confidence <= 1.0


def test_query_16_context_no_duplicates():
    ctx = _context("missing_csp")
    ids = [c["chunk_id"] for c in ctx.supporting_chunks if c.get("chunk_id")]
    assert len(ids) == len(set(ids)), "No duplicate chunks in supporting_chunks"


# ── 17. Brain health artifacts ───────────────────────────────────────────────

def test_query_17_health_json_exists():
    """Brain health JSON should exist after check_brain_health.py runs."""
    if not os.path.exists(HEALTH_JSON):
        pytest.skip("brain_health.json not generated yet — run check_brain_health.py")
    data = json.loads(open(HEALTH_JSON, encoding="utf-8").read())
    assert "corpus" in data
    assert "vault" in data
    assert "hybrid_retrieval" in data


def test_query_17_vault_note_count():
    import glob
    notes = glob.glob(os.path.join(VAULT_DIR, "**", "*.md"), recursive=True)
    assert len(notes) >= 50, f"Expected 50+ vault notes, got {len(notes)}"


# ── 18. Dense queries (skip if no index) ─────────────────────────────────────

@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built")
def test_query_18_dense_csp():
    pytest.importorskip("sentence_transformers")
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("What headers prevent XSS attacks?", k=5, mode="hybrid")
    assert len(results) >= 1
    assert results[0]["hybrid_score"] > 0


@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built")
def test_query_18_dense_cloudflare():
    pytest.importorskip("sentence_transformers")
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("WAF blocking scanners with challenge pages", k=5, mode="hybrid")
    assert len(results) >= 1


@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built")
def test_query_18_dense_provider_false_positive():
    pytest.importorskip("sentence_transformers")
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve(
        "When is a Cloudflare block page not a vulnerability?", k=5, mode="hybrid"
    )
    assert len(results) >= 1


# ── 19. Retrieval speed SLA ───────────────────────────────────────────────────

def test_query_19_lexical_speed_sla():
    """Lexical retrieval must complete 5 queries in under 3 seconds."""
    queries = [
        "Content Security Policy CSP missing header",
        "Cloudflare WAF challenge page 1020",
        "exposed .env environment file secrets",
        "HSTS strict transport security downgrade",
        "AbuseIPDB GreyNoise CDN IP reputation",
    ]
    r = _retriever()
    t0 = time.perf_counter()
    for q in queries:
        r.retrieve(q, k=5, mode="lexical_only")
    elapsed = time.perf_counter() - t0
    assert elapsed < 3.0, f"5 lexical queries took {elapsed:.2f}s (SLA: 3.0s)"
