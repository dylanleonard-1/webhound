"""Phase 8B: WADE Retrieval Integration — test suite (50+ tests).

Tests cover:
  - Module structure (imports, exports)
  - Taxonomy resolver (22 finding types)
  - Provider resolver (aliases, queries, specialized)
  - FP resolver (patterns, notes, queries)
  - Language resolver (risk summary, remediation)
  - Retrieval service (6 methods, graceful degradation)
  - Context builder (ReasoningContext structure and fields)
  - Retrieval quality (lexical always runs)
  - Dense/hybrid tests skip gracefully when numpy absent

Run: .venv-api/Scripts/python -m pytest tests/ai/test_wade_retrieval.py -v
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

# ── Module structure ───────────────────────────────────────────────────────────

def test_wade_package_importable():
    import scripts.wade  # noqa: F401


def test_wade_init_exports():
    from scripts.wade import (
        WADERetrievalService, load_wade_retrieval_service,
        ReasoningContext, build_reasoning_context,
        SUPPORTED_FINDING_TYPES, resolve_taxonomy,
        normalize_provider, resolve_provider_query,
        resolve_fp_patterns, resolve_fp_query,
        resolve_customer_language, resolve_risk_summary,
    )
    assert callable(load_wade_retrieval_service)
    assert callable(build_reasoning_context)
    assert isinstance(SUPPORTED_FINDING_TYPES, frozenset)


def test_taxonomy_resolver_importable():
    from scripts.wade.taxonomy_resolver import (
        TAXONOMY_MAP, SUPPORTED_FINDING_TYPES, resolve_taxonomy,
    )
    assert isinstance(TAXONOMY_MAP, dict)
    assert isinstance(SUPPORTED_FINDING_TYPES, frozenset)
    assert callable(resolve_taxonomy)


def test_provider_resolver_importable():
    from scripts.wade.provider_resolver import (
        PROVIDER_ALIASES, PROVIDER_QUERY_MAP, normalize_provider,
        resolve_provider_query, get_provider_name,
    )
    assert callable(normalize_provider)
    assert callable(resolve_provider_query)


def test_fp_resolver_importable():
    from scripts.wade.false_positive_resolver import (
        FP_PATTERN_MAP, resolve_fp_patterns, resolve_fp_query, resolve_fp_notes,
    )
    assert callable(resolve_fp_patterns)
    assert callable(resolve_fp_query)


def test_language_resolver_importable():
    from scripts.wade.language_resolver import (
        CUSTOMER_LANGUAGE, resolve_customer_language, resolve_risk_summary, resolve_remediation,
    )
    assert callable(resolve_customer_language)
    assert callable(resolve_risk_summary)


def test_retrieval_service_importable():
    from scripts.wade.retrieval_service import (
        WADERetrievalService, load_wade_retrieval_service,
    )
    assert callable(load_wade_retrieval_service)


def test_context_builder_importable():
    from scripts.wade.context_builder import ReasoningContext, build_reasoning_context
    assert callable(build_reasoning_context)


# ── Taxonomy resolver ─────────────────────────────────────────────────────────

def test_taxonomy_has_22_finding_types():
    from scripts.wade.taxonomy_resolver import TAXONOMY_MAP
    assert len(TAXONOMY_MAP) == 22, f"Expected 22, got {len(TAXONOMY_MAP)}"


def test_taxonomy_supported_types_match_map():
    from scripts.wade.taxonomy_resolver import TAXONOMY_MAP, SUPPORTED_FINDING_TYPES
    assert SUPPORTED_FINDING_TYPES == frozenset(TAXONOMY_MAP)


def test_taxonomy_each_entry_has_required_fields():
    from scripts.wade.taxonomy_resolver import TAXONOMY_MAP
    required = {"cwe", "cwe_name", "owasp", "severity_guidance", "query"}
    for ft, entry in TAXONOMY_MAP.items():
        missing = required - set(entry)
        assert not missing, f"{ft} missing taxonomy fields: {missing}"


def test_taxonomy_resolve_missing_csp():
    from scripts.wade.taxonomy_resolver import resolve_taxonomy
    tax = resolve_taxonomy("missing_csp")
    assert tax["cwe"] == "CWE-693"
    assert "CSP" in tax["query"] or "Content Security" in tax["query"]


def test_taxonomy_resolve_exposed_env():
    from scripts.wade.taxonomy_resolver import resolve_taxonomy
    tax = resolve_taxonomy("exposed_env")
    assert tax["cwe"] == "CWE-312"
    assert "Critical" in tax["severity_guidance"]


def test_taxonomy_resolve_unknown_falls_back():
    from scripts.wade.taxonomy_resolver import resolve_taxonomy
    tax = resolve_taxonomy("nonexistent_finding_type")
    assert tax["cwe"] == "CWE-unknown"
    assert "severity_guidance" in tax


def test_taxonomy_no_empty_cwe():
    from scripts.wade.taxonomy_resolver import TAXONOMY_MAP
    for ft, entry in TAXONOMY_MAP.items():
        assert entry["cwe"], f"{ft} has empty CWE"
        assert entry["cwe"].startswith("CWE-"), f"{ft} CWE doesn't start with CWE-"


# ── Provider resolver ─────────────────────────────────────────────────────────

def test_provider_aliases_normalize_cf():
    from scripts.wade.provider_resolver import normalize_provider
    assert normalize_provider("cf") == "cloudflare"
    assert normalize_provider("Cloudflare") == "cloudflare"
    assert normalize_provider("CLOUDFLARE") == "cloudflare"


def test_provider_aliases_normalize_gcp():
    from scripts.wade.provider_resolver import normalize_provider
    assert normalize_provider("gcp") == "google-cloud"
    assert normalize_provider("google") == "google-cloud"


def test_provider_aliases_unknown_returns_none():
    from scripts.wade.provider_resolver import normalize_provider
    assert normalize_provider("unknown_provider_xyz") is None
    assert normalize_provider(None) is None


def test_provider_resolve_specialized_cloudflare_challenge():
    from scripts.wade.provider_resolver import resolve_provider_query
    q = resolve_provider_query("cloudflare_challenge_page", "cloudflare")
    assert "cloudflare" in q.lower() or "1020" in q.lower()


def test_provider_resolve_specialized_vercel_protection():
    from scripts.wade.provider_resolver import resolve_provider_query
    q = resolve_provider_query("vercel_deployment_protection", "vercel")
    assert "vercel" in q.lower()


def test_provider_resolve_generic_query():
    from scripts.wade.provider_resolver import resolve_provider_query
    q = resolve_provider_query("missing_csp", "fastly")
    assert len(q) > 5


def test_provider_get_name():
    from scripts.wade.provider_resolver import get_provider_name
    assert get_provider_name("cf") == "cloudflare"
    assert get_provider_name(None) == "Unknown"


def test_provider_finding_types_set():
    from scripts.wade.provider_resolver import PROVIDER_FINDING_TYPES
    assert "cloudflare_challenge_page" in PROVIDER_FINDING_TYPES
    assert "vercel_deployment_protection" in PROVIDER_FINDING_TYPES
    assert "provider_blocked_scan" in PROVIDER_FINDING_TYPES


# ── FP resolver ───────────────────────────────────────────────────────────────

def test_fp_has_all_22_finding_types():
    from scripts.wade.false_positive_resolver import FP_PATTERN_MAP
    assert len(FP_PATTERN_MAP) == 22, f"Expected 22, got {len(FP_PATTERN_MAP)}"


def test_fp_patterns_are_nonempty():
    from scripts.wade.false_positive_resolver import FP_PATTERN_MAP
    for ft, entry in FP_PATTERN_MAP.items():
        assert len(entry["patterns"]) >= 1, f"{ft} has no FP patterns"


def test_fp_resolve_missing_csp():
    from scripts.wade.false_positive_resolver import resolve_fp_patterns
    patterns = resolve_fp_patterns("missing_csp")
    assert any("CDN" in p or "Meta" in p or "meta" in p for p in patterns)


def test_fp_resolve_cloudflare_challenge():
    from scripts.wade.false_positive_resolver import resolve_fp_patterns
    patterns = resolve_fp_patterns("cloudflare_challenge_page")
    assert any("Cloudflare" in p or "WAF" in p for p in patterns)


def test_fp_resolve_unknown_returns_fallback():
    from scripts.wade.false_positive_resolver import resolve_fp_patterns
    patterns = resolve_fp_patterns("totally_unknown_type")
    assert len(patterns) == 1
    assert "totally_unknown_type" in patterns[0]


def test_fp_query_is_nonempty():
    from scripts.wade.false_positive_resolver import resolve_fp_query
    for ft in [
        "missing_csp", "threat_intel_match", "exposed_env", "cloudflare_challenge_page"
    ]:
        q = resolve_fp_query(ft)
        assert len(q) > 5, f"{ft} FP query is too short"


def test_fp_notes_are_nonempty():
    from scripts.wade.false_positive_resolver import resolve_fp_notes
    for ft in ["missing_csp", "exposed_env", "cloudflare_challenge_page"]:
        note = resolve_fp_notes(ft)
        assert len(note) > 5, f"{ft} FP note is empty"


# ── Language resolver ─────────────────────────────────────────────────────────

def test_language_has_all_22_finding_types():
    from scripts.wade.language_resolver import CUSTOMER_LANGUAGE
    assert len(CUSTOMER_LANGUAGE) == 22, f"Expected 22, got {len(CUSTOMER_LANGUAGE)}"


def test_language_each_entry_has_required_keys():
    from scripts.wade.language_resolver import CUSTOMER_LANGUAGE
    for ft, entry in CUSTOMER_LANGUAGE.items():
        for key in ["risk_summary", "remediation", "escalation_note"]:
            assert key in entry, f"{ft} missing language key: {key}"
            assert len(entry[key]) > 10, f"{ft}.{key} is too short"


def test_language_resolve_exposed_env():
    from scripts.wade.language_resolver import resolve_customer_language
    lang = resolve_customer_language("exposed_env")
    assert "credentials" in lang["risk_summary"].lower() or "secret" in lang["risk_summary"].lower()
    assert "rotate" in lang["remediation"].lower()


def test_language_resolve_unknown_fallback():
    from scripts.wade.language_resolver import resolve_customer_language
    lang = resolve_customer_language("not_a_real_finding")
    assert "risk_summary" in lang
    assert "remediation" in lang


def test_language_resolve_risk_summary():
    from scripts.wade.language_resolver import resolve_risk_summary
    summary = resolve_risk_summary("missing_csp")
    assert len(summary) > 20


def test_language_resolve_remediation():
    from scripts.wade.language_resolver import resolve_remediation
    r = resolve_remediation("missing_hsts")
    assert "Strict-Transport-Security" in r or "HSTS" in r


# ── Retrieval service ─────────────────────────────────────────────────────────

def test_service_loads():
    from scripts.wade.retrieval_service import load_wade_retrieval_service
    svc = load_wade_retrieval_service()
    assert svc is not None


def test_service_get_security_guidance_returns_list():
    from scripts.wade.retrieval_service import load_wade_retrieval_service
    svc = load_wade_retrieval_service()
    results = svc.get_security_guidance("missing_csp", k=3)
    assert isinstance(results, list)


def test_service_get_security_guidance_csp_hits():
    from scripts.wade.retrieval_service import load_wade_retrieval_service
    svc = load_wade_retrieval_service()
    results = svc.get_security_guidance("missing_csp", k=5)
    if results:
        texts = " ".join(r.get("snippet", "") for r in results).lower()
        assert any(kw in texts for kw in ["csp", "content-security", "header"]), (
            "Expected CSP-related content in security guidance"
        )


def test_service_get_provider_context_cloudflare():
    from scripts.wade.retrieval_service import load_wade_retrieval_service
    svc = load_wade_retrieval_service()
    results = svc.get_provider_context("cloudflare_challenge_page", provider="cloudflare", k=5)
    assert isinstance(results, list)


def test_service_get_threat_intel_policy():
    from scripts.wade.retrieval_service import load_wade_retrieval_service
    svc = load_wade_retrieval_service()
    results = svc.get_threat_intel_policy(k=5)
    assert isinstance(results, list)


def test_service_get_taxonomy_mapping():
    from scripts.wade.retrieval_service import load_wade_retrieval_service
    svc = load_wade_retrieval_service()
    results = svc.get_taxonomy_mapping("exposed_env", k=3)
    assert isinstance(results, list)


def test_service_get_false_positive_patterns():
    from scripts.wade.retrieval_service import load_wade_retrieval_service
    svc = load_wade_retrieval_service()
    results = svc.get_false_positive_patterns("threat_intel_match", k=5)
    assert isinstance(results, list)


def test_service_get_customer_safe_language():
    from scripts.wade.retrieval_service import load_wade_retrieval_service
    svc = load_wade_retrieval_service()
    results = svc.get_customer_safe_language("missing_csp", k=3)
    assert isinstance(results, list)


def test_service_none_retriever_returns_empty():
    from scripts.wade.retrieval_service import WADERetrievalService
    svc = WADERetrievalService(None)
    assert svc.get_security_guidance("missing_csp") == []
    assert svc.get_provider_context("missing_csp", "cloudflare") == []
    assert svc.get_threat_intel_policy() == []
    assert svc.get_taxonomy_mapping("missing_csp") == []
    assert svc.get_false_positive_patterns("missing_csp") == []
    assert svc.get_customer_safe_language("missing_csp") == []


# ── Context builder ───────────────────────────────────────────────────────────

def test_context_builder_returns_reasoning_context():
    from scripts.wade.context_builder import build_reasoning_context, ReasoningContext
    ctx = build_reasoning_context("missing_csp")
    assert isinstance(ctx, ReasoningContext)


def test_context_has_required_fields():
    from scripts.wade.context_builder import build_reasoning_context
    ctx = build_reasoning_context("missing_csp")
    assert ctx.finding_type == "missing_csp"
    assert ctx.brain_version == "8B"
    assert ctx.created_at.endswith("Z")
    assert isinstance(ctx.taxonomy_context, dict)
    assert isinstance(ctx.customer_safe_language, dict)
    assert isinstance(ctx.false_positive_patterns, list)
    assert isinstance(ctx.reasoning_summary, str)


def test_context_taxonomy_populated():
    from scripts.wade.context_builder import build_reasoning_context
    ctx = build_reasoning_context("missing_csp")
    assert ctx.taxonomy_context.get("cwe") == "CWE-693"


def test_context_fp_patterns_populated():
    from scripts.wade.context_builder import build_reasoning_context
    ctx = build_reasoning_context("cloudflare_challenge_page")
    assert len(ctx.false_positive_patterns) >= 1


def test_context_reasoning_summary_nonempty():
    from scripts.wade.context_builder import build_reasoning_context
    ctx = build_reasoning_context("exposed_env")
    assert "exposed_env" in ctx.reasoning_summary
    assert len(ctx.reasoning_summary) > 20


def test_context_with_provider():
    from scripts.wade.context_builder import build_reasoning_context
    ctx = build_reasoning_context("cloudflare_challenge_page", provider="cloudflare")
    assert ctx.provider_name is not None
    assert isinstance(ctx.provider_context, list)


def test_context_confidence_is_float():
    from scripts.wade.context_builder import build_reasoning_context
    ctx = build_reasoning_context("missing_csp")
    assert isinstance(ctx.retrieval_confidence, float)
    assert 0.0 <= ctx.retrieval_confidence <= 1.0


def test_context_supporting_chunks_deduped():
    from scripts.wade.context_builder import build_reasoning_context
    ctx = build_reasoning_context("missing_csp")
    ids = [c.get("chunk_id") for c in ctx.supporting_chunks if c.get("chunk_id")]
    assert len(ids) == len(set(ids)), "Duplicate chunk IDs in supporting_chunks"


def test_context_unknown_finding_type_graceful():
    from scripts.wade.context_builder import build_reasoning_context
    ctx = build_reasoning_context("unknown_xyz_finding")
    assert ctx.finding_type == "unknown_xyz_finding"
    assert ctx.brain_version == "8B"
    assert "unknown_xyz_finding" in ctx.reasoning_summary


def test_context_customer_safe_language_keys():
    from scripts.wade.context_builder import build_reasoning_context
    ctx = build_reasoning_context("exposed_env")
    lang = ctx.customer_safe_language
    assert "risk_summary" in lang
    assert "remediation" in lang


# ── Retrieval quality (lexical always runs) ────────────────────────────────────

def test_retrieval_missing_csp_returns_csp_content():
    from scripts.wade.retrieval_service import load_wade_retrieval_service
    svc = load_wade_retrieval_service()
    results = svc.get_security_guidance("missing_csp", k=5)
    if not results:
        pytest.skip("No corpus chunks available")
    texts = " ".join(r.get("snippet", "") for r in results).lower()
    assert any(kw in texts for kw in ["csp", "content-security", "header", "policy"])


def test_retrieval_cloudflare_challenge_returns_cloudflare_content():
    from scripts.wade.retrieval_service import load_wade_retrieval_service
    svc = load_wade_retrieval_service()
    results = svc.get_provider_context("cloudflare_challenge_page", provider="cloudflare", k=5)
    if not results:
        pytest.skip("No corpus chunks available")
    texts = " ".join(
        r.get("snippet", "") + r.get("title", "") for r in results
    ).lower()
    assert "cloudflare" in texts


def test_retrieval_exposed_env_returns_env_content():
    from scripts.wade.retrieval_service import load_wade_retrieval_service
    svc = load_wade_retrieval_service()
    results = svc.get_security_guidance("exposed_env", k=5)
    if not results:
        pytest.skip("No corpus chunks available")
    texts = " ".join(r.get("snippet", "") for r in results).lower()
    assert any(kw in texts for kw in ["env", "secret", "credential", "exposure"])


def test_retrieval_results_have_required_fields():
    from scripts.wade.retrieval_service import load_wade_retrieval_service
    svc = load_wade_retrieval_service()
    results = svc.get_security_guidance("missing_csp", k=3)
    if not results:
        pytest.skip("No corpus chunks available")
    for r in results:
        for field in ["rank", "score", "snippet", "title", "source_type"]:
            assert field in r, f"Result missing field: {field}"


# ── Dense/hybrid tests — skip gracefully ──────────────────────────────────────

@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built yet")
def test_dense_security_guidance_csp():
    pytest.importorskip("sentence_transformers")
    from scripts.wade.retrieval_service import WADERetrievalService
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    svc = WADERetrievalService(r)
    results = svc.get_security_guidance("missing_csp", k=5)
    assert len(results) >= 1
    assert results[0]["hybrid_score"] > 0


@pytest.mark.skipif(not _DENSE_AVAILABLE, reason="dense index not built yet")
def test_dense_context_confidence_above_zero():
    pytest.importorskip("sentence_transformers")
    from scripts.wade.context_builder import build_reasoning_context
    ctx = build_reasoning_context("missing_csp")
    assert ctx.retrieval_confidence > 0.0
