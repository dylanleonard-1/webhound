# Phase 8B Results — WADE Retrieval Integration

**Date:** 2026-06-14
**Branch:** feat/wade-phase-8b-retrieval-integration
**Status:** Complete — advisory mode only

## Summary

Phase 8B adds a local knowledge-base retrieval layer for WADE. WADE can now
READ from the WebHound AI Brain corpus to assemble advisory context for each
finding type. No production scoring, severity, suppression, or reporting was
modified.

## Deliverables

| File | Purpose | Lines |
|------|---------|-------|
| `scripts/wade/__init__.py` | Package exports | 35 |
| `scripts/wade/taxonomy_resolver.py` | CWE/OWASP mapping for 22 finding types | 178 |
| `scripts/wade/provider_resolver.py` | CDN/WAF provider query mapping | 125 |
| `scripts/wade/false_positive_resolver.py` | FP patterns for 22 finding types | 210 |
| `scripts/wade/language_resolver.py` | Customer-safe language for 22 finding types | 265 |
| `scripts/wade/retrieval_service.py` | WADERetrievalService (6 methods) | 120 |
| `scripts/wade/context_builder.py` | ReasoningContext builder | 175 |
| `tests/ai/test_wade_retrieval.py` | 61 tests | 310 |
| `scripts/ai/test_wade_reasoning.py` | Sandbox demo (4 queries) | 100 |

## Architecture

```
Finding type + provider
        │
        ▼
scripts/wade/
  ├── taxonomy_resolver.py   → CWE, OWASP, severity guidance, search query
  ├── provider_resolver.py   → Provider alias normalization, specialized queries
  ├── false_positive_resolver.py → Known FP patterns per finding type
  ├── language_resolver.py   → Customer-facing risk summaries + remediation
  ├── retrieval_service.py   → WADERetrievalService (wraps hybrid_retrieval)
  └── context_builder.py     → ReasoningContext assembly
        │
        ▼
  ReasoningContext (advisory, read-only)
```

## Supported Finding Types (22)

```
missing_csp            missing_hsts           missing_x_frame_options
missing_secure_cookie  missing_httponly_cookie missing_samesite_cookie
mixed_content          third_party_script_risk suspicious_javascript
threat_intel_match     provider_blocked_scan   cloudflare_challenge_page
vercel_deployment_protection
exposed_env            exposed_git             exposed_backup_file
wordpress_xmlrpc       graphql_exposure        swagger_exposure
tls_expiry             tls_misconfiguration    api_exposure
```

## 6 Retrieval Functions

| Method | Query Strategy | Use Case |
|--------|---------------|----------|
| `get_security_guidance(finding_type)` | Taxonomy query | CWE/OWASP/remediation evidence |
| `get_provider_context(finding_type, provider)` | Specialized or provider query | CDN/WAF context |
| `get_threat_intel_policy(finding_type)` | TI policy query | AbuseIPDB/GreyNoise/CDN IP guidance |
| `get_taxonomy_mapping(finding_type)` | CWE + OWASP query | Authoritative taxonomy references |
| `get_false_positive_patterns(finding_type)` | FP-specific query | Known benign condition patterns |
| `get_customer_safe_language(finding_type)` | Risk language query | Non-technical stakeholder text |

## ReasoningContext Fields (14)

```python
@dataclass
class ReasoningContext:
    finding_type: str
    retrieved_sources: list[dict]      # from get_security_guidance
    provider_context: list[dict]       # from get_provider_context
    taxonomy_context: dict[str, str]   # CWE, OWASP, severity_guidance
    threat_intel_context: list[dict]   # from get_threat_intel_policy
    false_positive_context: list[dict] # from get_false_positive_patterns
    customer_safe_language: dict       # risk_summary, remediation, escalation_note
    supporting_chunks: list[dict]      # all chunks de-duped by chunk_id
    authority_tiers: list[str]         # tiers present in supporting chunks
    reasoning_summary: str             # one-line human-readable summary
    retrieval_confidence: float        # 0.0–1.0 quality estimate
    brain_version: str                 # "8B"
    created_at: str                    # UTC ISO timestamp
    false_positive_patterns: list[str] # human-readable FP pattern descriptions
    false_positive_notes: str          # investigation guidance
    provider_name: str | None          # normalized provider display name
```

## Test Results

```
tests/ai/test_wade_retrieval.py   61 passed
tests/ai/ (full suite)            202 passed   (141 pre-8B + 61 new)
```

All dense/hybrid tests passed because the dense index is built locally.
Dense tests use `@pytest.mark.skipif` + `pytest.importorskip` to skip
gracefully in CI where numpy/sentence_transformers are absent.

## Security Constraints — All Verified

- [x] scanner/webhound/wade/ (production scoring) — NOT modified
- [x] scanner/provider-access/ — NOT modified
- [x] .mcp.json — NOT modified
- [x] No cloud APIs — all retrieval is local (hybrid_retrieval, all-MiniLM-L6-v2)
- [x] No customer data or credentials in any generated file
- [x] No production scoring/severity/confidence/suppression/report changes

## STATE OF WADE RETRIEVAL — Phase 8B Snapshot

```
knowledge_base_chunks : 1161
supported_finding_types : 22
retrieval_modes : lexical_only, dense_only, hybrid
dense_model : all-MiniLM-L6-v2 (local)
cloud_api_used : false
production_impact : none (advisory only)
brain_version : 8B
tests_passing : 202
phase : 8B-complete
date : 2026-06-14
```
