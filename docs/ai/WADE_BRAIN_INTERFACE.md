# WADE Brain Interface

Interface design for WADE (WebHound Automated Detection Engine) to query the
WebHound AI Knowledge Brain. This document defines inputs, retrieval functions,
and outputs — no WADE implementation logic is included.

## Purpose

WADE uses the knowledge brain to:
1. Fetch supporting evidence for a potential finding
2. Retrieve known FP patterns before finalizing confidence
3. Look up provider behavior context
4. Map findings to CWE/OWASP classifications
5. Generate human-readable explanations
6. Retrieve precedent decisions for similar findings

## Input Types (8)

| Input | Schema | Description |
|-------|--------|-------------|
| `FindingContext` | `{type, url, parameter, payload, response_code, scanner}` | Raw scanner finding |
| `ProviderContext` | `{provider_name, category, headers, ip, response_signature}` | Detected provider/CDN info |
| `ThreatIntelContext` | `{ip, domain, hash, source}` | TI enrichment data |
| `ScannerContext` | `{engine, rule_id, confidence, raw_evidence}` | Scanner-level metadata |
| `TaxonomyQuery` | `{finding_type, owasp_id, cwe_id}` | Classification lookup request |
| `FPCheckQuery` | `{finding_type, provider, response_code, pattern}` | FP suppression check |
| `ExplanationQuery` | `{finding_id, audience}` | Request for human-readable explanation |
| `PrecedentQuery` | `{finding_type, provider, confidence_range}` | Historical precedent lookup |

## Retrieval Functions (6)

### 1. `retrieve_evidence(finding_ctx: FindingContext, k: int = 5) → list[KnowledgeChunk]`

Fetches knowledge chunks that support or contextualize a finding.

```python
chunks = brain.retrieve_evidence(
    FindingContext(
        type="xss_reflected",
        url="https://example.com/search?q=<script>",
        parameter="q",
        scanner="dalfox",
    ),
    k=5
)
# Returns: [KnowledgeChunk(chunk_id, title, text, source_type, authority_tier, score)]
```

Query strategy: `hybrid` mode, query string constructed as `"{type} {parameter} evidence"`

---

### 2. `check_false_positive(fp_query: FPCheckQuery) → FPResult`

Retrieves FP suppression patterns matching the finding context.

```python
result = brain.check_false_positive(
    FPCheckQuery(
        finding_type="missing_csp",
        provider="cloudflare",
        response_code=1020,
    )
)
# Returns: FPResult(is_likely_fp, confidence_adjustment, supporting_chunks, reason)
```

Query strategy: `hybrid` mode, query string `"false positive {finding_type} {provider} suppress"`

---

### 3. `get_provider_context(prov_ctx: ProviderContext) → ProviderKnowledge`

Retrieves provider-specific behavioral documentation.

```python
pk = brain.get_provider_context(
    ProviderContext(provider_name="cloudflare", category="cdn")
)
# Returns: ProviderKnowledge(provider, behavior_notes, challenge_signatures, chunks)
```

Query strategy: `lexical_only` mode for provider name + category terms.

---

### 4. `lookup_taxonomy(query: TaxonomyQuery) → TaxonomyResult`

Maps a finding type to CWE, OWASP, and severity.

```python
tax = brain.lookup_taxonomy(
    TaxonomyQuery(finding_type="xss_reflected", owasp_id="A03")
)
# Returns: TaxonomyResult(cwe_id, cwe_name, owasp_category, severity_range, references)
```

Query strategy: `dense_only` mode, optimized for semantic taxonomy matching.

---

### 5. `explain_finding(query: ExplanationQuery) → Explanation`

Retrieves knowledge to construct a human-readable explanation.

```python
exp = brain.explain_finding(
    ExplanationQuery(finding_id="find-001", audience="technical")
)
# Returns: Explanation(summary, technical_detail, remediation, references, chunks_used)
```

Query strategy: `hybrid` mode, composite query from finding metadata.

---

### 6. `retrieve_precedent(query: PrecedentQuery) → list[PrecedentChunk]`

Retrieves past WADE decision patterns for similar findings (via Graphiti memory).

```python
precedents = brain.retrieve_precedent(
    PrecedentQuery(
        finding_type="waf_bypass",
        provider="cloudflare",
        confidence_range=(0.3, 0.6)
    )
)
# Returns: [PrecedentChunk(episode_id, decision, outcome, context)]
```

Requires Graphiti integration (Phase 8B+).

---

## Output Types (6)

| Output | Fields | Description |
|--------|--------|-------------|
| `KnowledgeChunk` | chunk_id, title, text, source_type, authority_tier, score, phase | Retrieved knowledge chunk |
| `FPResult` | is_likely_fp, confidence_adjustment, supporting_chunks, reason | FP suppression result |
| `ProviderKnowledge` | provider, behavior_notes, challenge_signatures, chunks | Provider context |
| `TaxonomyResult` | cwe_id, cwe_name, owasp_category, severity_range, references | Taxonomy classification |
| `Explanation` | summary, technical_detail, remediation, references, chunks_used | Human-readable explanation |
| `PrecedentChunk` | episode_id, decision, outcome, context | Historical precedent |

## Integration Constraints

- **No WADE logic implementation** in this interface — pure input/output specification
- **Local-only retrieval** — `load_retriever()` from `hybrid_retrieval.py`, no cloud APIs
- **Read-only corpus access** — brain queries never mutate the knowledge base
- **No customer data** passes through the brain interface
- **Async-compatible** — all functions should be `async def` in the final implementation

## Current Status (Phase 8A)

| Function | Status |
|----------|--------|
| `retrieve_evidence` | ✅ Implementable (hybrid_retrieval.py ready) |
| `check_false_positive` | ✅ Implementable (hybrid_retrieval.py ready) |
| `get_provider_context` | ✅ Implementable (provider chunks in corpus) |
| `lookup_taxonomy` | ✅ Implementable (taxonomy chunks in corpus) |
| `explain_finding` | ✅ Implementable (hybrid_retrieval.py ready) |
| `retrieve_precedent` | 🔲 Requires Graphiti (Phase 8B+) |

## Files Created (Phase 8A)

- `docs/ai/WADE_BRAIN_INTERFACE.md` (this file)
