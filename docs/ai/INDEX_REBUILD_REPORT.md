# Index Rebuild Report — Phase CONTROL-2B

**Type:** KNOWLEDGE-INGESTION. Rebuilds the hybrid retrieval index over docs + production code.
**Generators:** `scripts/ai/ingest_production_code.py` → `scripts/ai/rebuild_brain_index.py`.
**Artifacts (regenerable, NOT committed — big blobs kept out of git):** `corpus/normalized/unified_chunks_with_code.jsonl`, `corpus/indexes/dense_with_code/{chunk_embeddings.npy,config.json,retrieval_smoke.json}`.

## Chunk counts (before → after)

| Set | Chunks |
|-----|------:|
| Doc/knowledge chunks (pre-existing corpus) | 1,161 |
| **+ Production code chunks (new)** | **+746** |
| **Combined index total** | **1,907** |

Model: `all-MiniLM-L6-v2` (384-dim, local, no cloud, no Ollama). Embeddings regenerated for all 1,907 chunks. The committed `corpus/indexes/dense/` (1,161) is left untouched; the code-augmented index lives in `dense_with_code/` as a build artifact.

## Retrieval impact — smoke tests (top-1 hit per concept)

| Query | Top-1 score | Hit type | Top-1 file |
|-------|------------:|----------|-----------|
| cookie_scanner | 0.724 | **CODE** | `scanner/webhound/engines/cookies/cookie_scanner.py` |
| domain_classifier | 0.580 | **CODE** | `scanner/webhound/threat_intel/domain_classifier.py` |
| tls_checker | 0.606 | **CODE** | `scanner/webhound/engines/tls_dns/tls_checker.py` |
| threat_intel | 0.691 | **CODE** | `scanner/webhound/threat_intel/__init__.py` |
| API Authentication | 0.581 | **CODE** | `apps/api/schemas/auth.py` |
| Scanner Orchestrator | 0.438 | **CODE** | `scanner/webhound/core/scan_context.py` |
| WADE | 0.374 | DOC | `knowledge/webhound/wade/WADE_FOUNDATION.md` |
| Verification Flow | 0.377 | DOC | `corpus/normalized/.../det-libinjection…` |

**6 of 8 concepts now retrieve production code directly** (vs 0 before — code wasn't in the index at all). `domain_classifier`, previously a total blind spot, now resolves to its real module at 0.58. WADE and Verification Flow still surface docs first (WADE has heavy doc coverage; "Verification Flow" is an API concept whose top match is weak — a residual gap, see results doc).

**Result:** the hybrid index is now **code-aware**; retrieval reaches the real product. Committed index unchanged; rebuild is reproducible via the two scripts.
</content>
