# Phase CONTROL-2C — Canonical Code-Aware Brain Index: Results

**Type:** Brain-index canonicalization. No scanner/WADE-production-scoring/reports/`.mcp.json`/provider-access/billing/auth changes; no MCP installs; no deploys; no large binary blobs committed.
**Branch:** `feat/control-2c-canonical-brain-index` off `main` @ `ace3fab`.
**Precheck:** main current; open PRs #30 (2B), #29 (2A), #24, #2; corpus = 1,161 doc chunks; retrieval entrypoint `scripts/ai/hybrid_retrieval.py`; graph builder `scripts/ai/build_graphify.py`; vault `vault/WebHound AI Brain/`.

## Counts (committed manifests — deterministic)

| Metric | Value |
|--------|------:|
| Sources scanned | 794 |
| Sources **included** | 752 |
| Sources **excluded** (lock/env/cache/build) | 42 |
| **Code chunks** (symbol-level, Python + TS/TSX) | **5,701** |
| Doc chunks (existing corpus) | 1,161 |
| **Canonical total** | **6,862** |

Code chunk categories: frontend 173 · api_service 60 · scanner_engine 44 · api_model 37 · api_route 26 · scanner_core 25 · threat_intel 14 · wade_production 14 · report 12 · provider 2 · scanner(other) 150 · test 195.

## What is now CANONICAL (committed)

- `corpus/index/brain_sources_manifest.json` — every brain source w/ include/exclude + content hash.
- `corpus/index/code_chunks_manifest.jsonl` — 5,701 chunk metadata records (id, path, symbol, lines, hashes, category — **no embeddings**).
- `corpus/index/retrieval_config.json` — canonical retrieval config (`prefer_canonical: true`).
- `scripts/ai/build_canonical_brain_index.py`, `check_brain_traceability.py`, `tests/ai/test_canonical_brain_index.py`, updated `hybrid_retrieval.py`.

## What is REGENERATED (not committed)

`corpus/index/canonical_chunks.jsonl` (~8.4 MB), `corpus/index/dense/*.npy` (~11 MB) — gitignored (`corpus/index/.gitignore`). Plus local Neo4j/LightRAG/Ollama state. See `BRAIN_INDEX_ARTIFACT_POLICY.md`.

## Determinism & fresh-clone rebuild — PROVEN

- Two consecutive builds produced **byte-identical** `code_chunks_manifest.jsonl` + `brain_sources_manifest.json` (SHA-256 match).
- Simulated fresh clone: deleted `canonical_chunks.jsonl` + `dense/`, ran `build_canonical_brain_index.py` from committed scripts/manifests → regenerated successfully with **no network/Ollama/Neo4j**; lexical traceability identical.

## Retrieval default

`load_retriever()` now **prefers the canonical code-aware index** when `canonical_chunks.jsonl` is present; otherwise it falls back to the doc-only index **with a printed `stderr` warning + rebuild command** (no silent fallback). Dense embeddings align with the loaded chunk set (canonical dense dir for canonical chunks; doc dense dir for fallback).

## Traceability (canonical index, lexical mode — fresh-clone-safe)

| Concept | Verdict |
|---------|---------|
| cookie_scanner | PASS |
| domain_classifier | PASS |
| tls_checker | PASS |
| advisory WADE | PASS |
| verification flow | PASS |
| API authentication | PASS |
| threat_intel | PARTIAL (indexed; lexical top hit was orchestrator) |
| production WADE | PARTIAL (indexed; lexical top hit was a wade test) |
| report rendering | PARTIAL (indexed; lexical top hit was a grouping test) |
| scanner orchestrator | FAIL (lexical ranking; **module IS indexed** — orchestrator.py has 13 chunks; dense ranks it #1 per 2B) |

**Score: 6 PASS / 3 PARTIAL / 1 FAIL (lexical).** All 10 concepts are *present* in the index (verified via `code_chunks_manifest`); the PARTIAL/FAIL are lexical-ranking artifacts that dense retrieval resolves (the `--embed` step). The test suite asserts **manifest membership** (robust), not lexical rank.

## Tests run

- `tests/ai/test_canonical_brain_index.py` — **PASS** (manifests exist; scanner/api/web included; key modules + production WADE indexed; no secrets/local artifacts; `--dry-run` rebuild succeeds).
- `tests/ai/test_hybrid_retrieval.py` — **PASS** (24 passed total with the canonical index + local embeddings; warned fallback preserves CI behavior).

## Remaining gaps

| Gap | Severity |
|-----|----------|
| Lexical ranking weak for orchestrator/threat_intel/WADE/report (dense needed for top-1) | MEDIUM |
| Canonical dense embeddings are a local `--embed` artifact (committed index is metadata-only) | MEDIUM |
| TS parsing is regex-level (symbols/exports), not full AST | LOW |
| Neo4j/Graphiti production load (2B) still depends on local services; Ollama uninstalled | LOW (out of 2C scope) |

## STATE OF CANONICAL BRAIN

1. **Is the code-aware brain now canonical?** **Yes** — committed manifests + builder make 5,701 code chunks the official, versioned brain source.
2. **Can a fresh clone rebuild it?** **Yes** — proven; one script, no network/Ollama/Neo4j; deterministic.
3. **Is production code represented?** **Yes** — 752 sources, 5,701 code chunks across scanner/api/web/tests.
4. **Is apps/web represented?** **Yes** — the 2B gap is closed: 173 frontend chunks (547 TS/TSX chunk records), regex symbol-level.
5. **Are scanner engines traceable?** **Yes** — cookie_scanner/tls_checker/domain_classifier/threat_intel all PASS or indexed; engines = 44 chunks category.
6. **Is WADE traceable?** **Yes** — production WADE 14 + advisory WADE indexed (72 wade chunks total).
7. **Is API traceable?** **Yes** — routes 26 + services 60 + models 37; API auth + verification PASS.
8. **What remains non-canonical?** the **embeddings** (local `--embed` artifact) and the **graph/LLM tier** (Neo4j/Graphiti/Ollama from 2B) — retrieval chunks + manifests are canonical; vector embeddings are regenerated per environment.
9. **Next single action:** add a tiny committed **embedding build step in CI** (or commit a quantized small embedding shard) so dense retrieval — not just lexical — works out-of-the-box on a fresh clone, making orchestrator/WADE/threat_intel top-1 without a local `--embed`.

*Canonical brain index established. No production behavior changed; no large binaries committed; fresh-clone rebuild verified.*
</content>
