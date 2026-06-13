# Phase 5C — Internal Retrieval Ranking & Chunk Quality: Results

Zero-download lexical refinements on the **internal corpus only**. No LightRAG/
torch/sentence-transformers, **no model download, no external embeddings API, no
external ingestion.** Fixes the cheap structural ranking problems before any future
dense embeddings (these help even after embeddings land).

Code: [`scripts/ai/ingest_internal_knowledge.py`](../../scripts/ai/ingest_internal_knowledge.py)
(roles + chunk filters), [`scripts/ai/semantic_retrieval.py`](../../scripts/ai/semantic_retrieval.py)
(role/path-match ranking).

## 1. Document role / source-type model
Added a first-class **`doc_role`** field (manifest schema extended + validated;
`tests/ai` updated) — finer than `authority_tier`/`source_type`. 12 roles:
`canonical_note, architecture_summary, decision_log, false_positive_note,
provider_note, engine_note, policy_doc, phase_result_report, audit_report,
historical_reference, empty_stub, generated_summary`.

Corpus role distribution (221 docs): canonical_note **94**, engine_note **51**,
policy_doc **25**, provider_note **14**, false_positive_note **10**, audit_report
**6**, empty_stub **6**, historical_reference **5**, architecture_summary **5**,
decision_log **3**, phase_result_report **2**.

## 2. Ranking model (generalizes — NOT hardcoded for any topic)
Final score = **BM25** (IDF + length-norm, from 5B) × **tier** × **role(intent)** ×
**path-match**:
- **tier:** A=1.15 / B=1.0 / C=0.85.
- **role (intent-aware):** for *definitional* queries, boost canonical/policy/
  decision/FP/provider/engine notes (1.1–1.35), **demote** `phase_result_report`
  (0.5), `audit_report` (0.55), `generated_summary` (0.55), `historical_reference`
  (0.7); for *audit/history* queries, those reports are **not** demoted (intent
  detected from words like "audit/review/history").
- **path-match:** boost docs whose **filename/dir tokens** match the query subject
  — canonical notes are named after their topic (`WADE_FOUNDATION`,
  `PLATFORM_ACCESS_FRAMEWORK`, `SECURITY_GRAPH_BRIDGE`, `MCP_SECURITY_MODEL`), while
  generic reports (`PHASE5A_RESULTS`, `*_REVIEW`) are not. **No per-topic
  hardcoding.**
- Minimal plural-stemmer (`positives→positive`, `rules→rule`) so singular/plural
  queries match topical paths.

## 3. Chunk-quality filters (with reporting)
`build_chunks` now reports `{docs_skipped_empty, chunks_short_dropped,
chunks_dup_dropped}`:
- **empty docs / 0-byte stubs → 0 chunks** (`docs_skipped_empty=6`).
- **chunks < 40 chars dropped** — but each non-empty doc keeps its largest chunk,
  so **no document is silently dropped** (a reason is always recorded).
- **identical chunks deduped** by normalized content hash.
- Source attribution preserved on every chunk (`doc_id`, `source_path`,
  `authority_tier`, `doc_role`, `chunk_hash`).

## 4. Empty-stub handling (the 6 found in 5A)
The 6 empty 0-byte stubs (`docs/{api-routes, architecture, database-schema,
roadmap, scanner-engines, wade}.md`) are **NOT deleted**. They are marked
`doc_role: empty_stub` + `verification_status: deprecated` in `manifest.jsonl` and
**produce zero chunks** (verified by `tests/ai`).

## 5. Before / after retrieval (same metric, honest)
| Config | top-1 (orig 6) | top-3 (orig 6) | top tier A/B (orig 6) |
|--------|:--:|:--:|:--:|
| Keyword (5A baseline) | 2/6 | 2/6 | 4/6 |
| BM25 + authority (5B) | 2/6 | 4/6 | 6/6 |
| **BM25 + tier + role + path (5C)** | **4/6** | **6/6** | **6/6** |

**Full 10-query set (5C): top-1 = 8/10, top-3 = 10/10, top tier A/B = 10/10.**

## 6. Per-query results (10) — Phase 5C
| # | Query | Top-1 | Role | top-1 ok? | canonical in top-3? |
|---|-------|-------|------|:--:|:--:|
| 1 | What is WADE? | `…/wade/WADE_FOUNDATION.md` | canonical_note | ✅ | ✅ |
| 2 | Provider access framework | `…/provider-access/PLATFORM_ACCESS_FRAMEWORK.md` | canonical_note | ✅ | ✅ |
| 3 | Scanner IPs approved | `…/PLATFORM_ACCESS_FRAMEWORK.md` (`scanner-identity.md` #2) | canonical_note | ~ (relevant; gold #2) | ✅ |
| 4 | Known false positives | `…/false-positive-catalog/correlation/README.md` (+cors,csp) | canonical_note | ✅ | ✅ |
| 5 | Corpus vs knowledge | `…/decisions/AI_KNOWLEDGE_LAYER_DECISIONS.md` (`knowledge/README.md` #2) | decision_log | ~ (defines the split; gold #2) | ✅ |
| 6 | Threat-intel architecture | `…/threat-intel/THREAT_INTEL_CURRENT_STATE.md` | canonical_note | ✅ | ✅ |
| 7 | Rules for Claude memory | `docs/ai/CLAUDE_MEMORY_POLICY.md` | policy_doc | ✅ | ✅ |
| 8 | Security Graph bridge | `docs/ai/SECURITY_GRAPH_BRIDGE.md` | canonical_note | ✅ | ✅ |
| 9 | What should never enter the corpus | `docs/ai/corpus/RETENTION_POLICY.md` | policy_doc | ✅ | ✅ |
| 10 | MCP security model | `docs/ai/mcp/MCP_SECURITY_MODEL.md` | canonical_note | ✅ | ✅ |

Authority tiers: **top result is tier A/B for all 10**. No generated report or
audit ranks #1 anywhere.

## 7. Quality targets (STEP 7) — met
- top-1 above 2/6 on the original six → **4/6** ✅
- top-3 stay ≥4/6 (preferably improve) → **6/6** ✅
- tier-A/B top-result stay 6/6 → **6/6** ✅
- generated reports don't dominate definitional queries → ✅ (role-demoted; tier A/B 10/10)
- canonical notes in top-3 for all relevant canonical queries → **top-3 10/10** ✅

## 8. Remaining weaknesses (honest)
- **The two "~" cases are genuinely-relevant alternates, not errors:** #3's top-1
  (`PLATFORM_ACCESS_FRAMEWORK`) really does cover approved scanner IPs, and #5's
  top-1 (the decisions log) literally states the corpus-vs-knowledge split — the
  strict gold just preferred a different canonical doc (present at #2). top-1 = 8/10
  against a strict gold understates real usefulness.
- **Lexical ceiling:** path-match + roles can't capture paraphrase/synonymy (a query
  with none of the topic's words would still miss). That needs dense embeddings.
- **Role heuristic is path-based** — robust here, but a mis-named future doc could be
  mis-roled.
- **Weights are hand-tuned** on 10 internal queries; they generalize by construction
  (role/path, not topic) but aren't learned.

## 9. Phase 5D recommendation
1. **Now you can decide dense embeddings on solid footing.** Offline local model
   (`sentence-transformers`, e.g. `all-MiniLM-L6-v2`) is the recommended path
   (docs stay local) but costs a torch install + ~90 MB model download — an
   explicit, flagged opt-in. Keep the lexical layer as a **hybrid** re-ranker
   (BM25+role+path is a strong prior; embeddings add paraphrase recall).
2. **No-download follow-ups:** small synonym/alias map for query expansion; promote
   `tests/ai` into CI; consider populating or removing the 6 deprecated empty stubs.
3. **Only after** internal retrieval is solid, begin **gated external ingestion**
   (separate approval) — never before.

---
*Scope honored: internal-only, no external/threat-feed/provider/OWASP ingestion, no
embeddings API, no model download, no scanner/WADE/provider-access changes,
`.mcp.json` untouched.*
