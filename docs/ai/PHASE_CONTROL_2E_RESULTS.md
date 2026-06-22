# Phase CONTROL-2E — Code Symbol Ranking & Traceability Accuracy: Results

**Branch:** `feat/control-2e-code-symbol-ranking` off `main` @ `558cc33` (2D).
**Scope:** retrieval ranking logic only. No scanner/WADE-scoring/reports/provider-access/billing/auth/`.mcp.json` changes; **no chunk content altered**; no vector artifacts committed.

## Before → after (full-index hybrid)
| Metric | Before (2D) | After (2E) |
|--------|-------------|-----------|
| PASS | 9 | **10** |
| PARTIAL | 1 (`tls_checker`) | **0** |
| FAIL | 0 | 0 |
| Top hits that are code | 9/10 | **10/10** |

Improvement: **+1 PASS (90% → 100%)**; the last doc-over-code inversion (`tls_checker`) is resolved. See `TRACEABILITY_BENCHMARK.md` for the per-concept table.

## What changed (ranking logic, `scripts/ai/hybrid_retrieval.py`)
- **Code-symbol boost** (generalized): +0.25 when the query names a code chunk's module stem; +0.12 when it names the symbol title. Metadata-driven (file stem + title), no per-concept hardcoding.
- **Source-priority tie-break**: 1 production · 2 API · 3 WADE · 4 tests · 5 tech docs · 6 knowledge · 7 planning → `(8-tier)·0.01` bonus (small; exact symbol matches dominate via the boost).
- Wider candidate pool (k·8) for all modes so a near-miss code chunk can be re-ranked above docs.
- `check_brain_traceability.py --show-ranking` prints rank/type/tier/score per concept.
- `tests/ai/test_code_symbol_ranking.py` (7 tests): asserts **code-above-doc** (rank-robust), not absolute scores.

## Validation
- `pytest tests/ai`: **347 passed, 3 skipped** (clean).
- `check_brain_traceability.py --mode hybrid`: **10 PASS / 0 PARTIAL / 0 FAIL**.
- **CONTROL-2D dense-quality-gate re-run** (seeded shard, `--min-found 8`): **found 10/10 → OK (no regression)**.
- Protected paths unchanged; no chunk content modified; no `.npy`/canonical artifacts staged.

## STATE OF CODE-SYMBOL RANKING
1. **Does exact symbol lookup now prefer code?** Yes — exact module-name queries return the real module as a code chunk #1 (`test_exact_symbol_lookup_prefers_code`).
2. **tls_checker PASS?** **Yes** (was PARTIAL) — `tls_checker.py` 1.124 > Nuclei doc 0.858.
3. **production WADE PASS?** Yes — `webhound/wade/anomaly_scorer.py` top.
4. **orchestrator PASS?** Yes — `webhound/core/orchestrator.py` top.
5. **threat_intel PASS?** Yes — `threat_intel/threat_correlation.py` top.
6. **Remaining ranking weaknesses?** Boost/penalty values are heuristic constants (not learned). The HSTS query's best doc is a CWE taxonomy note (the corpus lacks a dedicated HSTS explainer), so the top doc is adjacent rather than perfect — defensible, and it is docs/knowledge (not code/test).
7. **Next single action:** tune the boost/penalty constants from a small labeled query set (code-seeking vs knowledge-seeking) instead of hand-picked values.

## Knowledge-query guard (added — CONTROL-2E refinement)
Proves the code bias does NOT break documentation/knowledge retrieval. Initial probe
of 5 prose queries found **3/5 returned CODE at top** — two real over-application bugs:
- "what causes **Cloudflare** challenge pages…" got +0.25 because it contained the
  module token `cloudflare`.
- "how does HSTS…" and "how should webhook signatures…" returned a test file / router
  on pure semantics.

Fixes (ranking logic, `hybrid_retrieval.py`):
- **Query gating** (`_is_symbol_like_query`): the code-symbol/source-tier boost applies
  ONLY to symbol-like queries (identifier/path/short noun phrase, no question word).
- **Prose preference** (`_prose_bonus`): for prose questions, demote test chunks
  (−0.30) and gently favor docs/knowledge (+0.06); production code neutral.

After: **5/5 prose guards rank docs/knowledge #1**; **10/10 code concepts still PASS**;
dense-quality-gate still 10/10. Guard tests: `tests/ai/test_code_symbol_ranking.py`
(`test_prose_query_is_not_code_seeking`, `test_prose_query_top_is_doc`).

| Prose query | Top result |
|-------------|-----------|
| how does HSTS prevent downgrade attacks | DOC `knowledge/vulnerability-taxonomy/cwe/cwe-614-*` |
| what does Content Security Policy help prevent | DOC `docs/official/mdn-csp-guide.md` |
| how should webhook signatures be validated | DOC `knowledge/provider-docs/stripe/README.md` |
| what causes Cloudflare challenge pages to block scanners | DOC `knowledge/provider-docs/render/deployment.md` |
| how should threat-intel shared hosting false positives be handled | DOC `knowledge/threat-intelligence/threat-intel-false-positives*` |
