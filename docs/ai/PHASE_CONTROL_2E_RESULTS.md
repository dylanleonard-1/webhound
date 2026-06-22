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
6. **Remaining ranking weaknesses?** The source-tier bonus is a small global nudge that could, in rare no-symbol-match cases, edge a code chunk over a slightly-more-relevant doc; mitigated by keeping it tiny (0.01/tier) so semantics still dominate generic knowledge queries. Boost values are heuristic constants (not learned).
7. **Next single action:** add a small ranking regression fixture that also asserts *doc* wins for pure knowledge queries (e.g. "how does HSTS prevent downgrade") so the code-boost can't silently regress doc retrieval; then consider tuning boost constants from a labeled query set.
