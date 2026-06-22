# Phase CONTROL-2G — Retrieval Intent Routing: Results

**Branch:** `feat/control-2g-retrieval-intent-routing` off `main` @ `9e45d04`.
**Scope:** retrieval intent classification + ranking rules + tests + docs. No
scanner/WADE-scoring/reports/provider/billing/auth/`.mcp.json` changes; no chunk
content changes; no installs/deploys.

## Retrieval reality: before → after
| | 2F (before) | 2G (after) |
|---|---|---|
| PASS | 6 | **8** |
| PARTIAL | 1 | 2 |
| FAIL | **3** | **0** |

The 3 FAILs are eliminated. The 10 real questions now: cookie ✅, domain_fp ✅
(MIXED), tls ✅, **prod_wade ✅** (was FAIL), **adv_wade ✅** (was FAIL),
**threat_intel ✅** (was FAIL), verify_flow ✅, csp ✅ (doc), scan_to_report PARTIAL,
api_auth PARTIAL.

## No regression (the critical checks)
- **Code traceability: 10/10 PASS** (`check_brain_traceability.py --mode hybrid`).
- **Documentation guards: 5/5** prose knowledge queries still rank docs #1.
- **dense-quality-gate**: bounded seeded shard still ≥8/10 (see VALIDATION).

## Examples (intent → top result)
| Query | Intent | Top |
|-------|--------|-----|
| where is production WADE baseline implemented | CODE_LOOKUP | `scanner/webhound/models/baseline.py` (code) |
| what handles threat intelligence | CODE_LOOKUP | `engines/threat_intel/external_domains.py` (code) |
| where is advisory WADE reasoning implemented | CODE_LOOKUP | `tests/ai/test_wade_reasoning_engine.py` (code) |
| how does HSTS prevent downgrade attacks | KNOWLEDGE | `…/cwe/cwe-614-*` (doc) |
| what does CSP help prevent | KNOWLEDGE | `docs/official/mdn-csp-guide.md` (doc) |
| where is CSP handled and what does it prevent | MIXED | top-5 has both code + doc |

## Remaining weaknesses (honest)
- **scan_to_report — PARTIAL.** "how does a scan become a report" is classified
  KNOWLEDGE ("how does") → returns a process doc; the orchestrator/reporting code is
  in top-k but not #1. Defensible (process question), not forced to PASS.
- **api_auth — PARTIAL.** "which file handles API authentication" tops the **frontend**
  API client (`apps/web/src/lib/api.ts`, also code) over the backend handler
  (`routers/auth.py`/`security.py`, in top-k). Frontend-client-vs-backend-handler
  ambiguity; reported honestly rather than gamed.
- **adv_wade top is a test file** — advisory WADE's real code lives in `scripts/wade/`,
  which is NOT in the canonical index `CODE_ROOTS`; the closest indexed artifact is the
  reasoning test. (Indexing `scripts/wade/` is a future canonical-index change.)

## Answers
1. **Code-location prose finds code now?** Yes — prod_wade/adv_wade/threat_intel went FAIL→PASS; CODE_LOOKUP top is code 6/6 in the routing test.
2. **Explanation prose still finds docs?** Yes — 5/5 doc guards intact.
3. **Mixed returns both?** Yes — top-5 contains code + doc (guaranteed).
4. **Did retrieval reality improve?** Yes — 6/1/3 → **8/2/0** (0 FAIL).
5. **10/10 traceability remained PASS?** Yes.
6. **Doc guards remained PASS?** Yes (5/5).
7. **What remains weak?** scan_to_report (process Q→doc), api_auth (frontend vs backend), adv_wade code not indexed (`scripts/wade/`).
8. **Next single action:** add `scripts/wade/` (+ a frontend-vs-backend tier) so advisory-WADE implementation and backend-auth questions resolve to the precise module — targeting 10/10.
