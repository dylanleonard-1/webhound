# Traceability Benchmark — Phase CONTROL-2E (before vs after)

Full-index hybrid retrieval, top hit per concept. **Before** = CONTROL-2D (dense,
no symbol boost). **After** = CONTROL-2E (dense + code-symbol boost + source tier).

| Concept | Before: top hit (type) | Before verdict | After: top hit (type, score) | After verdict |
|---------|------------------------|----------------|------------------------------|---------------|
| tls_checker | `nuclei--syntax-reference.md` (doc, 0.828) | **PARTIAL** | `engines/tls_dns/tls_checker.py` (code, 1.124) | **PASS** |
| cookie_scanner | `engines/cookies/cookie_scanner.py` (code) | PASS | `engines/cookies/cookie_scanner.py` (code, 1.176) | PASS |
| domain_classifier | `threat_intel/domain_classifier.py` (code) | PASS | `threat_intel/domain_classifier.py` (code, 1.102) | PASS |
| threat_intel | `threat_intel/threat_correlation.py` (code) | PASS | `threat_intel/threat_correlation.py` (code, 0.943) | PASS |
| production WADE | `webhound/wade/anomaly_scorer.py` (code) | PASS | `webhound/wade/anomaly_scorer.py` (code, 1.097) | PASS |
| advisory WADE | `tests/ai/test_wade_reasoning_engine.py` (code/test) | PASS | same (code/test, 0.979) | PASS |
| scanner orchestrator | `webhound/core/orchestrator.py` (code) | PASS | `webhound/core/orchestrator.py` (code, 0.991) | PASS |
| verification flow | `apps/api/services/verification.py` (code) | PASS | `apps/api/services/verification.py` (code, 1.046) | PASS |
| API authentication | `apps/api/tests/test_auth.py` (code/test) | PASS | `apps/api/routers/auth.py` (code, 1.098) | PASS |
| report rendering | `webhound/reporting/json_report.py` (code) | PASS | `webhound/reporting/json_report.py` (code, 1.058) | PASS |

## Summary
- **Before:** 9 PASS / 1 PARTIAL / 0 FAIL.
- **After:** **10 PASS / 0 PARTIAL / 0 FAIL.**
- The only change in verdict is **tls_checker PARTIAL → PASS**; every other concept
  stays PASS and most now lead with a higher-confidence exact code chunk (and API
  authentication now surfaces the real `routers/auth.py` over the test).
- All 10 top hits are now `chunk_type=code`.

Reproduce: `python scripts/ai/check_brain_traceability.py --mode hybrid --show-ranking`
(needs canonical chunks + dense vectors — see `BRAIN_DENSE_RETRIEVAL_BUILD.md`).
