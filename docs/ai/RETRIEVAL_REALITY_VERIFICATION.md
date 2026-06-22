# Retrieval Reality Verification — Phase CONTROL-2F

Can canonical hybrid retrieval answer 10 REAL WebHound questions correctly?
Run: `python scripts/ai/verify_brain_reality.py`. Index: 6,886 chunks (code+docs).
PASS = expected source is #1 (correct type); PARTIAL = in top-k; FAIL = absent/wrong.

| # | Question | Top result | Type | Verdict |
|---|----------|-----------|------|---------|
| 1 | where is cookie_scanner implemented | `engines/cookies/cookie_scanner.py` | code | **PASS** |
| 2 | how does domain_classifier avoid shared-hosting FPs | `threat_intel/domain_classifier.py` | code | **PASS** |
| 3 | where is TLS checking implemented | `engines/tls_dns/tls_checker.py` | code | **PASS** |
| 4 | how does a scan become a report | `knowledge/detection-engineering/…scanner-audit-prep` | doc | **PARTIAL** (report/orchestrator code in top-k, not #1) |
| 5 | where is production WADE implemented | `knowledge/webhound/wade/WADE_FOUNDATION.md` | doc | **FAIL** (wade/ engine not in top-k; baseline models rank, not the WADE engine) |
| 6 | where is advisory WADE implemented | `knowledge/webhound/wade/WADE_FOUNDATION.md` | doc | **FAIL** (`scripts/wade/` not in top-k) |
| 7 | how does API authentication work | `apps/api/security.py` | code | **PASS** |
| 8 | how does verification flow work | `apps/api/services/verification.py` | code | **PASS** |
| 9 | what handles threat intelligence | `knowledge/threat-intelligence/…source-overview` | doc | **FAIL** (threat_intel/ engine code not #1; risk_explainer.py only at rank 4) |
| 10 | what does CSP help prevent | `docs/official/mdn-csp-guide.md` | doc | **PASS** (knowledge question → doc, correct) |

**Score: 6 PASS / 1 PARTIAL / 3 FAIL.**

## Root cause of the FAILs (honest)
The 3 FAILs (and the PARTIAL) are **natural-language "where is X implemented / what
handles X" questions**. CONTROL-2E gates the code-symbol/source-tier boost to
*symbol-like* queries; prose questions (containing `where/is/how/what`) get pure
semantic ranking + a docs-favoring prose preference. So verbose implementation
questions surface the WADE/threat-intel **knowledge docs** instead of the engine code,
and some engine modules (`scanner/webhound/wade/`, `scanner/webhound/threat_intel/`)
don't rank for long queries.

This is the inverse trade-off of the CONTROL-2E knowledge-query guard: that guard
*deliberately* makes prose questions return docs (correct for "what does CSP prevent"),
but it also catches "where is WADE implemented" — which a developer means as a code
lookup. **Symbol/short queries still resolve code perfectly** (concept traceability:
10/10 PASS; `cookie_scanner`/`tls_checker`/`domain_classifier` PASS above as code).

## Honest conclusion
- **Code-lookup via symbol or short noun-phrase queries: excellent (10/10).**
- **Code-lookup via verbose natural-language questions: mixed (6/10)** — docs win for
  WADE/threat-intel implementation questions. Not faked; reported as FAIL.
- **Knowledge questions (CSP): correct (doc returned).**

**Fix (out of scope for verification-only 2F):** a CONTROL-2G ranking refinement to
detect code-locating intent ("where is … implemented", "what handles …") and apply the
code boost even for those prose questions.
