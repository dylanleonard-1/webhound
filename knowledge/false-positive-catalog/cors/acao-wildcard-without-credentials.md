# FP: `Access-Control-Allow-Origin: *` flagged MEDIUM on public, non-credentialed resources

- **Engine area:** security headers / CORS (`scanner/webhound/engines/headers/cors.py`).
- **Original bad behavior:** `cors.py` flagged any `ACAO: *` at **MEDIUM** (cvss 5.3,
  conf 0.7) with no auth/credentials/sensitivity check; emitted once per page (×21
  on a 23-page crawl).
- **Why it was a false positive:** on a **public, non-credentialed** HTML page,
  `ACAO: *` is not exploitable — any origin could already read public HTML
  server-side. Without `Access-Control-Allow-Credentials: true` there is no
  cross-origin secret to steal. Over-severity + per-page duplication.
- **Correct behavior:** keep **HIGH** only for `*` **+ credentials** (`ACAC:true`);
  otherwise **INFO** ("public CORS — fine for public data; review if this endpoint
  ever returns PII/auth'd data"). Group per-finding (dedupe across pages).
- **Evidence required before flagging:** the credentials value (already parsed at
  `cors.py:64-82`) and/or an authenticated/sensitive-resource signal.
- **Severity guidance:** HIGH only with credentials; else INFO. Never MEDIUM for a
  public, non-credentialed resource.
- **Regression test expectation:** a public page with `ACAO:*` and no credentials →
  **INFO, fires once** (not MEDIUM, not ×N). `ACAO:*` + `ACAC:true` → HIGH.
- **Source:** `WEBHOUND_DETECTION_AUDIT.md` (TOP FINDING TYPES; "FINDINGS REQUIRING
  TUNING" #1; code change `cors.py:118`).
- **Review status:** curated (seeded from audit).
