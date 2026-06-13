# FP/tuning: CSP `'unsafe-inline'`/`'unsafe-eval'` over-severity + directive scoping

- **Engine area:** security headers / CSP
  (`scanner/webhound/engines/headers/security_headers.py:290-307`).
- **Original bad behavior:** `'unsafe-inline'`/`'unsafe-eval'` in CSP reported at
  **HIGH**, and the match was not scoped to a specific directive (a style-only
  `'unsafe-inline'` could trigger the script-XSS framing).
- **Why it was (partly) a false positive / mis-rated:** this is a **real config
  weakness** (it does defeat CSP's XSS mitigation) — a **true positive in
  existence** — but **HIGH over-states it**: it is a common Next.js-without-nonces
  config, not an active exploit. And a `style-src 'unsafe-inline'` is not the same
  risk as `script-src 'unsafe-inline'`; matching unscoped misattributes severity.
- **Correct behavior:** **keep the finding** but **downgrade HIGH → MEDIUM** (align
  to the cvss 6.1 band) and **scope the match to `script-src`** so a style-only
  `'unsafe-inline'` never triggers the script-XSS finding.
- **Evidence required before flagging:** `'unsafe-inline'`/`'unsafe-eval'` present
  **within `script-src`** specifically.
- **Severity guidance:** MEDIUM (config weakness), not HIGH; not an active exploit.
- **Regression test expectation:** `script-src 'unsafe-inline'` → MEDIUM finding;
  `style-src 'unsafe-inline'` only → **no script-XSS finding**.
- **Source:** `WEBHOUND_DETECTION_AUDIT.md` ("HIGH CONFIDENCE TRUE POSITIVES" #1 +
  "DETECTION RULE IMPROVEMENTS" #6; code change `security_headers.py:290-307`).
- **Review status:** curated (seeded from audit). *Note: a true positive that was
  mis-rated/over-scoped — kept as a tuning lesson, not a "delete the finding" case.*
