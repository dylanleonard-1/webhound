# FP: correlation "threat chain" from co-occurrence, with no real attack path

- **Engine area:** cross-engine correlation (`scanner/webhound/core/correlation.py`,
  `_csp_external_inline_chain` `:391-458`).
- **Original bad behavior:** a MEDIUM (cvss 6.1, conf 0.85) "csp external inline
  compounding risk" finding built from **2-of-3 signals via bare title/engine
  co-occurrence** — here a CSP-config finding + the **weak entropy heuristic**.
  Severity was hard-coded; confidence (`0.65+0.10×signals`) ignored the inputs' own
  low confidence (0.45). **No same-page check, no attack-path validation, no
  confidence floor** (unlike `_exposed_admin_chain`, which gates `confidence ≥ 0.6`).
- **Why it was a false positive:** two config/heuristic findings co-occurring is
  **not** a threat chain. Correlation requires a real **relationship** (a genuine
  external-script signal feeding an exploitable sink on the same page), not mere
  co-occurrence.
- **Correct behavior:** require the **real external-script** signal (not config +
  entropy), add a constituent **confidence floor (≥0.6)**, and a **same-page/host**
  check; don't escalate co-occurrence of config + heuristic to MEDIUM.
- **Evidence required before flagging:** a validated relationship/attack-path across
  same-page constituents that each clear the confidence floor.
- **Severity guidance:** derive from the real chain; never hard-code MEDIUM for a
  2-of-3 co-occurrence.
- **Regression test expectation:** CSP-config + weak-entropy on a page, no real
  external-script chain → **no correlation finding**.
- **Source:** `WEBHOUND_DETECTION_AUDIT.md` ("LIKELY FALSE POSITIVES" #2; code change
  `correlation.py:391-458`).
- **Review status:** curated (seeded from audit).
