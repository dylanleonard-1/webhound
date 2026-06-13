# FP: minified framework bundle flagged as "unusually random-looking" (entropy)

- **Engine area:** JavaScript / obfuscation detection
  (`scanner/webhound/engines/javascript/obfuscation_detector.py`).
- **Original bad behavior:** "Inline script has unusually random-looking content"
  fired at **entropy 5.53 vs a 5.5 threshold** (LOW, conf 0.45→0.55). No
  minified-bundle exclusion; the description itself admitted the signal is "weak."
- **Why it was a false positive:** minified Next.js inline runtime/RSC scripts
  naturally reach ~5.5 bits/char. 5.53 barely clears 5.5 — high entropy is normal
  for minified framework code, not evidence of obfuscated malware.
- **Correct behavior:** raise `_ENTROPY_THRESHOLD` (`:101`) to ~5.8 for inline
  scripts and/or skip clearly-minified framework bundles; keep the weak signal as
  **correlation-only**, never a standalone finding.
- **Evidence required before flagging:** entropy clearly above the realistic
  minified-bundle band **plus** a corroborating signal (suspicious decode chain,
  dynamic injection, unknown third-party origin) — not entropy alone.
- **Severity guidance:** never a standalone finding; only contributes to a
  correlated malicious-JS finding with real behavior/provenance.
- **Regression test expectation:** a minified Next.js inline bundle at ~5.5 → **no
  standalone entropy finding**.
- **Source:** `WEBHOUND_DETECTION_AUDIT.md` ("LIKELY FALSE POSITIVES" #3; code change
  `obfuscation_detector.py:101,329`).
- **Review status:** curated (seeded from audit).
