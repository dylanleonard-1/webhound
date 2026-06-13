# FP/noise: "cross-origin isolation not set" inflating the finding list

- **Engine area:** security headers (cross-origin isolation / COOP-COEP) +
  reporting/dedup.
- **Original bad behavior:** "Cross-origin isolation not set" emitted as **INFO ×21**
  (once per page), alongside other low-value hygiene rows ("CSP isn't reporting",
  tech disclosure) — inflating the list with duplicated, low-value noise.
- **Why it was a false positive (effectively):** cross-origin isolation
  (`crossOriginIsolated` / COOP+COEP) only matters if the app **needs** powerful
  features (e.g. `SharedArrayBuffer`, precise timers). For a normal marketing/app
  page that doesn't, "not isolated" is not a finding — and certainly not 21 of them.
- **Correct behavior:** suppress unless the app declares it needs
  `crossOriginIsolated`; if kept, **at most one INFO**, folded into a single
  hygiene/"hardening recommendations" tier; dedupe across pages.
- **Evidence required before flagging:** a signal that the page requires isolation
  (uses `SharedArrayBuffer`/high-res timers) — otherwise don't flag.
- **Severity guidance:** INFO only, and only once; prefer the consolidated hygiene
  tier so it informs without competing with real findings.
- **Regression test expectation:** a normal page that doesn't need isolation →
  **0 or one consolidated INFO**, not ×N.
- **Source:** `WEBHOUND_DETECTION_AUDIT.md` ("FINDINGS REQUIRING TUNING" #3;
  "DETECTION RULE IMPROVEMENTS" #7 hygiene-tier consolidation).
- **Review status:** curated (seeded from audit).
