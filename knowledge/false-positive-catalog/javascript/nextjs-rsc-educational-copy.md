# FP: educational/marketing copy containing a "malicious" keyword flagged as malicious JS

- **Engine area:** JavaScript / compromise detection (keyword-based malicious-JS
  signal).
- **Original bad behavior:** a Next.js RSC payload / page copy that **contained a
  scary keyword** (e.g. the word "exfiltration" in educational/marketing text) was
  flagged as malicious JavaScript.
- **Why it was a false positive:** the keyword appeared in **human-readable copy /
  RSC data**, not in executable behavior. "The string 'exfiltration' appears on the
  page" ≠ "this page exfiltrates data." Keyword presence is not malware.
- **Correct behavior:** require **executable context + behavior**, not a substring
  match in copy/RSC text. Distinguish rendered text / RSC payloads from actual
  script execution; corroborate with dynamic behavior (network beacon, credential/
  cookie access) before flagging.
- **Evidence required before flagging:** the keyword in **executing script** plus a
  corroborating dynamic/behavioral or provenance signal — never a keyword in copy
  alone.
- **Severity guidance:** keyword-in-copy → **not a finding**. Real malicious JS is
  rated on corroborated behavior (see `javascript-malware-library/`).
- **Regression test expectation:** a page whose only "signal" is the word
  "exfiltration" in educational copy/RSC → **0 malicious-JS findings**.
- **Source:** `WEBHOUND_DETECTION_AUDIT.md` (line ~123, "recent FP fixes: **RSC
  keyword**, …"); standard-of-proof rule: "keyword exists ≠ malware."
- **Review status:** curated (seeded; fix already shipped per audit).
