# Severity Model (starter)

How bad a finding is **if real** (separate from confidence). Severity follows
**impact + exploitability**, never mere presence or repetition.

## Bands
| Severity | Meaning | Examples |
|----------|---------|----------|
| **Critical** | Likely compromise / data theft / account takeover, or active malicious behavior | confirmed skimmer/Magecart exfiltrating fields; unauthenticated admin access with control |
| **High** | Serious exploitable exposure or a dangerous chain | real XSS sink reachable; credentials sent in URL via native GET; exploitable misconfig with a path to impact |
| **Medium** | Meaningful weakness needing remediation | CSP `script-src 'unsafe-inline'` (no nonces); auth weaknesses without a direct exploit shown |
| **Low** | Hardening / best practice | missing hardening header with no demonstrated impact; `robots.txt` leaks `/admin` |
| **Info** | Awareness / context | public CORS on public data; framework data-traffic; single hygiene note |

## Rules
- **Do NOT inflate severity from repeated affected URLs.** 21 copies of one
  header issue across 21 pages is **one** issue, not 21 — group/dedupe; severity is
  per-distinct-issue.
- Common framework config weaknesses are **Medium**, not High (e.g. Next.js CSP
  without nonces).
- A weak static signal never reaches Critical on its own — Critical requires
  corroborated malicious **behavior** (see `javascript-malware-library/`).
- Info/Low hygiene items roll into a consolidated "hardening" tier so they inform
  without competing with real findings.

**Review status:** curated (seeded). **Authority:** internal methodology + audit
docs + Tier-A (CVSS/OWASP) where cited.
