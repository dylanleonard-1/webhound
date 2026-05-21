# Safety and Authorization Notice

WebHound is a **passive, read-only website security monitoring tool**.

## What WebHound Does

- Sends standard HTTP/HTTPS GET requests to pages it discovers by following links.
- Inspects HTTP response headers, cookies, TLS configuration, and JavaScript sources.
- Compares results to a stored baseline to detect changes over time (WADE).
- Generates reports in JSON, SARIF, CSV, and Markdown formats.

## What WebHound Does NOT Do

- Does not submit forms, POST data, or modify any content on the target site.
- Does not exploit vulnerabilities or attempt to bypass authentication.
- Does not perform denial-of-service or rate-flooding requests.
- Does not scan networks, ports, or internal infrastructure.
- Does not guarantee detection of all security issues — it is an audit support tool, not a full penetration test.

## Authorization Requirement

**You must own or have explicit written authorization to scan any target domain.**

Running WebHound against a domain you do not own or control without authorization may violate applicable computer fraud laws (e.g., the Computer Fraud and Abuse Act in the US, the Computer Misuse Act in the UK, and equivalent statutes elsewhere).

Before scanning any target:

1. Confirm you are the domain owner, or
2. Obtain written authorization from the domain owner that covers automated HTTP scanning, or
3. Use a domain you control in a development or staging environment.

The default demo target (`example.com`) is designated by IANA for use in documentation and examples and is acceptable for brief functional testing only.

## No Exploitation Policy

WebHound does not include exploit code, payload injection, or fuzzing capabilities. Any findings it reports are observations about configuration and headers — not verified vulnerabilities. Findings should be treated as leads for further manual investigation, not confirmed exploits.

## Coverage Limitations

WebHound's scan coverage is limited by:

- Pages reachable by following links from the seed URL (no JavaScript-rendered SPA crawling in v0.x).
- Headers and metadata analysis only — no source-code or server-side logic analysis.
- Known-pattern detection in the scanner engines; zero-day issues will not appear in findings.
- The scan profile chosen (quick / standard / deep / monitor).

See `docs/known-limitations.md` for the complete list.

## Reporting Misuse

If you believe WebHound is being used to scan systems without authorization, please contact the project maintainer at the address listed in the repository.
