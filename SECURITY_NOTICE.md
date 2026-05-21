# WebHound — Security and Authorization Notice

Read this before running any scan.

---

## Authorization Requirement

**You must own the target domain, or have explicit written authorization from the domain owner, before scanning it with WebHound.**

Scanning a domain without authorization — even passively — may violate applicable law, including but not limited to:

- Computer Fraud and Abuse Act (US)
- Computer Misuse Act (UK)
- Directive on Attacks Against Information Systems (EU)
- Equivalent statutes in your jurisdiction

The alpha tester's responsibility is to ensure every target is authorized. The maintainer accepts no liability for unauthorized use.

---

## What WebHound Does (Passive Only)

WebHound performs **read-only** reconnaissance:

- Sends standard HTTP GET requests to the target URL and links it discovers
- Reads HTTP response headers, `Set-Cookie` headers, and page HTML
- Inspects TLS certificate and protocol version for the primary connection
- Identifies external script sources referenced in `<script src>` tags
- Stores findings and optionally saves a baseline for change detection

WebHound does **not**:

- Submit forms or send POST requests to the target
- Exploit any vulnerability it finds
- Inject payloads of any kind
- Perform denial-of-service or flood the target with requests
- Enumerate ports, services, or infrastructure beyond the specified URL
- Attempt authentication bypass or credential stuffing

---

## Responsible Use — Alpha Testers

As an alpha tester you agree to:

1. **Scan only authorized targets.** Your own domains, local dev environments, or `example.com` for basic functional testing.
2. **Report sensitive findings responsibly.** If a scan produces a finding that suggests a serious vulnerability in a system you own, address it through your normal security process. Do not publish scan results publicly.
3. **Not abuse public infrastructure.** Do not run repeated or high-volume scans against `example.com` or other public targets. Use a domain you control for extended testing.
4. **Keep the alpha private.** Do not share the repository URL, alpha builds, or scan results from this program publicly.

---

## Scan Results Contain Sensitive Information

Scan reports may include:

- HTTP response headers (including `Server` version strings)
- Cookie names and attributes
- Enumerated third-party JavaScript sources
- TLS configuration details

Treat these reports as confidential. Do not share them publicly or with parties who are not authorized to receive security information about the scanned domain.

---

## False Positives and False Negatives

WebHound is alpha software. Its findings are indicators, not verified vulnerabilities.

- **False positives** are expected — a flagged issue may not be exploitable in your context.
- **False negatives** are expected — WebHound's engine coverage is limited and will not catch everything.
- **Do not take action** on a finding without first manually verifying that it represents a real risk in your environment.

---

## For More Detail

See `docs/safety-authorization-notice.md` for additional context on scope and coverage limitations.
