# Known Limitations — WebHound v0.x Beta

This document lists known gaps and limitations as of the beta release. Items are tracked for future milestones.

## Scanning

| Limitation | Detail | Planned |
|---|---|---|
| No SPA/JavaScript rendering | The crawler follows HTML `<a>` links only. Pages that require JavaScript execution to render content are not crawled. | v1.x |
| No authenticated crawling | WebHound cannot log in to scan pages behind a login wall. | v1.x |
| No API endpoint scanning | REST/GraphQL endpoints are not enumerated or fuzzed. | v1.x |
| No form submission | No POST data is sent. Form-based vulnerabilities (CSRF, injection) are not detected. | Not planned |
| Page depth limit | Crawl depth is capped by profile. The `quick` profile scans the root page and immediate links only. | — |
| No subdomain enumeration | Only the specified URL and its discovered subpages are scanned. | v1.x |
| Rate limiting not self-throttled | WebHound does not currently enforce a max-requests-per-second cap against the target. Use on production sites during low-traffic periods. | v0.x patch |
| TLS check is passive | TLS version detection infers from the negotiated connection. It does not actively probe for deprecated cipher suites. | v1.x |

## Scanner Engines

| Engine | Limitation |
|---|---|
| `headers` | Checks response headers of crawled pages only. Does not validate CSP directives semantically. |
| `cookies` | Detects cookies present in `Set-Cookie` response headers. Cannot observe cookies set by JavaScript. |
| `javascript` | Identifies third-party script sources by hostname. Does not analyze script contents for malicious code. |
| `tls` | Checks the TLS version negotiated for the primary connection. Does not enumerate all accepted cipher suites. |
| `mixed_content` | Detects HTTP resources referenced in HTML. Cannot detect mixed content loaded by JavaScript at runtime. |
| `secrets` | Pattern-based detection of API keys and tokens in HTML/JS. High false-positive rate; all matches require manual review. |

## API and Backend

- No email delivery — notifications are in-app only. SMTP integration is not yet implemented.
- No OAuth / SSO — only email/password authentication is supported.
- No multi-tenancy or team accounts — each account is a single user.
- Rate limiting is disabled by default (`RATE_LIMIT_ENABLED=false`). Enable it for any shared deployment.
- Domain verification is bypassed in dev mode (`DEV_ALLOW_UNVERIFIED_SCANS=true`). This must not be set in production.
- `DEV_ALLOW_UNVERIFIED_SCANS=true` is set in `docker-compose.yml` for convenience during development and beta testing.

## Frontend

- The web UI is a work-in-progress. Some pages may be incomplete or unstyled.
- No dark mode yet.
- Mobile layout is not optimized.

## Reporting

- Report downloads are served as JSON from the API. CSV/Markdown/SARIF formats are generated on scan completion. File download UI is not yet fully implemented in the frontend.
- SARIF output passes schema validation but may not render correctly in all SARIF viewers for all finding types.

## Infrastructure

- No horizontal scaling — the worker and API run as single instances.
- No distributed tracing or structured request logging to an external sink.
- Scheduled scan monitoring (heartbeat/alerting on missed schedules) is implemented but not connected to external alerting channels.

## Not a Penetration Test

WebHound is a **monitoring and audit support tool**. A passing scan does not mean a site is secure. It checks a defined set of observable indicators. Manual review, penetration testing, and code review are required for a complete security assessment.
