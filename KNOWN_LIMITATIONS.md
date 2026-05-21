# WebHound — Known Limitations (Alpha)

This is an honest list of what WebHound does not yet do and where the alpha build has known gaps.
See `docs/known-limitations.md` for the extended version with detail tables.

---

## This Is Alpha Software

- Findings may be inaccurate. Expect false positives and false negatives.
- The API shape is not finalized and may change between builds.
- The frontend is a work in progress. Not all features are wired up.
- Performance has not been tuned for large or complex sites.

---

## Scanner Scope

| Limitation | Impact |
|---|---|
| No JavaScript rendering | Single-page apps (SPAs) are not crawled. Only server-rendered HTML links are followed. |
| No authenticated crawling | Pages behind a login wall are not scanned. |
| No form submission | Form-based vulnerabilities (CSRF, SQLi, XSS via POST) are not detected. |
| No port scanning | Only the HTTP/HTTPS ports used by the target URL are checked. |
| No subdomain enumeration | Only the specified URL and its linked pages are scanned. |
| Depth capped by profile | `quick` scans the root and immediate links only. `standard` goes deeper but is still limited. |

**Implication**: A passing WebHound scan does not mean a site is secure. Manual review and penetration testing are still required for full coverage.

---

## Scanner Engines (Alpha Status)

| Engine | Known Gap |
|---|---|
| `headers` | Does not semantically validate CSP directives. Checks presence only. |
| `cookies` | Cannot see cookies set by JavaScript (`document.cookie`). |
| `javascript` | Identifies external script domains; does not analyze script contents for malice. |
| `tls` | Passive only — does not enumerate all cipher suites or probe for deprecated ones. |
| `mixed_content` | Detects mixed content in HTML only; misses runtime-injected mixed content. |
| `secrets` | Pattern-based; high false-positive rate. All matches require human review. |

---

## Backend

- No email delivery — notifications are in-app only. SMTP is not implemented.
- No OAuth or SSO — email/password only.
- No team or multi-user accounts — each user is isolated.
- Rate limiting is off by default. Enable `RATE_LIMIT_ENABLED=true` for any non-local deployment.
- Domain ownership verification is bypassed in dev mode (`DEV_ALLOW_UNVERIFIED_SCANS=true`). The app refuses to set this in production.

---

## Frontend

- Some pages are incomplete or not fully styled.
- No dark mode.
- Mobile layout is not optimized.
- Report downloads may require using the API directly in some flows.

---

## Infrastructure

- No horizontal scaling — worker and API run as single instances.
- No external alerting for failed scheduled scans (in-app notifications only).
- SQLite is not supported — PostgreSQL is required.

---

## Not a Penetration Test

WebHound is a monitoring and audit support tool. It identifies observable indicators (missing headers, misconfigured cookies, outdated TLS, etc.) from the outside. It does not simulate an attacker, does not verify that findings are exploitable, and does not replace a manual security review or a professional penetration test.
