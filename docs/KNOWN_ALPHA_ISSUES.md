# WebHound Alpha — Known Issues

This document lists known issues and non-blocking limitations discovered during alpha development.
Items marked **[BLOCKER]** should be resolved before broader testing.
Items marked **[COSMETIC]** or **[MINOR]** are non-blocking for typical workflows.

Last updated: 2026-05-12

---

## Authentication

| Severity | Issue | Workaround |
|----------|-------|------------|
| MINOR | No email verification — any email format accepted on registration | Acceptable for alpha; verification will be added before public launch |
| MINOR | JWT tokens expire after a configurable timeout; no silent refresh — the user is logged out abruptly | Log in again; session state is preserved on the backend |
| INFO | No "Forgot Password" flow | Use the admin script to reset manually via DB access |

---

## Scan Execution

| Severity | Issue | Workaround |
|----------|-------|------------|
| MINOR | Scans on sites with JavaScript-rendered content show fewer pages than the site actually has | Expected; SPA/JS rendering is not supported in v0.x |
| MINOR | `quick` profile on large sites may only scan the root page and 10–20 subpages | Use `standard` profile for more coverage |
| INFO | Domain ownership verification is bypassed in dev mode (`DEV_ALLOW_UNVERIFIED_SCANS=true`) | This is intentional for development; **must not be set in production** |
| INFO | A scan stuck on `queued` for >2 minutes usually means the worker is not running | Run `docker compose logs --tail=50 worker` to diagnose |

---

## Results Page

| Severity | Issue | Workaround |
|----------|-------|------------|
| INFO | External Domains section appears only when the scan detected external `<script src>` domains — it is absent for clean pages | Expected behaviour |
| INFO | WADE "Change Detection" shows "No previous baseline existed" on the first scan of a website | Run a second scan to enable baseline comparison |
| MINOR | Report downloads require the scan to have completed successfully; partially-completed scans may show empty report buttons | Trigger a new scan |

---

## Engine Diagnostics

| Severity | Issue | Workaround |
|----------|-------|------------|
| INFO | `js_collector` always appears in the "Engines with findings" section counting 0 findings — this is an aggregation edge case | Cosmetic; the engine did run correctly |
| INFO | TLS checker may show "skipped" for `http://` targets (not `https://`) | Expected; no TLS to check on plain HTTP |

---

## Monitoring Page

| Severity | Issue | Workaround |
|----------|-------|------------|
| MINOR | WADE Activity section is absent until at least one `wade_anomaly` notification exists | Run two scans on the same website; if page structure changed, a WADE anomaly notification is created |
| INFO | Schedule "next run" time is calculated from `schedule.next_run_at` — if the field is null, it shows "No schedule" | Create a schedule via the website monitoring tab |

---

## Notifications

| Severity | Issue | Workaround |
|----------|-------|------------|
| INFO | No email delivery — notifications are in-app only | Check the Notifications page after each scan |
| INFO | `scan_completed` notifications are created for every scan; the list grows quickly in high-volume testing | Use the severity/type filters, or "Mark all read" |

---

## Worker / Celery

| Severity | Issue | Workaround |
|----------|-------|------------|
| MINOR | Worker startup takes ~30 seconds; scans submitted immediately after `docker compose up` may be queued longer than expected | Wait for the worker health check to pass before submitting scans |
| INFO | Celery retry on connection error is configured but not yet fully tuned — a transient Redis blip may cause a scan to fail | Restart the scan manually |

---

## Frontend

| Severity | Issue | Workaround |
|----------|-------|------------|
| COSMETIC | Mobile layout is not optimised for small screens | Use a desktop browser for alpha testing |
| COSMETIC | The sidebar does not collapse on mobile | Rotate to landscape or use a wider screen |
| INFO | The Settings page shows account info but does not yet support password change or profile updates | Use the DB directly if needed |

---

## Not Yet Implemented (v0.x Scope)

These features are intentionally absent in the alpha:

- Email verification and forgot-password flow
- Team accounts / multi-user workspaces
- OAuth / SSO login
- Webhook or Slack/email alert delivery for notifications
- Authenticated scanning (crawling behind login walls)
- SPA / JavaScript-rendered page crawling
- API endpoint fuzzing or GraphQL scanning
- Rate limiting per-account (disabled by default; set `RATE_LIMIT_ENABLED=true` to enable)
- Horizontal scaling (single worker instance)

---

## Manual Verification Required

The following behaviours **cannot be verified by automated tests** and require a human browser session:

- Scan job detail page auto-refreshes status correctly while a scan is running
- Report download buttons trigger a browser download (not just an API 200)
- Finding detail drawer opens, scrolls, and closes without layout issues
- Notification bell count in the topbar updates after "Mark all read"
- WADE anomaly count matches what appears in the notifications list
- Engine diagnostics collapsible groups expand and collapse correctly

---

## How to File a Bug

File issues at the project's issue tracker with:
1. Steps to reproduce
2. Expected vs. actual behaviour
3. Screenshot or network log if relevant
4. Browser and OS version
5. Whether the Docker stack was freshly started or had prior session data

Use `docs/tester-feedback-template.md` as a starting point.
