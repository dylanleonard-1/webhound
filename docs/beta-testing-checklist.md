# Beta Testing Checklist — WebHound v0.x

Use this checklist during your testing session. File a bug report for any item that fails.
Bug report template: `.github/ISSUE_TEMPLATE/bug_report.md`
Feedback form template: `docs/tester-feedback-template.md`

---

## Infrastructure

- [ ] `docker compose up -d` starts without errors
- [ ] All four services (`postgres`, `redis`, `api`, `web`) reach `healthy` state within 2 minutes
- [ ] `docker compose down && docker compose up -d` recovers cleanly (no data loss from prior session)

---

## Authentication

- [ ] New user registration succeeds with a valid email/password
- [ ] Duplicate email registration returns a clear error (not a 500)
- [ ] Login with correct credentials returns a token
- [ ] Login with wrong password returns 401 (not 500 or 200)
- [ ] Authenticated endpoints return 401 when no token is provided
- [ ] Token from one user cannot access resources owned by another user (ownership isolation)

---

## Website Management

- [ ] Can add a website URL (must be a domain you own or `example.com` for demo)
- [ ] Adding the same URL twice returns a clear duplicate error
- [ ] Website appears in the website list
- [ ] Website detail page shows the URL and verification status
- [ ] Can delete a website; it disappears from the list
- [ ] Deleting a website cascades — related scan jobs and results are also removed

---

## Scan Execution

- [ ] Scan job is created with `profile=quick` and enters `queued` status
- [ ] Worker picks up the job; status transitions to `running`
- [ ] Scan completes with `status=completed` within 5 minutes (quick profile on example.com)
- [ ] Failed scan shows `status=failed` with a non-empty `error_message`
- [ ] Cancelled scan shows `status=cancelled`

---

## Scan Results

- [ ] Completed scan has an associated result (`GET /scan-results?scan_job_id=<id>` returns an item)
- [ ] Result includes `risk_score`, `risk_level`, `total_findings`, `severity_breakdown`
- [ ] At least one finding is present with `title`, `severity`, `category`, `description`, and `remediation`
- [ ] Grouped findings endpoint returns findings grouped by category
- [ ] Engine diagnostics list shows which engines ran and their status
- [ ] WADE metadata keys are present in `scanner_metadata` after a scan with `save_baseline=true`

---

## Reports

- [ ] Reports endpoint returns a list of available formats after a completed scan
- [ ] JSON report downloads and parses correctly
- [ ] SARIF report downloads (content is valid JSON)
- [ ] CSV report downloads and opens in a spreadsheet tool
- [ ] Markdown report downloads and renders correctly

---

## Baselines (WADE)

- [ ] A scan with `save_baseline=true` creates a baseline entry under the website
- [ ] `GET /websites/{id}/baselines/latest` returns a baseline after the first scan
- [ ] A second scan with `use_latest_baseline=true` sets `wade_compared_to_previous=true` in the result metadata

---

## Scheduled Scans

- [ ] A weekly schedule can be created for a website
- [ ] Schedule appears in the list with correct `next_run_at`
- [ ] Schedule can be disabled (`is_enabled=false` via PATCH)
- [ ] Disabled schedule can be re-enabled
- [ ] Schedule can be deleted

---

## Notifications

- [ ] After a completed scan, at least one notification appears in `GET /notifications`
- [ ] `GET /notifications/unread-count` returns the correct unread count
- [ ] Marking a notification as read clears it from the unread count
- [ ] `PATCH /notifications/read-all` sets all notifications to read

---

## API Quality

- [ ] `GET /openapi.json` returns valid OpenAPI schema (load in http://localhost:8000/docs)
- [ ] Invalid request bodies return 422 with field-level error details (not 500)
- [ ] Requests to non-existent resource IDs return 404 (not 500)
- [ ] Long-running operations (scan polling) do not cause memory spikes visible in `docker stats`

---

## Frontend (if available)

- [ ] Login and logout flow works
- [ ] Website list loads and displays correctly
- [ ] Scan history for a website is accessible
- [ ] Results page shows findings with severity indicators
- [ ] Notification badge updates after a scan completes
- [ ] No console errors on the main dashboard pages

---

## Security Basics

- [ ] Confirm `DEV_ALLOW_UNVERIFIED_SCANS` is NOT set to `true` in production config (`docker-compose.prod.yml`)
- [ ] Confirm API returns CORS error for requests from unauthorized origins
- [ ] Confirm password field is not returned in any API response

---

## Notes

Use the feedback template (`docs/tester-feedback-template.md`) to summarize your session.
File individual bugs using the GitHub issue template (`.github/ISSUE_TEMPLATE/bug_report.md`).
