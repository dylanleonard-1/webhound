# WebHound Alpha — Manual Testing Checklist

This is the primary manual testing guide for the WebHound alpha release.
Work through it top-to-bottom in a real browser against a running stack.

**Claude cannot perform browser testing** — these steps must be run by a human.

---

## Prerequisites

The stack must be running before you start. See [Developer Commands](#developer-commands) below.

- [ ] `docker compose ps` shows all services as **healthy**
- [ ] `http://localhost:3000` loads the login page
- [ ] `http://localhost:8000/health` returns `{"status":"ok"}`

---

## 1. Registration and Login

- [ ] Open `http://localhost:3000/register`
- [ ] Fill in email + password and submit
- [ ] You are redirected to `/dashboard`
- [ ] Sidebar shows: Overview, Websites, Scans, Monitoring, Notifications, Settings
- [ ] Open `http://localhost:3000/login` in an incognito window
- [ ] Log in with the same credentials
- [ ] Close the incognito window; continue in the main browser session

**Edge cases:**
- [ ] Try registering the same email twice → expect a clear error message (not a crash)
- [ ] Try logging in with wrong password → expect 401 / "Invalid credentials" message

---

## 2. Add a Website

- [ ] Click **Websites** in the sidebar
- [ ] Click **Add Website** (or the "+ New" button)
- [ ] Enter a URL you are authorised to scan — use `https://example.com` for a safe demo target
- [ ] Submit
- [ ] The website appears in the website list with its hostname

**Edge cases:**
- [ ] Try adding the same URL again → expect a duplicate error, not a crash
- [ ] Try adding a URL without `https://` → observe whether it accepts or rejects it

---

## 3. Start a Scan

- [ ] Click the website in the list to open the website detail page
- [ ] Click **Start Scan** (or **New Scan**)
- [ ] Choose profile: `quick` (fastest, ~30–60 seconds) or `standard` (~2 minutes)
- [ ] Submit
- [ ] You are taken to the scan job detail page
- [ ] Status shows **queued** then transitions to **running** (may need manual refresh)
- [ ] After the scan completes, status shows **completed**
- [ ] The scan result ID appears as a link

**Wait time:** `quick` profile typically completes in 30–60 seconds. `standard` takes 1–3 minutes.
If the scan is stuck on **queued** after 2 minutes, check worker logs (see Developer Commands).

---

## 4. View Scan Results

- [ ] Click the scan result link from the scan job page
- [ ] The results page loads without an error state
- [ ] **Risk score** circle is visible with a number and label
- [ ] **Severity Breakdown** card shows finding counts
- [ ] **Performance** card shows pages crawled, duration, and profile

**"Fix First" section** (appears when critical/high findings exist):
- [ ] Up to 5 prioritised findings are listed with severity badges and category
- [ ] Clicking a finding opens the detail drawer
- [ ] The drawer shows: title, description, remediation, affected URLs, evidence, compliance mappings
- [ ] Closing the drawer works (click outside, press Escape, or click ×)

**All Findings table:**
- [ ] Findings are listed sorted by severity (critical first)
- [ ] Severity filter works
- [ ] Category filter appears and works if multiple categories exist
- [ ] Clicking a finding opens the detail drawer

---

## 5. Engine Diagnostics

- [ ] Scroll to **Scanner Engines** section
- [ ] At least some engines show "passed" or "with findings"
- [ ] If any engines show "failed", note the error message shown
- [ ] Click "Engines with findings" to expand/collapse
- [ ] Click "Engines that passed" to expand/collapse

---

## 6. WADE Behavioral Analysis

- [ ] Scroll to **Behavioral Analysis** section
- [ ] **Site Snapshot** card should say "A behavioral baseline was captured"
- [ ] **Change Detection** card should say "No previous baseline existed — run a second scan"
- [ ] **Anomalies** card reflects the appropriate state

Run a second scan on the same website to validate change detection:
- [ ] Go back to the website detail and start another scan (same profile)
- [ ] After completion, view the new result
- [ ] **Change Detection** should now say "This scan was compared against a previous baseline"
- [ ] **Anomalies** count is present (0 is fine — it means no unexpected changes)

---

## 7. External Domains Section

- [ ] Scroll to **External Domains Observed** section (appears when external scripts exist)
- [ ] Trusted CDN/platform domains show as green badges
- [ ] Unknown/unrecognised domains show as yellow badges with a warning note
- [ ] Section is absent when no external scripts were detected

---

## 8. Report Downloads

- [ ] Scroll to **Export Report** section
- [ ] Four format buttons appear: JSON, SARIF, CSV, Markdown
- [ ] Click **JSON** → browser downloads a `.json` file
- [ ] Click **Markdown** → browser downloads a `.md` file
- [ ] Verify the downloaded files are not empty

---

## 9. Monitoring Page

- [ ] Click **Monitoring** in the sidebar
- [ ] Page loads without crashing
- [ ] If no websites/schedules exist: onboarding card with "Add your first website" link is shown
- [ ] If websites exist: "Monitored Sites" card lists them with next-run info (or "No schedule")

---

## 10. Notifications Page

- [ ] Click **Notifications** in the sidebar (or the bell icon in the topbar)
- [ ] Page loads without crashing
- [ ] Notifications appear after a scan completes (e.g. "Scan Completed" notification)
- [ ] Severity filter works
- [ ] Type filter works
- [ ] Click **Mark all read** → unread count in topbar updates
- [ ] Clicking the notification's "View result" link (if present) navigates to the correct result

---

## 11. Schedule Creation (if available)

- [ ] Go to **Websites** → open a website → click **Monitoring** tab (or the monitoring link)
- [ ] Look for a **Create Schedule** section
- [ ] Create a daily schedule (e.g. every 24 hours)
- [ ] The schedule appears in the list on the Monitoring page
- [ ] Pause / delete the schedule to keep the dev environment clean

---

## 12. Settings Page

- [ ] Click **Settings** in the sidebar
- [ ] Your email address is shown
- [ ] **Logout** button works → you are redirected to `/login`

---

## Known Safe Test Targets

The following targets are safe to use for alpha testing:

| URL | Notes |
|-----|-------|
| `https://example.com` | IANA reserved, minimal findings expected |
| `https://httpbin.org` | Returns standard headers, good for header engine testing |
| A website you personally own or operate | Best for realistic results |

**Do not** scan sites you do not own or are not explicitly authorised to test.
See `docs/safety-authorization-notice.md`.

---

## Developer Commands

### Start the stack

```bash
# Start all services (build if needed)
docker compose up -d

# Check all services are healthy
docker compose ps

# Or use the dev startup script (builds, starts, waits for healthy, runs e2e check)
bash scripts/setup_dev.sh

# Start frontend in dev mode (hot reload)
bash scripts/setup_dev.sh --frontend
```

### View logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f api
docker compose logs -f worker
docker compose logs -f web

# Recent 100 lines from worker (useful when scan is stuck)
docker compose logs --tail=100 worker
```

### Check health endpoints

```bash
# API alive
curl http://localhost:8000/health

# Database connected
curl http://localhost:8000/health/db

# Worker (broker) reachable
curl http://localhost:8000/health/worker
```

### Quick smoke test (no scan, ~10 seconds)

```bash
python3 scripts/smoke_check.py
```

### Full e2e test (runs a real scan, ~3–5 minutes)

```bash
python3 scripts/backend_e2e_check.py

# With WADE comparison (two scans, ~6–10 minutes)
python3 scripts/backend_e2e_check.py --wade

# Against a specific URL
python3 scripts/backend_e2e_check.py --target https://example.com
```

### Promote a user to admin

```bash
# Requires DATABASE_URL or a running stack
DATABASE_URL=postgresql+asyncpg://webhound:webhound@localhost:5432/webhound \
  python3 scripts/promote_admin.py --email your@email.com
```

### Reset the dev database

```bash
# Wipe everything and start fresh (all data lost)
docker compose down -v
docker compose up -d

# Apply migrations only (no data loss)
docker compose exec api alembic upgrade head
```

### Seed demo data

```bash
# Creates a demo user and pre-seeded website
docker compose up -d
python3 scripts/seed_demo.py
# Then log in with: demo@webhound.dev / demo-password-change-me
```

### Stop the stack

```bash
docker compose down          # stop containers, keep data
docker compose down -v       # stop containers and delete all data volumes
```
