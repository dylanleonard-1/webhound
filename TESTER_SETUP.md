# WebHound — Alpha Tester Setup Guide

Complete setup from zero to a running scan. Estimated time: 10–15 minutes.

---

## Prerequisites

Before starting, confirm you have:

| Tool | Minimum version | Check |
|---|---|---|
| Docker Desktop (or Engine + Compose plugin) | Docker 24, Compose v2 | `docker compose version` |
| Python | 3.10 | `python3 --version` |
| Free disk space | ~3 GB (images + DB) | |
| Free ports | 3000, 5432, 6379, 8000 | |

**Windows users**: WSL 2 is required. Run all commands inside your WSL terminal, not PowerShell or CMD.

**macOS users**: Docker Desktop must be running before you begin.

---

## Step 1 — Get the Code

If you received a zip archive:

```bash
unzip webhound-alpha.zip
cd webhound-alpha
```

If you have direct repo access:

```bash
git clone <repo-url>
cd webhound
```

---

## Step 2 — Configure Environment

Copy the example environment file:

```bash
cp .env.example .env
```

The defaults in `.env.example` work for local Docker development. **Do not change anything for your first run.**

If any of the default ports (3000, 5432, 6379, 8000) are already in use on your machine, edit `.env` to change `API_PORT` or `WEB_PORT` — but try the defaults first.

> Note: `DEV_ALLOW_UNVERIFIED_SCANS=true` is set in `docker-compose.yml` for the alpha. This bypasses domain ownership verification so you can scan immediately without configuring DNS records. It is intentional for local testing only.

---

## Step 3 — Build and Start the Stack

```bash
docker compose up --build -d
```

This builds five images and starts: `postgres`, `redis`, `api`, `worker`, `web`.

First build takes 3–8 minutes depending on your connection. Subsequent starts take under a minute.

Wait for all services to become healthy:

```bash
docker compose ps
```

All five rows should show `healthy` in the Status column. The `api` service takes the longest (~30 seconds after the container starts).

**If a service stays `starting` for more than 3 minutes:**

```bash
docker compose logs api       # check API errors
docker compose logs worker    # check worker errors
docker compose logs postgres  # check DB errors
```

---

## Step 4 — Create Your Account

Option A — via the frontend (easiest):

1. Open http://localhost:3000
2. Click **Register** and create an account with your email and a password

Option B — via the seed script (creates demo account automatically):

```bash
python3 scripts/seed_demo.py
# Creates: demo@webhound.dev / DemoHound42!
```

Option C — via the API directly:

```bash
curl -s -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"YourPassword1!"}' \
  | python3 -m json.tool
```

---

## Step 5 — Log In

Open http://localhost:3000 and log in with the credentials you created in Step 4.

Verify the API works independently:

```bash
curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"YourPassword1!"}' \
  | python3 -m json.tool
```

You should receive an `access_token` in the response.

---

## Step 6 — Add an Authorized Website

**Important**: Only add a website you own or are explicitly authorized to test.  
For initial verification, `https://example.com` is safe to use — it is an IANA-designated test domain.

In the frontend: navigate to **Websites → Add Website** and enter the URL.

Via API:

```bash
TOKEN="<your-access-token>"

curl -s -X POST http://localhost:8000/websites \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","display_name":"Example (Demo)"}' \
  | python3 -m json.tool
```

Note the `id` in the response — you'll use it in the next step.

---

## Step 7 — Run a Scan

In the frontend: open the website and click **Start Scan** → choose **Quick** profile.

Via API:

```bash
WEBSITE_ID="<website-id-from-step-6>"

curl -s -X POST http://localhost:8000/scan-jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"website_id\": \"$WEBSITE_ID\",
    \"profile\": \"quick\",
    \"save_baseline\": true,
    \"use_latest_baseline\": false
  }" | python3 -m json.tool
```

Poll for completion (status transitions: `queued` → `running` → `completed`):

```bash
JOB_ID="<job-id-from-above>"

curl -s "http://localhost:8000/scan-jobs/$JOB_ID" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

A quick scan of `example.com` typically completes in 30–90 seconds.

---

## Step 8 — View Results

In the frontend: open the scan job and navigate to the **Results** tab.

Via API — get the result ID:

```bash
curl -s "http://localhost:8000/scan-results?scan_job_id=$JOB_ID" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Get full findings detail:

```bash
RESULT_ID="<result-id>"

curl -s "http://localhost:8000/scan-results/$RESULT_ID" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

For a reference example of what a complete result looks like, see `scripts/fixtures/sample_scan_result.json`.

---

## Demo Flow Summary

```
docker compose up --build -d
↓
python3 scripts/seed_demo.py     (optional: creates demo user + website + scan)
↓
Open http://localhost:3000
↓
Login → Add website → Start scan → View results → Download report
↓
Check notifications (bell icon)
↓
Create a weekly schedule
↓
Report bugs: BUG_REPORT_TEMPLATE.md
Submit feedback: FEEDBACK_TEMPLATE.md
```

---

## Useful Commands

| Action | Command |
|---|---|
| Start stack | `docker compose up -d` |
| Stop stack (keep data) | `docker compose down` |
| Stop stack + wipe DB | `docker compose down -v` |
| View API logs | `docker compose logs -f api` |
| View worker logs | `docker compose logs -f worker` |
| Run full E2E smoke test | `python3 scripts/backend_e2e_check.py` |
| Seed demo data | `python3 scripts/seed_demo.py` |
| API interactive docs | http://localhost:8000/docs |
| Run backend tests | `python3 -m pytest apps/api/tests/ -q` |

---

## Troubleshooting

**"Port already in use"**  
Another service is using port 3000, 5432, 6379, or 8000. Stop conflicting services, or edit the port bindings in `docker-compose.yml`.

**Scan stays in `queued` forever**  
The worker isn't running. Check `docker compose logs worker`. If it shows errors, try `docker compose restart worker`.

**API returns 403 when creating scan jobs**  
`DEV_ALLOW_UNVERIFIED_SCANS` is not set to `true`. Confirm the `api` service in `docker-compose.yml` has this environment variable.

**Frontend shows blank page**  
Check `docker compose logs web`. If you see a build error, run `docker compose build web` and restart.

**`seed_demo.py` says "API is not reachable"**  
The API health check hasn't passed yet. Wait 30–60 seconds and re-run.

---

## Done?

Report bugs using `BUG_REPORT_TEMPLATE.md` and submit your session feedback using `FEEDBACK_TEMPLATE.md`.

Thank you for testing WebHound.
