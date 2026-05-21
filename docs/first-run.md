# WebHound — First Run & Demo Flow

This guide walks through the full demo from a cold start to viewing results.
Estimated time: 10–15 minutes (plus scan time, typically 1–3 minutes for `quick` profile).

---

## Prerequisites

- Docker Desktop (or Docker Engine + Compose plugin) installed and running
- Python 3.10+ (for seed script)
- Ports 3000, 5432, 6379, and 8000 free on localhost

---

## Step 1 — Start the Stack

```bash
docker compose up -d
```

Wait for all four services to become healthy:

```bash
docker compose ps
```

All four services (`postgres`, `redis`, `api`, `web`) should show `healthy`.

Alternatively, use the dev setup script which waits for you:

```bash
bash scripts/setup_dev.sh
```

---

## Step 2 — Seed Demo Data

Run the seed script to create the demo user and a demo website:

```bash
python3 scripts/seed_demo.py
```

This creates:
- Demo user: `demo@webhound.dev` / `DemoHound42!`
- Demo website: `https://example.com`
- One queued scan job (quick profile against example.com)
- One weekly schedule

To skip the scan and just create the user and website:

```bash
python3 scripts/seed_demo.py --no-scan --no-schedule
```

**Authorization reminder**: The default target (`example.com`) is designated by IANA for examples and documentation. When demonstrating against any other domain you must own it or have written authorization to scan it.

---

## Step 3 — Log In

Open the frontend: **http://localhost:3000**

Enter the demo credentials:
- Email: `demo@webhound.dev`
- Password: `DemoHound42!`

You can also test via the API directly:

```bash
curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@webhound.dev","password":"DemoHound42!"}' | python3 -m json.tool
```

Copy the `access_token` for subsequent API calls.

---

## Step 4 — Add a Website (if not seeded)

In the frontend, navigate to **Websites → Add Website** and enter the URL of a domain you own.

Via API:

```bash
curl -s -X POST http://localhost:8000/websites \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://yourdomain.example","display_name":"My Test Site"}' | python3 -m json.tool
```

---

## Step 5 — Run a Scan

In the frontend, open the website detail page and click **Start Scan** (choose `quick` for the demo).

Via API:

```bash
curl -s -X POST http://localhost:8000/scan-jobs \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"website_id":"<website_id>","profile":"quick","save_baseline":true,"use_latest_baseline":false}' \
  | python3 -m json.tool
```

Poll for completion:

```bash
curl -s http://localhost:8000/scan-jobs/<job_id> \
  -H "Authorization: Bearer <token>" | python3 -m json.tool
```

When `"status": "completed"` appears, proceed to step 6.

---

## Step 6 — View Scan Results

In the frontend, open the scan job and navigate to the **Results** tab.

Via API — list results for the job:

```bash
curl -s "http://localhost:8000/scan-results?scan_job_id=<job_id>" \
  -H "Authorization: Bearer <token>" | python3 -m json.tool
```

Get full detail including findings:

```bash
curl -s http://localhost:8000/scan-results/<result_id> \
  -H "Authorization: Bearer <token>" | python3 -m json.tool
```

For a representative example of what a result looks like, see `scripts/fixtures/sample_scan_result.json`.

---

## Step 7 — Download a Report

Reports are generated in JSON, SARIF, CSV, and Markdown formats.

List available reports:

```bash
curl -s http://localhost:8000/scan-results/<result_id>/reports \
  -H "Authorization: Bearer <token>" | python3 -m json.tool
```

Download a specific format:

```bash
curl -s http://localhost:8000/scan-results/<result_id>/reports/markdown \
  -H "Authorization: Bearer <token>" | python3 -m json.tool
```

---

## Step 8 — Create a Schedule

Automate recurring scans from the **Schedules** tab in the frontend, or via API:

```bash
curl -s -X POST http://localhost:8000/scan-schedules \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "website_id":"<website_id>",
    "profile":"standard",
    "frequency":"weekly",
    "is_enabled":true,
    "use_latest_baseline":true,
    "save_baseline":true,
    "next_run_at":"2025-06-01T09:00:00Z"
  }' | python3 -m json.tool
```

---

## Step 9 — View Notifications

After a scan completes, WebHound generates in-app notifications for:
- Scan completed
- High-risk or critical findings
- WADE anomalies detected
- Scheduled scan failures

Check your notification inbox in the frontend header, or via API:

```bash
curl -s http://localhost:8000/notifications \
  -H "Authorization: Bearer <token>" | python3 -m json.tool
```

---

## Helpful Commands

| Purpose | Command |
|---|---|
| Full E2E smoke test | `python3 scripts/backend_e2e_check.py` |
| Seed demo data | `python3 scripts/seed_demo.py` |
| API interactive docs | http://localhost:8000/docs |
| Stream API logs | `docker compose logs -f api` |
| Stream worker logs | `docker compose logs -f worker` |
| Stop stack | `docker compose down` |
| Stop and wipe DB | `docker compose down -v` |

---

## Troubleshooting

**API returns 403 on scan start**
> Domain verification is required. The dev stack sets `DEV_ALLOW_UNVERIFIED_SCANS=true` in `docker-compose.yml`, which bypasses this. Confirm the environment variable is set in the `api` service.

**Scan stays in `queued` status**
> The worker is not running or failed to start. Check: `docker compose logs worker`. If the worker is healthy, confirm Redis is reachable.

**`seed_demo.py` reports API unreachable**
> Run `docker compose ps` and confirm the `api` service is `healthy`. The API takes ~30 seconds to start after the container launches.

**Frontend shows blank page or build errors**
> Check `docker compose logs web`. Run `docker compose build web` if the image is stale.
