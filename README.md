# WebHound

Security scanning and monitoring platform. Crawls websites, runs security engines, scores findings, and surfaces actionable vulnerabilities.

---

## Table of Contents

- [Architecture](#architecture)
- [Quick Start — Local Dev](#quick-start--local-dev)
- [Environment Variables](#environment-variables)
- [Production Deployment](#production-deployment)
- [Database Migrations](#database-migrations)
- [Health Checks](#health-checks)
- [Storage Notes](#storage-notes)
- [Running Tests](#running-tests)

---

## Architecture

```
┌─────────────┐   REST/JSON   ┌──────────────┐   Celery   ┌──────────────┐
│  Next.js 16 │ ──────────── │  FastAPI API  │ ─────────── │ Celery Worker│
│   (web)     │               │  (apps/api)  │             │  (worker/)   │
└─────────────┘               └──────┬───────┘             └──────┬───────┘
                                     │                             │
                              ┌──────▼───────┐             ┌──────▼───────┐
                              │  PostgreSQL  │             │  WebHound    │
                              │  (postgres)  │             │  Scanner     │
                              └──────────────┘             │  (scanner/)  │
                                     ▲                     └──────────────┘
                              ┌──────┴───────┐
                              │    Redis     │
                              │  (broker +   │
                              │   results)   │
                              └──────────────┘
```

Services: `postgres`, `redis`, `api`, `worker`, `web`

---

## Quick Start — Local Dev

### Prerequisites

- Docker + Docker Compose v2
- Python 3.12 (for tests and scripts outside Docker)
- Node 20 (for frontend dev server; not needed when using Docker)

### Start everything

```bash
# Build images and start all five services
./scripts/start_dev.sh

# Options:
./scripts/start_dev.sh --no-e2e     # skip the smoke test
./scripts/start_dev.sh --frontend   # also run Next.js dev server (hot reload)
./scripts/start_dev.sh --pull       # pull latest base images first
```

Once healthy:

| Service  | URL                          | Notes                        |
|----------|------------------------------|------------------------------|
| Frontend | http://localhost:3000        |                              |
| API      | http://localhost:8000        |                              |
| API docs | http://localhost:8000/docs   | Swagger (dev only)           |
| Postgres | localhost:5432               | user/pass: `webhound/webhound` |
| Redis    | localhost:6379               |                              |

### Create your first user (dev)

```bash
python3 scripts/create_admin.py
# or non-interactively:
python3 scripts/create_admin.py --email me@example.com --password mypassword
```

### Stop

```bash
docker compose down
```

---

## Environment Variables

Copy `.env.example` to `.env` for local dev (Docker Compose reads it automatically).

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | yes | `postgresql+asyncpg://webhound:webhound@localhost:5432/webhound` | Async PostgreSQL URL |
| `REDIS_URL` | yes | `redis://localhost:6379/0` | Redis URL for Celery broker and result backend |
| `SECRET_KEY` | **yes** | *(dev default)* | HS256 signing key for JWTs. **Must be changed in production.** |
| `APP_ENV` | yes | `development` | One of `development`, `staging`, `production` |
| `DEBUG` | no | `false` | Enable debug mode. Never `true` in production. |
| `LOG_LEVEL` | no | `INFO` | Python log level: `DEBUG` `INFO` `WARNING` `ERROR` |
| `CORS_ORIGINS` | prod | *(localhost defaults)* | JSON array of allowed frontend origins: `["https://app.example.com"]` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | no | `1440` | JWT lifetime (minutes). 1440 = 24 hours. |
| `RATE_LIMIT_ENABLED` | no | `false` | Enable per-IP rate limiting. Recommended `true` in production. |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | no | `60` | Max requests/minute/IP when rate limiting is on. |
| `WORKER_CONCURRENCY` | no | `2` | Celery worker process count. Tune to available cores. |
| `NEXT_PUBLIC_API_URL` | yes | `http://localhost:8000` | Public API URL baked into the frontend bundle at build time. |
| `POSTGRES_USER` | no | `webhound` | Postgres user (docker-compose init). |
| `POSTGRES_PASSWORD` | prod | `webhound` | Postgres password. Change in production. |
| `POSTGRES_DB` | no | `webhound` | Postgres database name. |
| `DEV_ALLOW_UNVERIFIED_SCANS` | no | `false` | Skip domain verification for scan jobs. Dev/Docker only. **App rejects this in production.** |
| `API_PORT` | no | `8000` | Host port for the API (prod compose only). |
| `WEB_PORT` | no | `3000` | Host port for the frontend (prod compose only). |

### Generating SECRET_KEY

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## Production Deployment

### 1. Prepare environment file

```bash
cp .env.example .env.prod
# Edit .env.prod — fill in all required values:
#   SECRET_KEY       → strong random value (see above)
#   DATABASE_URL     → prod PostgreSQL URL
#   REDIS_URL        → prod Redis URL
#   CORS_ORIGINS     → ["https://app.your-domain.com"]
#   NEXT_PUBLIC_API_URL → https://api.your-domain.com
#   POSTGRES_PASSWORD → strong password
```

> **.env.prod must never be committed to version control.** It is in `.gitignore`.

### 2. Start the production stack

```bash
./scripts/start_prod.sh
```

This builds all images, starts the five services using `docker-compose.prod.yml`, and waits for each to report healthy.

```bash
# Restart without rebuilding images (e.g., config change):
./scripts/start_prod.sh --no-build

# Stop the production stack:
./scripts/start_prod.sh --down
```

### 3. Create admin user

```bash
# Run inside the api container (DATABASE_URL is already set):
docker compose -f docker-compose.prod.yml exec api python3 scripts/create_admin.py
```

### 4. Verify health

```bash
curl http://localhost:8000/health
curl http://localhost:8000/health/db
curl http://localhost:8000/health/worker
```

### Reverse proxy

WebHound expects to sit behind a reverse proxy (nginx, Caddy, Traefik) that handles TLS termination. Configure your proxy to forward to:

- API: `localhost:8000` (or `${API_PORT}`)
- Frontend: `localhost:3000` (or `${WEB_PORT}`)

Set `NEXT_PUBLIC_API_URL` to the **public** HTTPS URL of the API (e.g. `https://api.example.com`) before building the web image, since it is baked into the JS bundle.

### Scaling

- **More scan parallelism**: increase `WORKER_CONCURRENCY` (default 2). Each concurrent worker uses one CPU core and one DB connection.
- **Multiple API instances**: the API is stateless; run behind a load balancer. Share the same `DATABASE_URL` and `REDIS_URL`.
- **Database connection pool**: managed by asyncpg. Default pool size is fine for small deployments.

---

## Database Migrations

Migrations are managed by Alembic. The API container runs `alembic upgrade head` automatically on startup.

```bash
# Run from the repo root (requires DATABASE_URL in environment or .env):

# Upgrade to latest
./scripts/run_migrations.sh

# Show current revision
./scripts/run_migrations.sh current

# Show migration history
./scripts/run_migrations.sh history

# Roll back one step
./scripts/run_migrations.sh downgrade -1

# Roll back to a specific revision
./scripts/run_migrations.sh downgrade 0004
```

### Migration history

| Revision | Description |
|---|---|
| 0001 | Initial schema (users, websites, scan_jobs, scan_results, findings) |
| 0002 | Add celery_task_id to scan_jobs |
| 0003 | Add scan_schedules |
| 0004 | Add notifications |
| 0005 | Performance indexes, unique constraints, cascade fix |

### Creating a new migration

```bash
alembic -c apps/api/alembic.ini revision --autogenerate -m "describe your change"
# Review the generated file in apps/api/migrations/versions/ before applying.
```

---

## Health Checks

| Endpoint | Checks |
|---|---|
| `GET /health` | API process is alive |
| `GET /health/db` | PostgreSQL connection |
| `GET /health/worker` | Redis broker reachable |

All health endpoints are used by Docker's health-check directives and return HTTP 200 with a JSON body (`{"status": "ok", ...}`).

The `/docs` Swagger UI is **disabled** when `APP_ENV=production`.

---

## Storage Notes

### PostgreSQL data

All scan results, findings, baselines, schedules, and notifications are stored in PostgreSQL. The `postgres_data` Docker volume persists between restarts.

**Backup**: use `pg_dump` before upgrades or migrations:

```bash
docker compose exec postgres pg_dump -U webhound webhound > backup_$(date +%Y%m%d).sql
```

### Baselines

Baseline JSON snapshots are stored in the `baselines` table (`baseline_json` column) as JSON. Each website can have multiple versioned baselines. The unique constraint `(website_id, baseline_version)` prevents duplicates.

### Report files

Generated reports (JSON, CSV, Markdown, SARIF) are stored in the `reports` table (`content_json` column) alongside their scan result. There is no separate filesystem volume needed for reports.

Scanner reports produced during development (standalone `run_scan.py`) are written to `scanner/reports/` — this directory is excluded from Docker images.

### Notifications

Notifications are owned by users and soft-linked to websites/scans via nullable FKs (`ondelete=SET NULL`). Deleting a website or scan does not delete its notifications — the context columns become NULL. Deleting a user does cascade-delete all their notifications.

---

## Running Tests

### API tests

```bash
python3 -m pytest apps/api/tests/ -q
```

### Scanner tests

```bash
python3 -m pytest scanner/ -q
```

### All tests

```bash
python3 -m pytest apps/api/tests/ scanner/ -q
```

### Frontend TypeScript check

```bash
cd apps/web && npm run build
```

---

## Scripts Reference

| Script | Description |
|---|---|
| `./scripts/start_dev.sh` | Build + start dev stack (alias for `setup_dev.sh`) |
| `./scripts/start_prod.sh` | Build + start production stack from `.env.prod` |
| `./scripts/run_migrations.sh` | Run Alembic migrations |
| `./scripts/create_admin.py` | Create a user in the database |
| `./scripts/run_scan.sh <url>` | Run the scanner standalone (no API required) |
| `./scripts/backend_e2e_check.py` | Smoke-test a running API stack |
