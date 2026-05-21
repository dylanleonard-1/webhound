# Onboarding Checklist — WebHound Beta

Work through this checklist before your first test session.

---

## Environment Setup

- [ ] Docker Desktop (or Docker Engine ≥ 24 + Compose plugin) installed
- [ ] Docker daemon is running (`docker info` succeeds)
- [ ] Python 3.10 or newer installed (`python3 --version`)
- [ ] Ports 3000, 5432, 6379, and 8000 are free on localhost
- [ ] Git repository cloned (`git clone …`)
- [ ] `.env` file is NOT present in the project root (the stack uses docker-compose env defaults for local dev)

---

## Start the Stack

```bash
docker compose up -d
docker compose ps   # confirm all four services are "healthy"
```

- [ ] `postgres` is healthy
- [ ] `redis` is healthy
- [ ] `api` is healthy (may take ~30 s)
- [ ] `web` is healthy

---

## Verify the API

```bash
curl http://localhost:8000/health
# expect: {"status":"ok"}
```

- [ ] Health check returns `{"status":"ok"}`
- [ ] API docs load at http://localhost:8000/docs

---

## Seed Demo Data

```bash
python3 scripts/seed_demo.py
```

- [ ] Script runs without errors
- [ ] Output confirms "Demo data ready"
- [ ] Demo credentials are printed: `demo@webhound.dev` / `DemoHound42!`

---

## Frontend Access

Open http://localhost:3000

- [ ] Login page loads
- [ ] You can log in with the demo credentials
- [ ] Dashboard shows the demo website (`example.com`)

---

## Read Before Testing

- [ ] Read `docs/safety-authorization-notice.md` — understand what WebHound does and does not do
- [ ] Read `docs/known-limitations.md` — understand current gaps
- [ ] Read `docs/beta-testing-checklist.md` — know what to test and how to report

---

## Optional: Run Automated Tests

```bash
# From the repository root — requires Python packages installed locally:
pip install -r apps/api/requirements.txt -r apps/api/requirements-dev.txt
cd apps/api && python -m pytest tests/ -q
```

- [ ] All tests pass (or note any pre-existing failures)

---

## Ready to Test

If all items above are checked, follow `docs/first-run.md` for the full demo flow.
