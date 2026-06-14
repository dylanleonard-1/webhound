---
title: Operations
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 22 — Operations

## Deployment

| Component | Deploy Method |
|-----------|--------------|
| Backend | Railway auto-deploy on `git push main` |
| Frontend | Vercel auto-deploy on `git push main` |
| AI Brain (local) | Manual — Neo4j Docker + Ollama |

## Maintenance Mode

- `apps/api/middleware.py` → `MaintenanceModeMiddleware`
- Toggleable without redeploy (via env var)
- Returns 503 to all non-health requests when enabled

## Database Migrations

```bash
# Apply pending migrations
alembic upgrade head

# Create new migration
alembic revision --autogenerate -m "description"
```

Migration files: `apps/api/migrations/versions/`

## Admin Operations

- `apps/api/admin/run_scan.py` — trigger scans without UI
- `apps/api/services/admin_scan.py` — admin scan service
- `apps/api/routers/` → `admin/` internal router

## AI Brain Operations

```bash
# Health check
.venv-api/Scripts/python scripts/ai/check_brain_health.py

# Rebuild LightRAG index
.venv-api/Scripts/python scripts/ai/build_lightrag_index_ollama.py --n 30

# Re-seed Graphiti
.venv-api/Scripts/python scripts/ai/load_graphiti_seed_memories.py --live

# Reload brain graph into Neo4j
.venv-api/Scripts/python scripts/ai/load_brain_graph_neo4j.py --live
```

## Runbooks

- Restart Neo4j: `wsl -d Ubuntu-24.04 -- docker start neo4j-brain`
- Stop Neo4j: `wsl -d Ubuntu-24.04 -- docker stop neo4j-brain`
- Stop Ollama: `Get-Process ollama | Stop-Process -Force`

## See Also

- [[06-Infrastructure/index|Infrastructure]] · [[19-Monitoring/index|Monitoring]]
- [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #operations #index
