<!-- WEBHOUND-GENERATED -->
# Neo4j Runtime Results — Phase 8C-INFRA

**Date:** 2026-06-14T07:01:54.708617Z
**Status:** OFFLINE

## Port Status

| Port | Service | Status |
|------|---------|--------|
| 7687 | Neo4j Bolt | OFFLINE |
| 7474 | Neo4j HTTP browser | OFFLINE |

## Gap

Docker daemon not running in this environment. See `docker-compose.ai-brain.yml` to start Neo4j locally.

## Setup (when Docker is available)

```bash
# Start Neo4j
docker compose -f docker-compose.ai-brain.yml up -d

# Wait ~30s for Neo4j to be healthy, then:
.venv-api/Scripts/python scripts/ai/load_neo4j.py
.venv-api/Scripts/python scripts/ai/load_brain_graph_neo4j.py
.venv-api/Scripts/python scripts/ai/load_graphiti_seed_memories.py --live
```

## Auth (LOCAL DEV ONLY)

| Setting | Value |
|---------|-------|
| URI | bolt://localhost:7687 |
| User | neo4j |
| Password | webhound-brain-local-dev |

**Never use this password outside localhost dev.**
