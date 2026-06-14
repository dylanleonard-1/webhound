<!-- WEBHOUND-GENERATED -->
# Neo4j Runtime Results — Phase 8C-INFRA

**Date:** 2026-06-14T07:55:29.962660Z
**Status:** LIVE

## Port Status

| Port | Service | Status |
|------|---------|--------|
| 7687 | Neo4j Bolt | LIVE |
| 7474 | Neo4j HTTP browser | LIVE |

## Connected

Neo4j is running.

## Setup (when Docker is available)

```bash
# Start Neo4j
docker compose -f docker-compose.ai-brain.yml up -d

# Wait ~30s for Neo4j to be healthy, then:
.venv-api/Scripts/python scripts/ai/load_neo4j.py
.venv-api/Scripts/python scripts/ai/load_brain_graph_neo4j.py
.venv-api/Scripts/python scripts/ai/load_graphiti_seed_memories.py --live
```

## Node Counts

| Label | Count |
|-------|-------|
| KnowledgeSource | 0 |
| Chunk | 0 |
| Provider | 0 |
| TaxonomyEntry | 0 |
| ScannerEngine | 0 |
| ThreatSource | 0 |
| FileNode | 126 |

## Auth (LOCAL DEV ONLY)

| Setting | Value |
|---------|-------|
| URI | bolt://localhost:7687 |
| User | neo4j |
| Password | webhound-brain-local-dev |

**Never use this password outside localhost dev.**
