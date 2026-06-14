---
title: Monitoring
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 19 — Monitoring

## Platform Monitoring

| Component | Method |
|-----------|--------|
| API health | `GET /health` → `apps/api/routers/health.py` |
| Observability | OpenTelemetry → `apps/api/telemetry.py`, `observability.py` |
| Infra metrics | `apps/api/services/infra_metrics.py` |
| Logs | Railway log streaming (`rail logs -f`) |
| Error tracking | `apps/api/errors.py` exception handlers |

## AI Brain Health

- Script: `scripts/ai/check_brain_health.py`
- Output: `docs/ai/brain_health.json` + `BRAIN_HEALTH_REPORT.md`
- Components checked: corpus, vault, hybrid_retrieval, lightrag, graphiti, neo4j, graphify, wade_retrieval, docker, ollama

## Runtime Service Health

| Service | Check | Last Status |
|---------|-------|-------------|
| Ollama | `curl localhost:11434/api/tags` | ✅ LIVE |
| Neo4j | `bolt://localhost:7687` port check | ✅ LIVE |
| LightRAG | `vdb_entities.json` entity count | ✅ LIVE_FULL |
| Graphiti | Neo4j + Ollama + episodes | ✅ READY |

## Alerts & Incidents

- `models/alert.py` — alert conditions
- `models/incident.py` — incident records
- `services/alerts.py` — alert evaluation
- `services/incidents.py` — incident management
- `routers/notifications.py` — delivery

## See Also

- [[06-Infrastructure/index|Infrastructure]] · [[22-Operations/index|Operations]]
- [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #monitoring #index
