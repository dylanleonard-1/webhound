---
title: Reports
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 23 — Reports

→ Existing Phase 8A coverage: [[09-Reports/Phase Results Overview|Phase Results Overview]]

## Scan Reports

Generated per scan by [[07-Scanner/Engine - Reporting|Reporting Engine]]:
- `apps/api/models/report.py` — `Report` model
- Format: PDF / JSON
- Content: score, findings by severity, delta, remediation
- Stored in cloud storage; URL in `Report.storage_url`

## Phase Results

| Phase | Doc |
|-------|-----|
| Phase 8G | `docs/ai/PHASE8G_FULL_VAULT_SYNC_RESULTS.md` |
| Phase 8C-INFRA-LIVE | `docs/ai/PHASE8C_INFRA_LIVE_RESULTS.md` |
| Brain Health | `docs/ai/BRAIN_HEALTH_REPORT.md` |
| LightRAG Runtime | `docs/ai/LIGHTRAG_GRAPH_RUNTIME_RESULTS.md` |
| Graphiti Runtime | `docs/ai/GRAPHITI_RUNTIME_RESULTS.md` |
| Neo4j Runtime | `docs/ai/NEO4J_RUNTIME_RESULTS.md` |
| LightRAG Results | `docs/ai/LIGHTRAG_OLLAMA_RESULTS.json` |

## See Also

- [[07-Scanner/Engine - Reporting|Reporting Engine]] · [[09-Reports/index|Phase 8A Reports]]
- [[05-Database/Database Entity Map|Entity Map (Report)]]

#webhound #reports #index
