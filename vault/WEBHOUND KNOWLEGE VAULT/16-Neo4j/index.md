---
title: Neo4j
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 16 — Neo4j

## Status: LIVE (Local Dev)

| Metric | Value |
|--------|-------|
| Version | neo4j:5-community |
| Container | Docker in WSL2 (Ubuntu-24.04) |
| Bolt | bolt://localhost:7687 |
| HTTP | http://localhost:7474 |
| Total nodes | 172 |
| Total relationships | 191 |

**Credentials: LOCAL DEV ONLY** (`neo4j/webhound-brain-local-dev`)

## Notes

- [[16-Neo4j/Neo4j Graph Overview|Graph Overview]]
- [[16-Neo4j/Neo4j Schema|Schema]]

## Node Breakdown

| Label | Count |
|-------|-------|
| FileNode | 126 |
| Episodic | 19 |
| Entity | 27 |
| Community | ~0 |
| Total | 172 |

## Relationship Breakdown

| Type | Count |
|------|-------|
| DEPENDS_ON | 34 |
| WIKI_LINK | 157 |
| Total | 191 |

## Hosted Content

Two distinct datasets in one Neo4j instance:
1. **Brain graph** — 126 FileNode + code dependencies (loaded by `load_brain_graph_neo4j.py`)
2. **Graphiti episodes** — 19 Episodic + 27 Entity nodes (seeded by `load_graphiti_seed_memories.py`)

## Scripts

- `scripts/ai/load_brain_graph_neo4j.py` — load brain graph from `docs/ai/graphify/graph.json`
- `scripts/ai/load_graphiti_seed_memories.py` — seed Graphiti episodes
- `scripts/ai/check_neo4j.py` — health check + Cypher queries

## Start/Stop

```bash
# Start (WSL2)
wsl -d Ubuntu-24.04 -- docker start neo4j-brain
# OR fresh start:
wsl -d Ubuntu-24.04 -- docker run -d --name neo4j-brain \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/webhound-brain-local-dev \
  neo4j:5-community

# Stop
wsl -d Ubuntu-24.04 -- docker stop neo4j-brain
```

## See Also

- [[16-Neo4j/Neo4j Graph Overview|Graph Overview]] · [[16-Neo4j/Neo4j Schema|Schema]]
- [[15-Graphiti/index|Graphiti]] · [[18-Graphify/index|Graphify]]
- [[11-External Tools/Neo4j Graph Schema Plan|Phase 8A Neo4j Plan]] · [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #neo4j #index
