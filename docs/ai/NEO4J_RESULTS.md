# Neo4j Results — Phase 8C

**Date:** 2026-06-14
**Status:** OFFLINE — Docker daemon not running in this environment

## Environment

| Component | Status |
|-----------|--------|
| Docker CLI | Installed (v29.4.2) |
| Docker daemon | OFFLINE (Docker Desktop not started) |
| Neo4j image | neo4j:5.26 (not pulled yet) |
| Bolt port 7687 | NOT REACHABLE |

## Gap Analysis

Docker Desktop must be running for the Neo4j container to start.
When Docker Desktop was launched during this session, the daemon
did not respond within the wait window (consistent with prior flaky behavior
noted in the Phase 8C spec).

## What IS Provided

- `docker-compose-neo4j.yml` — Neo4j 5.26 compose file with APOC, bolt/browser ports
- `scripts/ai/load_neo4j.py` — Cypher batch loader for Knowledge nodes
- Dry-run validated (176 statements, 50 KnowledgeSources, 50 Chunks, 16 Providers, 5 ScannerEngines, 5 ThreatSources)

## Schema

### Node Types

| Label | Key Property | Purpose |
|-------|-------------|---------|
| KnowledgeSource | doc_id | Represents a knowledge document |
| Chunk | chunk_id | Text chunk from a document |
| Provider | name | CDN/WAF provider entity |
| TaxonomyEntry | cwe | CWE/OWASP taxonomy node |
| ScannerEngine | name | Scanner engine node |
| ThreatSource | name | Threat intelligence source |

### Relationship Types

| Relationship | From → To | Purpose |
|-------------|-----------|---------|
| HAS_CHUNK | KnowledgeSource → Chunk | Document to chunk mapping |
| REFERENCES | Chunk → TaxonomyEntry | Chunk references a CWE |
| USES | KnowledgeSource → Provider | Doc covers a provider |
| CONFIRMED_BY | Chunk → ScannerEngine | Evidence from scanner |

## Activation Steps

```bash
# 1. Start Docker Desktop (or daemon)
# 2. Pull and start Neo4j
docker compose -f docker-compose-neo4j.yml up -d

# 3. Wait for health check
docker compose -f docker-compose-neo4j.yml ps

# 4. Load knowledge graph (all 487 docs, 1161 chunks)
python scripts/ai/load_neo4j.py

# 5. Browse: http://localhost:7474 (neo4j / webhound-brain-local)
```

## Node/Relationship Counts (projected)

When fully loaded from 487 manifest records / 1161 chunks:

| Node type | Expected count |
|-----------|---------------|
| KnowledgeSource | 487 |
| Chunk | 1,161 |
| Provider | 16 |
| ScannerEngine | 5 |
| ThreatSource | 5 |
| **Total nodes** | **~1,674** |
| HAS_CHUNK edges | ~1,161 |
| **Total edges** | **~1,200+** |

## Honest Status

Neo4j is **offline** in this session. Node/relationship counts above are
**projected** from the corpus — not measured from a live instance.
No fake counts are reported. Activate Docker + Neo4j to get live metrics.
