---
title: Dependency Map
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Dependency Map

Code dependency graph from Graphify analysis. Source: `docs/ai/graphify/graph.json`.

## Graph Summary

| Metric | Value |
|--------|-------|
| FileNodes | 126 |
| DEPENDS_ON edges | 34 |
| WIKI_LINK edges | 157 |
| Total edges | 191 |
| Node kinds | python, markdown |

## Top-Level Clusters (by DEPENDS_ON)

The brain graph shows WebHound's module structure. Key dependency hubs (nodes with many DEPENDS_ON edges) are the core services and models.

```
apps/api/main.py
  ├─ apps/api/routers/* (20+ routers)
  ├─ apps/api/middleware.py
  └─ apps/api/database.py

apps/api/database.py
  └─ apps/api/models/* (30+ models)

apps/api/services/scan_jobs.py
  ├─ apps/api/services/engines.py
  ├─ apps/api/services/result_persistence.py
  └─ apps/api/services/wade_correlation.py

apps/api/models/finding.py
  └─ apps/api/models/scan_result.py
```

## Querying the Graph

```cypher
-- Most-depended-on files
MATCH (n:FileNode)<-[:DEPENDS_ON]-(m)
RETURN n.id, count(m) AS in_degree
ORDER BY in_degree DESC LIMIT 10

-- Files depending on many others
MATCH (n:FileNode)-[:DEPENDS_ON]->(m)
RETURN n.id, count(m) AS out_degree
ORDER BY out_degree DESC LIMIT 10
```

## See Also

- [[18-Graphify/index|Graphify]] · [[16-Neo4j/Neo4j Graph Overview|Neo4j Graph Overview]]

#webhound #maps #dependency
