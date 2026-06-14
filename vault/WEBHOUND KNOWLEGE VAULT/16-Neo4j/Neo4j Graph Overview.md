---
title: Neo4j Graph Overview
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Neo4j Graph Overview

## Two Graphs in One Instance

### 1. Brain Graph (Graphify export)

Loaded from `docs/ai/graphify/graph.json` (126 FileNode, Python + Markdown files).

```cypher
MATCH (n:FileNode) RETURN count(n)  -- 126
MATCH ()-[r:DEPENDS_ON]->() RETURN count(r)  -- 34
MATCH ()-[r:WIKI_LINK]->() RETURN count(r)   -- 157
```

Node properties: `id`, `kind` (python/markdown), `path`, `label`

### 2. Graphiti Knowledge Graph

Seeded by Graphiti from 13 episodes via phi3:mini entity extraction.

```cypher
MATCH (n:Episodic) RETURN count(n)  -- 19
MATCH (n:Entity)   RETURN count(n)  -- 27
```

## Full Node Query

```cypher
-- Count all by label
MATCH (n)
RETURN labels(n) AS label, count(n) AS count
ORDER BY count DESC
```

## Useful Queries

```cypher
-- Find FileNode dependencies
MATCH (a:FileNode)-[:DEPENDS_ON]->(b:FileNode)
RETURN a.id, b.id LIMIT 20

-- Find Episodic nodes with episodes
MATCH (e:Episodic) RETURN e.name, e.episode_body LIMIT 5

-- Find entity relationships
MATCH (a:Entity)-[r]-(b:Entity)
RETURN a.name, type(r), b.name LIMIT 20

-- Full graph summary
MATCH (n) RETURN labels(n), count(n) AS cnt ORDER BY cnt DESC
```

## See Also

- [[16-Neo4j/index|Neo4j Index]] · [[16-Neo4j/Neo4j Schema|Schema]]
- [[15-Graphiti/Graphiti Episode Overview|Graphiti Episodes]] · [[18-Graphify/index|Graphify]]

#webhound #neo4j #graph
