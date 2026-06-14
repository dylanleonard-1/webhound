---
title: Neo4j Schema
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Neo4j Schema

## Node Labels

| Label | Source | Key Properties |
|-------|--------|----------------|
| FileNode | Brain graph (Graphify) | id, kind, path, label |
| Episodic | Graphiti episodes | name, episode_body, source, group_id |
| Entity | Graphiti entity extraction | name, entity_type, description |
| Community | Graphiti (future) | summary |
| Saga | Graphiti (future) | name |

## Relationship Types

| Type | From | To | Source |
|------|------|----|--------|
| DEPENDS_ON | FileNode | FileNode | Brain graph |
| WIKI_LINK | FileNode | FileNode | Brain graph |
| RELATES_TO | Entity | Entity | Graphiti |
| HAS_ENTITY | Episodic | Entity | Graphiti |
| IN_COMMUNITY | Entity | Community | Graphiti (future) |

## Indexes & Constraints

Created by `graphiti.build_indices_and_constraints()`:
- Constraint on `Entity(uuid)` (Graphiti)
- Constraint on `Episodic(uuid)` (Graphiti)
- Vector index on `Entity(embedding)` — nomic-embed-text 768-dim
- Vector index on `Episodic(embedding)` — nomic-embed-text 768-dim

## Schema Notes

- Brain graph uses string IDs (`FileNode.id`)
- Graphiti uses UUID-based nodes with vector embeddings
- Both coexist in the same database without collision

## See Also

- [[16-Neo4j/index|Neo4j Index]] · [[16-Neo4j/Neo4j Graph Overview|Graph Overview]]
- [[15-Graphiti/Graphiti Memory Types|Graphiti Memory Types]]

#webhound #neo4j #schema
