---
title: LightRAG Entity Map
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# LightRAG Entity Map

Current graph state as of Phase 8C-INFRA-LIVE (2026-06-14).

## Counts

| Metric | Value |
|--------|-------|
| Entities | 19 |
| Relationships | 1 |
| Chunks indexed | 30 |
| Graph file | `lightrag_storage/graph_chunk_entity_relation.graphml` |

## Entity Storage

Entities stored in `lightrag_storage/vdb_entities.json` (NanoVectorDB format):
- `{"embedding_dim": 384, "data": [...19 items...], "matrix": ...}`
- Each entity: `{id, entity_name, entity_type, description, source_id}`

## Graph Characteristics

- Format: NetworkX GraphML (in-memory, not persisted to Neo4j)
- Node types: entity nodes extracted by phi3:mini from corpus chunks
- Edge types: relationships between entities
- Coverage: sparse (phi3:mini 3.8B extracts conservatively at Q4_0)

## Relationship to Neo4j

LightRAG uses its own NetworkX graph (`lightrag_storage/`). This is **separate** from the Neo4j brain graph. They are complementary:

| System | Graph Content |
|--------|---------------|
| LightRAG | Corpus entity relationships (extracted by LLM) |
| Neo4j | Brain graph (FileNode + code dependencies + Graphiti episodes) |

## See Also

- [[14-LightRAG/index|LightRAG Index]] · [[16-Neo4j/index|Neo4j]] · [[15-Graphiti/index|Graphiti]]

#webhound #lightrag #entities
