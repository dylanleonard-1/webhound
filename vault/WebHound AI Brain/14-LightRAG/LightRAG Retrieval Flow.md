---
title: LightRAG Retrieval Flow
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# LightRAG Retrieval Flow

## Modes

LightRAG supports four retrieval modes. WebHound uses `hybrid` for WADE enrichment.

| Mode | Description |
|------|-------------|
| `naive` | Simple chunk vector search |
| `local` | Entity-local graph context |
| `global` | Full graph community summaries |
| `hybrid` | Local + global combined |

## Query Flow

```
Query (finding type + context)
      ↓
[Embedding] all-MiniLM-L6-v2 → 384-dim vector
      ↓
[Vector Search] vdb_chunks.json → top-K chunks
      ↓
[Graph Lookup] vdb_entities.json → entity neighbors
      ↓
[LLM Synthesis] phi3:mini → synthesized answer
      ↓
WADE context enrichment
```

## Index Build Flow

```
Corpus chunk (plain text)
      ↓ phi3:mini prompt
Extract entities + relationships (JSON)
      ↓
Store in vdb_entities.json (NanoVectorDB)
Store in graph_chunk_entity_relation.graphml (NetworkX)
Store chunk vector in vdb_chunks.json
Cache LLM response in kv_store_llm_response_cache.json
```

## Current Graph State

- 19 entities, 1 relationship
- Entity coverage: 30/30 chunks indexed
- Graph is sparse (phi3:mini extracts conservatively)

## Customizations

- `_LocalEmbeddingFunc`: wraps `all-MiniLM-L6-v2` SentenceTransformer (384-dim)
- `ollama_model_complete`: reads model from `global_config["llm_model_name"]`; host from `kwargs.pop("host", None)`

## See Also

- [[14-LightRAG/index|LightRAG Index]] · [[14-LightRAG/LightRAG Entity Map|Entity Map]]
- [[17-Ollama/index|Ollama]] · [[08-WADE/WADE Layer Map|WADE Layer Map]]

#webhound #lightrag #retrieval
