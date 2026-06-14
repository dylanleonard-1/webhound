---
title: LightRAG
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 14 — LightRAG

## Status: LIVE_FULL

| Metric | Value |
|--------|-------|
| Version | 1.5.2 |
| LLM | phi3:mini via Ollama (local) |
| Embedding | all-MiniLM-L6-v2 (384-dim, local) |
| Chunks indexed | 30/30 (30 corpus chunks) |
| Entities extracted | 19 |
| Relationships extracted | 1 |
| Indexing time | 1800s (30 min) |
| Cloud API used | No |

## Notes

- [[14-LightRAG/LightRAG Retrieval Flow|Retrieval Flow]]
- [[14-LightRAG/LightRAG Entity Map|Entity Map]]

## Architecture

```
Corpus chunks (JSONL)
      ↓
build_lightrag_index_ollama.py
      ↓ phi3:mini (entity/relation extraction)
      ↓ all-MiniLM-L6-v2 (embeddings)
      ↓
lightrag_storage/
  vdb_chunks.json        — 189 KB chunk vectors
  vdb_entities.json      — 69 KB entity vectors (19 entities)
  vdb_relationships.json — 3.6 KB relationship vectors
  graph_chunk_entity_relation.graphml — NetworkX graph
  kv_store_llm_response_cache.json — 1.4 MB LLM cache
      ↓
LightRAG.aquery() → hybrid graph+vector retrieval
```

## Storage Location

`lightrag_storage/` (gitignored — runtime data only)

## Script

`scripts/ai/build_lightrag_index_ollama.py`
- `--n N` to index N chunks (default 30)
- Uses Ollama LLM for entity extraction
- Local SentenceTransformer for embeddings

## Known Issues

- phi3:mini produces some hallucinated entities on complex chunks
- OneDrive temp-file locking causes transient PermissionError (auto-recovered)
- 60s average per chunk (CPU-only inference)

## See Also

- [[14-LightRAG/LightRAG Retrieval Flow|Retrieval Flow]] · [[17-Ollama/index|Ollama]]
- [[13-Knowledge Corpus/index|Corpus]] · [[16-Neo4j/index|Neo4j]] · [[08-WADE/WADE Layer Map|WADE Layer Map]]
- [[08-External Tools/LightRAG Plan|Phase 8A LightRAG Plan]] · [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #lightrag #index
