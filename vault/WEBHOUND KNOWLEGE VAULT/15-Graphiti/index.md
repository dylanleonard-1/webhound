---
title: Graphiti
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 15 — Graphiti

## Status: LIVE

| Metric | Value |
|--------|-------|
| Version | graphiti-core (latest) |
| Episodes defined | 13 |
| Episodes seeded | 13/13 (all loaded) |
| Episodic nodes (Neo4j) | 19 |
| Entity nodes (Neo4j) | 27 |
| LLM | phi3:mini via Ollama |
| Embedder | nomic-embed-text (768-dim) via Ollama |
| Neo4j backend | bolt://localhost:7687 (LOCAL DEV ONLY) |

## Notes

- [[15-Graphiti/Graphiti Memory Types|Memory Types]]
- [[15-Graphiti/Graphiti Episode Overview|Episode Overview]]

## Architecture

```
Episode schema (corpus/exports/graphiti_episode_schema.json)
      ↓
load_graphiti_seed_memories.py --live
      ↓ phi3:mini (entity extraction via OpenAI-compat API)
      ↓ nomic-embed-text (768-dim embeddings)
      ↓
Neo4j @ bolt://localhost:7687
  :Episodic nodes (19)  — episode memories
  :Entity nodes (27)    — extracted entities
  :Community nodes      — entity clusters
  :Saga nodes           — episode groups
```

## Key Fixes Applied (Phase 8C)

1. `small_model=phi3:mini` in `LLMConfig` — prevents gpt-4.1-nano calls for internal lightweight ops
2. `_make_null_cross_encoder()` — bypasses `OpenAIRerankerClient` (requires no `OPENAI_API_KEY`)

## Scripts

- `scripts/ai/load_graphiti_seed_memories.py` — seed episodes `--live`
- `scripts/ai/graphiti_runtime_check.py` — health check

## See Also

- [[15-Graphiti/Graphiti Memory Types|Memory Types]] · [[15-Graphiti/Graphiti Episode Overview|Episodes]]
- [[16-Neo4j/index|Neo4j]] · [[17-Ollama/index|Ollama]]
- [[11-External Tools/Graphiti Plan|Phase 8A Graphiti Plan]] · [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #graphiti #index
