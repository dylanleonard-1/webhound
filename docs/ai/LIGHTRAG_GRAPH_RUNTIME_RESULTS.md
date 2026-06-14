<!-- WEBHOUND-GENERATED -->
# LightRAG Graph Runtime Results — Phase 8C-INFRA

**Date:** 2026-06-14T08:22:45.094765Z
**Status:** LIVE_FULL
**Version:** lightrag-hku v1.5.2

## Layer Status

| Layer | Status | Detail |
|-------|--------|--------|
| lightrag-hku | INSTALLED v1.5.2 | pip install lightrag-hku |
| Vector storage | LIVE | 11 files in lightrag_storage/ |
| Vector DB files | LIVE | vdb_chunks.json, vdb_entities.json, vdb_relationships.json |
| Embedding model | LIVE | all-MiniLM-L6-v2 dim=384 |
| Graph entities | LIVE | 19 entities, 1 relationships |
| Ollama LLM | LIVE | models: nomic-embed-text:latest, phi3:mini |

## Layer Summary

- **Vector retrieval**: LIVE — 30 chunks indexed, naive mode queries work
- **Graph extraction**: LIVE
- **Entity note**: Graph entities extracted (LLM was used during indexing)

## Activating Full Graph Mode

Full graph extraction requires a local LLM (Ollama) to parse entity/relationship JSON
during indexing. The current stub returns `{"entities":[], "relationships":[]}` —
only vector retrieval works.

### Step-by-step

```bash
# 1. Start Ollama
docker compose -f docker-compose.ai-brain.yml up -d ollama
# Or install natively: see docs/ai/OLLAMA_SETUP.md

# 2. Pull models
docker exec webhound-ollama-dev ollama pull llama3.2
docker exec webhound-ollama-dev ollama pull nomic-embed-text

# 3. Clear stub-indexed storage
rm -rf lightrag_storage/

# 4. Re-index with Ollama (replace stub LLM in build_lightrag_index.py)
# See the code snippet in docs/ai/LIGHTRAG_GRAPH_RUNTIME_RESULTS.md
.venv-api/Scripts/python scripts/ai/build_lightrag_index.py
```

### LightRAG + Ollama Integration

```python
from lightrag.llm.ollama import ollama_model_complete, ollama_embed
from lightrag import LightRAG
from lightrag.utils import EmbeddingFunc

rag = LightRAG(
    working_dir="lightrag_storage",
    llm_model_func=lambda prompt, **kw: ollama_model_complete(
        prompt, model="llama3.2", host="http://localhost:11434", **kw
    ),
    embedding_func=EmbeddingFunc(
        embedding_dim=768,
        max_token_size=256,
        func=lambda texts: ollama_embed(
            texts, embed_model="nomic-embed-text", host="http://localhost:11434"
        ),
    ),
)
```

## See Also

- [[OLLAMA_SETUP]] — install Ollama and pull models
- [[build_lightrag_index]] — index builder
- [[LIGHTRAG_BENCHMARK]] — performance comparison
