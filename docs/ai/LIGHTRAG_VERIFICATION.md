# LightRAG Verification — Phase CONTROL-2A

**Type:** VERIFICATION-ONLY (read-only). No installs.
**Method:** static inspection of `lightrag_storage/` + the corpus dense index config. (LightRAG runtime not invoked; Ollama down.)

## Two distinct retrieval systems — don't conflate them

| System | Path | Chunks | Graph | Needs Ollama? | Status |
|--------|------|-------:|-------|---------------|--------|
| **Corpus dense/hybrid index** (the real one) | `corpus/indexes/dense/` + `scripts/ai/hybrid_retrieval.py` | **1,161** | n/a | ❌ (sentence-transformers, local) | ✅ functional, 76% top-1 (PHASE7A) |
| **LightRAG** (experiment) | `lightrag_storage/` | **52** | broken | ✅ (graph extraction) | ⚠️ tiny subset, graph failed |

## LightRAG storage contents (`lightrag_storage/`)

| Artifact | Count / size |
|----------|------|
| `vdb_chunks.json` (vector docs) | **52 chunks** (a small sample, NOT the 1,161 corpus) |
| `vdb_entities.json` | 19 entities |
| `vdb_relationships.json` | **1 relationship** |
| `graph_chunk_entity_relation.graphml` | 25 KB (near-empty graph) |
| `kv_store_llm_response_cache.json` | 1.4 MB (cached LLM calls) |
| Embedding model | all-MiniLM-L6-v2 (384-dim, local) |

→ LightRAG ingested ~52 chunks and extracted only **1 relationship** → its **graph-retrieval layer is non-functional**. Vector layer has 52 docs (a fraction of the corpus).

## Corpus dense index (`dense_index_config.json`) — the working backbone

- `chunk_count: 1161`, model `all-MiniLM-L6-v2`, 384-dim, cosine via numpy dot product, hybrid 0.35 lexical / 0.65 dense, `local_only: true`, `cloud_api_used: false`, `faiss_used: false`. Source attribution + provenance via `corpus/manifests/manifest.jsonl` (487 records).

## Retrieval tests (WADE, TLS, CSP, threat intel, domain classification)

Live LightRAG retrieval not runnable (graph mode needs Ollama, which is down). Concept presence by corpus lines (the real index) / LightRAG sample:

| Concept | Corpus (1161) | LightRAG (52) |
|---------|--------------:|--------------:|
| WADE | 65 | **0** |
| TLS | present | minimal |
| CSP | present | minimal |
| threat_intel | 62 | 1 |
| domain classification | **0** | 0 |

## Verdict

**The corpus hybrid index is a real, working retrieval system (1,161 chunks, 76% top-1, offline).** "LightRAG" as deployed is a **52-chunk experiment with a failed graph layer** and should not be confused with the working retrieval. `domain_classifier` knowledge is absent from both.

**Score (LightRAG): 25% (F)** — token vector store, broken graph. **Corpus hybrid retrieval (separate): ~85% (B+)** — the actual brain retrieval.
</content>
