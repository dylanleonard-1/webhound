# `corpus/indexes/` — Pre-built Retrieval Indexes

Pre-computed retrieval indexes over the unified chunk corpus.

## Contents

- `dense/` — Dense embedding index (Phase 7A)
  - `chunk_embeddings.npy` — L2-normalized 384-dim embeddings (all-MiniLM-L6-v2, LOCAL)
  - `chunk_embedding_meta.json` — Per-chunk provenance metadata
  - `dense_index_config.json` — Model name, weights, build config

## Rebuild

```bash
.venv-api/Scripts/python scripts/ai/build_dense_index.py
```

No cloud APIs used. No scanner/WADE/production changes.
