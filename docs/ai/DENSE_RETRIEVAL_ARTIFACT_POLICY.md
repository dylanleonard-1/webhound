# Dense Retrieval Artifact Policy — Phase CONTROL-2D

What is committed vs regenerated for dense/hybrid brain retrieval. Goal: a fresh
clone can rebuild dense retrieval from a documented command — never from hidden
local files, never from cloud APIs.

## COMMITTED (small, deterministic, inspectable)
| Artifact | Why |
|----------|-----|
| `scripts/ai/build_dense_brain_embeddings.py` | the build recipe |
| `scripts/ai/check_brain_traceability.py` | mode-aware verifier (`--mode lexical/dense/hybrid`) |
| `corpus/index/retrieval_config.json` | modes + explicit fallback policy (schema v2) |
| `corpus/index/brain_sources_manifest.json`, `code_chunks_manifest.jsonl` | CONTROL-2C deterministic manifests |
| `tests/ai/test_dense_retrieval_reliability.py` | CI contract |
| docs (`BRAIN_DENSE_RETRIEVAL_BUILD.md`, this file, `PHASE_CONTROL_2D_RESULTS.md`) | how/why |

The embeddings **manifest** (`corpus/index/dense/embeddings_manifest.json`) is small
and deterministic (model name, dim, chunk count, vector shape, chunk-ids hash) — it
records *what was built* without the vectors. It is written into the gitignored
`dense/` dir; it is safe to surface but is regenerated with the vectors.

## REGENERATED (build artifacts — gitignored, never committed)
| Artifact | Regenerate with |
|----------|-----------------|
| `corpus/index/canonical_chunks.jsonl` (code+doc chunk text) | `build_canonical_brain_index.py` |
| `corpus/index/dense/chunk_embeddings.npy` (the vectors) | `build_dense_brain_embeddings.py` |
| `corpus/index/dense/chunk_embedding_meta.json` | (with the vectors) |
| HF model cache (~90 MB all-MiniLM-L6-v2) | downloaded once by sentence-transformers |

`corpus/index/.gitignore` enforces: `canonical_chunks.jsonl`, `dense/`, `*.npy`.

## OPTIONAL — tiny smoke-test shard: **NOT committed (decision)**
A 25-vector shard is only ~38 KB, but it is **rejected** because:
- **Non-deterministic across environments** — MiniLM output varies by
  sentence-transformers/torch version, CPU vs GPU, and BLAS backend, so a committed
  shard would drift from a fresh local build and create false test failures.
- **No CI value** — the minimal `ai-knowledge` CI job has no `sentence-transformers`,
  so it cannot consume vectors anyway; the reliability test instead asserts the
  build/fallback *contract* and skips the actual embed when the dep is absent.
- **Regeneration is fast & reliable** — `--limit 25` builds a smoke shard in seconds.

## NEVER committed
Full models, Ollama models, local DB volumes (Neo4j/LightRAG), HF caches, secrets,
`.env`, large binary blobs.

## Reproducibility contract
Fresh clone → `pip install sentence-transformers` → `build_canonical_brain_index.py`
→ `build_dense_brain_embeddings.py` → `check_brain_traceability.py --mode hybrid`.
No cloud APIs. If the model dep is missing, the build **fails with an install hint**
(exit 3) — it never fabricates vectors.
