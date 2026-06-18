# Brain Index Artifact Policy — Phase CONTROL-2C

**Principle:** the canonical WebHound brain must be **regenerable from small deterministic manifests + scripts** — never from committed binary blobs. A fresh clone runs one script and gets the same code-aware brain.

## COMMITTED (small, deterministic, text)

| Artifact | Path | Size | Why committable |
|----------|------|------|-----------------|
| Sources manifest | `corpus/index/brain_sources_manifest.json` | ~240 KB | every brain source w/ include/exclude + content hash; deterministic |
| Code-chunk manifest | `corpus/index/code_chunks_manifest.jsonl` | ~2.1 MB | one line/chunk: id, path, symbol, lines, hashes, category — **metadata only, no embeddings** |
| Retrieval config | `corpus/index/retrieval_config.json` | ~1 KB | canonical paths + rebuild command |
| Builder + checker + tests | `scripts/ai/build_canonical_brain_index.py`, `check_brain_traceability.py`, `tests/ai/test_canonical_brain_index.py` | small | regenerate + verify |
| Docs | `docs/ai/*` | small | this policy + results |

Determinism: manifests are sorted by path/line; hashes derive from file content; **per-file timestamps are intentionally omitted** so re-running yields byte-identical manifests (verified: two consecutive builds produce identical SHA-256).

## REGENERATED — NOT committed (large / binary / local)

| Artifact | Path | Size | Why excluded |
|----------|------|------|--------------|
| Canonical retrieval chunks (with text) | `corpus/index/canonical_chunks.jsonl` | ~8.4 MB | regenerable from manifest + source files |
| Dense embeddings | `corpus/index/dense/chunk_embeddings.npy` (+ meta) | ~11 MB | binary; regenerable via `--embed` |
| Local Neo4j volume | (WSL Docker volume) | large | machine-local DB state |
| LightRAG storage | `lightrag_storage/` | binary | local experiment store |
| Ollama models | (WSL) | GBs | local model cache |
| Caches / venvs / lockfiles | `__pycache__/`, `.venv*`, `node_modules/`, `*.lock` | — | environment-specific |
| Secrets / env | `.env*`, `*.pem`, `*.key` | — | never indexed or committed |

Enforced by `corpus/index/.gitignore` (ignores `canonical_chunks.jsonl`, `dense/`, `*.npy`).

## Rebuild on a fresh clone

```bash
python scripts/ai/build_canonical_brain_index.py          # manifests + canonical_chunks (lexical-ready)
python scripts/ai/build_canonical_brain_index.py --embed  # + local dense embeddings (downloads MiniLM once)
python scripts/ai/check_brain_traceability.py             # verify concepts are discoverable
```

No network/Ollama/Neo4j/Graphiti required for the manifest build or lexical retrieval; `--embed` downloads the local MiniLM model once (then cached).
</content>
