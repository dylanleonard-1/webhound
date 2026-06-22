# Brain Dense Retrieval — Build & Verify

Fresh-clone runbook for the code-aware WebHound brain. All local; no cloud APIs.

## Prerequisites
- Python 3.12 + the api dev env (`.venv-api`).
- For dense/hybrid only: `sentence-transformers` (pulls a ~90 MB local model on first run).
  ```
  .venv-api/Scripts/python -m pip install sentence-transformers
  ```
  Lexical retrieval needs none of this.

## 1. Build the canonical chunk set (lexical works immediately)
```
.venv-api/Scripts/python scripts/ai/build_canonical_brain_index.py
```
Writes the committed manifests + the regenerated `corpus/index/canonical_chunks.jsonl`
(code + docs, ~6,862 chunks). Deterministic; no network.

## 2. Build dense embeddings (enables dense + hybrid)
```
.venv-api/Scripts/python scripts/ai/build_dense_brain_embeddings.py
```
- Smoke/CI: `--limit 25`  ·  Plan only: `--dry-run`  ·  Custom out: `--output-dir DIR`
- Writes `corpus/index/dense/chunk_embeddings.npy` (gitignored) + a small
  `embeddings_manifest.json`. If `sentence-transformers` is missing it exits 3 with
  an install hint (never fakes vectors).

## 3. Traceability check
```
.venv-api/Scripts/python scripts/ai/check_brain_traceability.py --mode hybrid
```
- `--mode lexical|dense|hybrid` · `--require-dense` (fail if no vectors) · `--json`
- Expected (hybrid, full build): **9 PASS / 1 PARTIAL / 0 FAIL** across the 10 concepts.

## Expected outputs
| Command | Output |
|---------|--------|
| canonical build | `brain_sources_manifest.json`, `code_chunks_manifest.jsonl`, `retrieval_config.json` (committed) + `canonical_chunks.jsonl` (gitignored) |
| dense build | `dense/chunk_embeddings.npy` + `dense/embeddings_manifest.json` (gitignored) |
| traceability `--mode hybrid` | per-concept PASS/PARTIAL/FAIL + totals |

## Fallback behavior (retrieval_config.json, schema v2)
- dense vectors present → **hybrid** (0.35 lexical + 0.65 dense).
- dense vectors missing → **lexical** with a printed WARNING + rebuild instruction.
- **Never** silently uses stale/mismatched dense artifacts.

## CI dense-quality gate (concept-seeded shard)
CI gates hybrid retrieval *quality* (not just plumbing) on a small concept-seeded
shard — every one of the 10 concept modules plus a bounded ~1,200-chunk sample:
```
python scripts/ai/build_canonical_brain_index.py
python scripts/ai/build_dense_brain_embeddings.py --seed-modules CI --sample 1200 --output-dir corpus/index/_ci_shard
python scripts/ai/check_brain_traceability.py --index-dir corpus/index/_ci_shard --mode hybrid --min-found 8
```
- `--seed-modules CI` = the built-in 10-concept set; writes a self-contained shard
  (chunks + aligned vectors). `--min-found 8` = gate (concept found in top-k; exit 1 if <8).
- Rank-robust: gates on top-k membership, not exact order. Shard vectors are gitignored.

## Delete / regenerate
```
rm -rf corpus/index/canonical_chunks.jsonl corpus/index/dense   # remove artifacts
# then repeat steps 1–2
```

## Troubleshooting
- *"canonical_chunks.jsonl missing"* → run step 1.
- *"sentence-transformers not installed"* (exit 3) → install per Prerequisites.
- Lexical ranks docs over code → expected; use hybrid for code-concept retrieval.
- First dense build slow → one-time model download; subsequent runs are cached/offline.
