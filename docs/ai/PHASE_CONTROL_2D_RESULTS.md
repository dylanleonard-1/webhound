# Phase CONTROL-2D — Dense Retrieval & Embedding Reliability: Results

**Branch:** `feat/control-2d-dense-retrieval-reliability` off `main` @ `1cbf206` (2C).
**Scope:** retrieval reliability only. No scanner/WADE/reports/provider-access/billing/auth/`.mcp.json` changes; no installs; no deploys; no large binary/model/DB artifacts committed.

## Before vs after — traceability (10 concepts)

| Mode | Score | Notes |
|------|-------|-------|
| 2C lexical (code-only index) | 6 PASS / 3 PARTIAL / 1 FAIL | prior baseline |
| **2D lexical** (full code+doc index) | **1 PASS / 7 PARTIAL / 2 FAIL** | honest: docs lexically dominate short code queries |
| **2D hybrid** (dense, full build) | **9 PASS / 1 PARTIAL / 0 FAIL** | dense fixes code-concept ranking |

Hybrid wins (vs 2D lexical): `cookie_scanner` ✅, `domain_classifier` ✅, `threat_intel` PARTIAL→**PASS**, `production WADE` PARTIAL→**PASS**, `scanner orchestrator` FAIL→**PASS**, `verification flow` ✅, `API authentication` ✅, `report rendering` FAIL→**PASS**. Only `tls_checker` remains PARTIAL (a Nuclei TLS doc outranks `tls_checker.py`, which is still in-results).

## Dense build status
- `scripts/ai/build_dense_brain_embeddings.py`: builds **6,862 × 384** local MiniLM vectors; `--dry-run`, `--limit`, `--output-dir` all work; fails with install hint (exit 3) if `sentence-transformers` absent (no fabricated vectors). sentence-transformers 5.5.1 present locally → real hybrid score reported above.

## Hybrid retrieval status
Default = hybrid when dense vectors exist, else lexical **with a warning + rebuild
instruction** (never silent stale dense). `check_brain_traceability.py` gained
`--mode lexical|dense|hybrid`, `--require-dense` (exit 2 if no vectors), `--json`.

## Artifacts
- **Committed:** build scripts, mode-aware verifier, `retrieval_config.json` (v2: modes + fallback), 2C manifests, `tests/ai/test_dense_retrieval_reliability.py`, 3 docs, dashboard section.
- **Regenerated (gitignored):** `canonical_chunks.jsonl`, `dense/*.npy`, `dense/*meta*.json`, HF model cache.
- **Smoke shard:** NOT committed — non-deterministic across ST/torch/BLAS versions; regeneration via `--limit 25` is trivial (see policy doc).

## CI status
- `tests/ai/test_dense_retrieval_reliability.py`: **9 passed** locally (build/fallback contract + the dense-embed and quality-gate tests, which self-skip where `sentence-transformers` is absent, e.g. minimal CI).
- Full `tests/ai` (CI-equivalent state): **340 passed, 3 skipped**.

## CI dense-quality gate (added)
A dedicated `dense-quality-gate` job (in `.github/workflows/api-tests.yml`, separate
from the minimal `ai-knowledge` job) now gates dense QUALITY, not just plumbing:
```
pip install sentence-transformers numpy
python scripts/ai/build_canonical_brain_index.py
python scripts/ai/build_dense_brain_embeddings.py --seed-modules CI --sample 1200 --output-dir corpus/index/_ci_shard
python scripts/ai/check_brain_traceability.py --index-dir corpus/index/_ci_shard --mode hybrid --min-found 8
```
- **Threshold:** `--min-found 8` — at least 8/10 concepts must be **found in top-k**
  under hybrid. `found` = PASS or PARTIAL, so the gate is **rank-robust** (immune to
  torch/BLAS ordering jitter), with headroom for `tls_checker` to stay PARTIAL.
- **Bounded-shard design (chosen):** a **concept-seeded** shard — `--seed-modules CI`
  includes EVERY chunk from the 10 concept modules plus a deterministic strided
  sample of the rest (~1,200 chunks total = real distractors). A flat `--limit`
  shard was rejected: it cannot contain all 10 concepts, so a gate over it would be
  meaningless. The shard is self-contained (chunks + aligned vectors in one dir);
  vectors stay gitignored/regenerated.
- **Limitation (honest):** the shard is smaller than the full index, so absolute
  ranks differ — on the bounded shard `tls_checker` scores PASS (fewer Nuclei-doc
  distractors), whereas on the FULL index it is PARTIAL. The gate validates concept
  *findability*, not full-index ranking. Local full-index hybrid remains 9 PASS / 1
  PARTIAL (`tls_checker`) / 0 FAIL.

## STATE OF THE DENSE BRAIN
1. **Rebuild from a fresh clone?** Yes — `build_canonical_brain_index.py` → `build_dense_brain_embeddings.py` → `check_brain_traceability.py --mode hybrid`.
2. **Cloud APIs?** No — fully local sentence-transformers; offline after the one-time model download.
3. **When embeddings are missing?** Lexical with a printed WARNING + rebuild command; `--require-dense` hard-fails (exit 2). Never silent, never stale.
4. **Does hybrid improve traceability?** Strongly — 1/7/2 (lexical) → **9/1/0** (hybrid).
5. **Which concepts still fail?** None FAIL under hybrid; on the full index `tls_checker` is PARTIAL (TLS reference docs outrank the engine module). It still counts as "found" so the ≥8/10 gate has headroom.
6. **Next single action:** (DONE this phase) CI now gates hybrid quality ≥8/10 on a concept-seeded shard. Next: extend the seeded shard / queries so `tls_checker` reaches top-1 on the FULL index (e.g. boost code-symbol weighting for exact module-name queries), closing the last PARTIAL.
