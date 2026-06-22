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
- `tests/ai/test_dense_retrieval_reliability.py`: **8 passed** locally (the dense-embed test self-skips where `sentence-transformers` is absent, e.g. minimal CI).
- Full `tests/ai` validated in CI-equivalent state (see VALIDATION in the PR).

## STATE OF THE DENSE BRAIN
1. **Rebuild from a fresh clone?** Yes — `build_canonical_brain_index.py` → `build_dense_brain_embeddings.py` → `check_brain_traceability.py --mode hybrid`.
2. **Cloud APIs?** No — fully local sentence-transformers; offline after the one-time model download.
3. **When embeddings are missing?** Lexical with a printed WARNING + rebuild command; `--require-dense` hard-fails (exit 2). Never silent, never stale.
4. **Does hybrid improve traceability?** Strongly — 1/7/2 (lexical) → **9/1/0** (hybrid).
5. **Which concepts still fail?** None FAIL under hybrid; `tls_checker` is PARTIAL (TLS reference docs outrank the engine module).
6. **Next single action:** add a CI job (or extend `api-tests`) that installs `sentence-transformers`, builds `--limit`-bounded dense vectors, and asserts hybrid traceability ≥ 8/10 — so dense quality is gated, not just the contract.
