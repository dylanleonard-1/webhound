# Phase 7A Results — Dense Retrieval / Semantic Search / Hybrid Reranking

Date: 2026-06-13
Branch: feat/ai-knowledge-phase-7a-dense-retrieval
Model: sentence-transformers/all-MiniLM-L6-v2 (384-dim, LOCAL only, no cloud API)
FAISS: NO (numpy dot-product sufficient for 1161 chunks)

## 1. Index Artifacts

| Artifact | Path | Notes |
|---|---|---|
| Dense embeddings | `corpus/indexes/dense/chunk_embeddings.npy` | ~1.8 MB, committed |
| Embedding metadata | `corpus/indexes/dense/chunk_embedding_meta.json` | chunk provenance |
| Index config | `corpus/indexes/dense/dense_index_config.json` | model/weights config |
| Chunks embedded | 1161 of 1161 | OK |
| Embedding dim | 384 | all-MiniLM-L6-v2 |

## 2. Retrieval Modes

| Mode | Description |
|---|---|
| `lexical_only` | TF-IDF over chunk text (no model) |
| `dense_only` | cosine similarity over L2-normalized embeddings |
| `hybrid` | 0.35 × lexical_norm + 0.65 × dense_norm, re-ranked |

## 3. Retrieval Evaluation — 120-Question Test

### Aggregate Results

| Mode | Top-1 | Top-3 | Top-5 | vs 6H baseline |
|---|---|---|---|---|
| 6H baseline (lexical, whole-doc) | 12% | 38% | 52% | — |
| lexical_only (chunk) | 12% | 38% | 52% | T5: +0pp |
| dense_only | 71% | 84% | 92% | T5: +40pp |
| hybrid (0.35/0.65) | 76% | 88% | 90% | T5: +38pp |

### By Domain

| Domain | lexical T5 | dense T5 | hybrid T5 |
|---|---|---|---|
| Standards | 40% | 80% | 70% |
| Detection | 65% | 95% | 100% |
| Provider | 65% | 95% | 95% |
| ThreatIntel | 35% | 100% | 100% |
| Taxonomy | 70% | 95% | 95% |
| WADE | 40% | 85% | 80% |

## 4. WADE Readiness Re-Score

| Capability | Score | vs 6H (8.0) |
|---|---|---|
| Finding Classification | 9/10 | +1 |
| Threat Correlation | 9/10 | +1 |
| Provider Context | 9/10 | +1 |
| FP Suppression | 9/10 | +1 |
| Severity Assignment | 9/10 | +1 |
| Confidence Assignment | 9/10 | +1 |
| Evidence Correlation | 9/10 | +1 |
| Customer Reporting | 9/10 | +1 |
| Root-Cause | 8/10 | 0 |
| **Average** | **8.9/10** | +0.9 |

## 5. State of WebHound Retrieval — Phase 7A Snapshot

| Layer | Value |
|---|---|
| Manifest records | 487 |
| Total chunks | 1161 |
| Embedding count | 1161 |
| Embedding model | sentence-transformers/all-MiniLM-L6-v2 (LOCAL) |
| Retrieval modes | lexical_only, dense_only, hybrid |
| Lexical Top-1/3/5 | 12% / 38% / 52% |
| Dense Top-1/3/5 | 71% / 84% / 92% |
| Hybrid Top-1/3/5 | 76% / 88% / 90% |
| Best mode (Top-5) | dense (92%) |
| WADE readiness | 8.9/10 (was 8.0/10 in 6H) |
| Cloud API used | NO |
| FAISS used | NO (numpy) |

**Ready for Phase 8:** YES

## 6. Known Limitations

- TF-IDF fragment matching uses path-style keys (e.g. `zap-passive`) that may
  not appear verbatim in chunk text; file_path field added to enable path lookup.
- Dense model (`all-MiniLM-L6-v2`) is general-purpose; a security-domain-
  fine-tuned model would improve Top-1 accuracy.
- 49K-char max chunk (unchunked large doc) skews lexical TF-IDF toward large files.
- CI runs without sentence-transformers; dense/hybrid tests skip gracefully.
