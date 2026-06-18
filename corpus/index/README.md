# `corpus/index/` — Canonical brain index (CONTROL-2C)

Committed, deterministic manifests that make the WebHound brain **code-aware and
regenerable from a fresh clone** — no large binary blobs.

## Committed (small, deterministic)

- `brain_sources_manifest.json` — every brain source (include/exclude + content hash).
- `code_chunks_manifest.jsonl` — one line per code chunk (id, path, symbol, lines, hashes, category; **no embeddings**).
- `retrieval_config.json` — canonical retrieval config.

## Regenerated — NOT committed (see `.gitignore`)

- `canonical_chunks.jsonl` — retrieval chunks with text (regenerated).
- `dense/` — local embeddings (`--embed`).

## Rebuild

```bash
python scripts/ai/build_canonical_brain_index.py          # manifests + canonical chunks
python scripts/ai/build_canonical_brain_index.py --embed  # + local dense embeddings
python scripts/ai/check_brain_traceability.py             # verify concepts discoverable
```

Policy: `docs/ai/BRAIN_INDEX_ARTIFACT_POLICY.md`. Results: `docs/ai/PHASE_CONTROL_2C_RESULTS.md`.
</content>
