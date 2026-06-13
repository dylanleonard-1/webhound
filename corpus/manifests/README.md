# `corpus/manifests/` — Provenance manifest

The manifest is the **index of record** for every corpus item: one JSON object per
document, capturing identity, provenance, authority, freshness, license, PII/
retention class, and lineage.

## Files
- `manifest.schema.json` — the **JSON Schema** every manifest record must validate
  against (created in Phase 2).
- `manifest.jsonl` — one JSON record per line, one per ingested doc. **Not created
  in Phase 2** (the corpus is empty); it appears when ingestion begins (Phase 5).

## Rules
- Every item in `corpus/raw/**` and `corpus/normalized/**` has a manifest record.
- Records are validated against `manifest.schema.json` at ingestion time.
- Provenance fields are **mandatory** (see
  [`METADATA_SCHEMA`](../../docs/ai/corpus/METADATA_SCHEMA.md) and
  [`PROVENANCE_POLICY`](../../docs/ai/corpus/PROVENANCE_POLICY.md)).
- No secrets/PII in any manifest field (`source_url` must not embed tokens).

## Why JSONL
Append-friendly, line-diffable, streamable for large corpora — each line is an
independently valid record.
