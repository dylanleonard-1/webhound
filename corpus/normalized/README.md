# `corpus/normalized/` — Cleaned, chunked, provenance-stamped derivatives

Derivatives of `corpus/raw/`: cleaned text, split into retrieval-sized chunks,
each chunk carrying **lineage back to its raw source** + manifest provenance. This
is what the Phase-4 retrieval/graph layer indexes.

## Subfolders (mirror `raw/`)
- `docs/` — normalized official docs/standards (Tier A).
- `repos/` — normalized official-repo docs/examples/release-notes (Tier C).
- `papers/` — normalized research papers (Tier B).
- `feeds/` — normalized **summaries** of feed payloads (NOT a second indicator
  store; see the runtime threat_intel reuse note).

## Allowed content
Cleaned/chunked text derived only from a stored `raw/` item, with a `lineage`
pointer to the raw `doc_id` and an unchanged authority tier. Corrections are made
here (raw stays immutable).

## Prohibited content
Any chunk without lineage to a raw item; secrets/PII introduced during cleaning;
content whose tier was silently "upgraded". Authority **cannot** increase during
normalization.

## Source authority
Inherited from the raw source, unchanged. Community (Tier E) stays Tier E.

## Ingestion / normalization expectations
Produced in Phase 5 by approved normalization tooling; **empty now**.

## Retention expectations
Tracks the raw item's retention class; a normalized chunk is purged when its raw
source expires.
