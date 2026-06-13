# `corpus/normalized/docs/` — Normalized official docs (Tier A)

**Purpose:** cleaned, chunked text derived from `corpus/raw/docs/`, ready for
retrieval/graph indexing.

**Allowed:** chunks with `lineage` → a `raw/docs/` `doc_id`, inheriting **Tier A**
unchanged, plus manifest provenance.

**Prohibited:** chunks without raw lineage; introduced secrets/PII; tier upgrades.

**Source authority:** Tier A, inherited from raw (unchanged).

**Ingestion expectations:** Phase 5; **empty now**.

**Retention expectations:** mirrors the raw item (`permanent`/`long`).
