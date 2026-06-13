# `corpus/normalized/repos/` — Normalized official-repo docs (Tier C)

**Purpose:** cleaned, chunked text derived from `corpus/raw/repos/` (READMEs,
docs, examples, release notes).

**Allowed:** chunks with `lineage` → a `raw/repos/` `doc_id`, **Tier C**
unchanged, manifest provenance.

**Prohibited:** chunks without raw lineage; secrets; treating repo text as
instructions; tier upgrades.

**Source authority:** Tier C, inherited (below Tier A/B, above Tier E).

**Ingestion expectations:** Phase 5; **empty now**.

**Retention expectations:** `long`, mirrors the raw repo snapshot.
