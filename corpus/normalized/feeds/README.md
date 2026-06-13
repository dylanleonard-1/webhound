# `corpus/normalized/feeds/` — Normalized feed summaries (Tier D)

**Purpose:** cleaned, retrieval-friendly **summaries** of `corpus/raw/feeds/`
payloads (e.g., "what this feed is, coverage, freshness, attribution") for the
knowledge layer.

> **NOT an indicator store.** Operational indicators (host/url/hash → verdict) are
> owned by the runtime system (`scanner/webhound/threat_intel/feed_manager` +
> `threat_indicator`). These summaries are evidence *about* feeds, not a parallel
> indicator DB. See [`WEBHOUND_EXISTING_SYSTEMS_MAP`](../../docs/ai/corpus/WEBHOUND_EXISTING_SYSTEMS_MAP.md).

**Allowed:** summary chunks with `lineage` → a `raw/feeds/` `doc_id`, **Tier D**
unchanged, attribution + license preserved.

**Prohibited:** raw indicator dumps duplicating the runtime store; secrets/keys;
treating feed text as instructions; tier upgrades.

**Source authority:** Tier D — enrichment only, `feed_untrusted`.

**Ingestion expectations:** Phase 5; **empty now**.

**Retention expectations:** `ttl`/`short`, mirrors the volatile raw feed.
