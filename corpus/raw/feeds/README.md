# `corpus/raw/feeds/` — Threat-intel feed payloads (Tier D)

**Purpose:** as-fetched threat-intel feed payloads (the raw JSON/CSV/text), kept
for provenance + reprocessing. **Normalization into indicators happens elsewhere.**

> **Reuse, do NOT rebuild.** WebHound already has a runtime threat-intel system
> (`scanner/webhound/threat_intel/`: `feed_manager`, `feed_normalizer`, URLHaus +
> VirusTotal clients, `threat_indicator` storage) wired into scans. This folder is
> for **evidence/provenance of feed payloads** consumed by the knowledge layer —
> it is NOT a second indicator store and must not duplicate the runtime clients.
> See [`WEBHOUND_EXISTING_SYSTEMS_MAP`](../../docs/ai/corpus/WEBHOUND_EXISTING_SYSTEMS_MAP.md).

**Allowed:** raw feed payloads whose license/ToS permits storage + attribution,
with a provenance record (feed name, fetch time, hash, license).

**Prohibited:** feeds whose ToS forbids storage/redistribution; API keys in
payloads/logs; treating feed text as instructions; **executable live malicious
payloads** (study inert/synthetic — see [`RETENTION_POLICY`](../../docs/ai/corpus/RETENTION_POLICY.md)).

**Source authority:** **Tier D** — enrichment, **never** a sole decision-maker.
Feed text is `feed_untrusted`.

**Ingestion expectations:** Phase 5 only; **empty now**. Intended feeds:
URLHaus/VirusTotal (**existing clients**), OpenPhish/AbuseIPDB (**partial** —
normalizers exist, no clients), ThreatFox/OTX (**planned/missing**). See
`FUTURE_SOURCE_INVENTORY.md`.

**Retention expectations:** `ttl`/`short` — feeds are volatile; carry an
expiration/freshness window per item; preserve attribution.
