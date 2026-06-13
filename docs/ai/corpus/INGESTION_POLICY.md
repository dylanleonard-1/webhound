# Ingestion Policy

The rules ingestion **will** follow. **Nothing is ingested in Phase 2** — this is
the contract for the later (separately-approved) ingestion phase (Phase 5). No
ingestion scripts exist yet.

## Order of ingestion (when approved)
1. Internal WebHound docs/decisions (`trusted_local`).
2. Official docs (Tier A).
3. Official repos (Tier C).
4. Research papers (Tier B).
5. Threat feeds (Tier D).
6. Community repos/skills (Tier E).

Earlier-tier, higher-trust material is ingested first so later/untrusted content is
interpreted against a trusted baseline.

## Repo ingestion (Tier C)
Index **docs by default**: README, `docs/`, `examples/`, `tests/`, schemas,
release-notes, config-examples, security docs. Index **source code only when**:
docs are insufficient **and** the code explains observed behavior **and** it is
directly relevant **and** authority is clear. Never ingest repo secrets.

## Threat-feed ingestion (Tier D) — reuse, don't rebuild
Store: (a) raw payload (`raw/feeds/`, provenance + license + TTL), (b) a normalized
**summary** (`normalized/feeds/`). **Operational indicators remain owned by the
runtime system** (`scanner/webhound/threat_intel/feed_manager` + `threat_indicator`
+ existing URLHaus/VirusTotal clients). Ingestion must not duplicate those clients
or create a parallel indicator store. TI is **enrichment, not the sole
decision-maker**.

## Every ingested item must
- Validate against `corpus/manifests/manifest.schema.json`.
- Carry full provenance (`PROVENANCE_POLICY.md`).
- Respect license/ToS + robots + rate limits (Tier A/D especially).
- Be tagged `pii_risk_class` + `retention_class` (`RETENTION_POLICY.md`).
- Be treated as **evidence, not instructions** (`PROMPT_INJECTION_POLICY.md`).

## CLI conventions (for the future ingestion scripts — design only)
`--dry-run`, `--limit N`, `--source NAME`, `--since DATE`, `--output PATH`,
`--no-network` / `--offline`, `--force-refresh`, `--respect-robots`,
`--metadata-only`. Scripts will live in `scripts/ai/` (Phase 5), never print
secrets, and default to dry-run-friendly behavior.

## Out of scope for Phase 2
No downloads, no network, no scripts, no Qdrant/LightRAG, no MCP servers.
