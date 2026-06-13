# Threat-Intel Subsystem — Current State (pointer-first)

Curated summary of what WebHound's threat-intel subsystem has **today** (verified in
the Phase-0 gap report). Ground truth = `scanner/webhound/threat_intel/`.

## Architecture
Offline-by-design: feeds are **ingested** (pre-fetched payloads from
`WEBHOUND_THREAT_FEED_DIR`) and held by `feed_manager`, which answers "is this
host/URL/script-hash a known indicator?". Live provider lookups are operator-gated
(`enrichment_service`). Wired into scans via `core/orchestrator.py` +
`engines/threat_intel/external_domains.py`. Indicators persist in the
`threat_indicator` model (migration `0024_threat_intel`).

## Feed status (verified)
| Feed | State | Notes |
|------|-------|-------|
| **URLHaus** | **existing** | live client `urlhaus_client.py` + `normalize_urlhaus`; `ENABLE_URLHAUS`, optional `URLHAUS_API_KEY` |
| **VirusTotal** | **existing** | live client `virustotal_client.py` + `normalize_virustotal`; `VIRUSTOTAL_API_KEY` |
| **OpenPhish** | **partial** | `normalize_openphish` exists; **no fetch client** |
| **AbuseIPDB** | **partial** | `normalize_abuseipdb` exists; **no fetch client**; needs `ABUSEIPDB_API_KEY` |
| **PhishTank** | **partial** | `normalize_phishtank` exists; client status unverified |
| **ThreatFox** | **missing** | no client, no normalizer |
| **AlienVault OTX** | **missing** | no client, no normalizer |

## Supporting modules
`feed_normalizer`, `enrichment_service`, `domain_reputation`, `script_reputation`,
`reputation_cache`, `supply_chain`, `brand_impersonation`, `threat_correlation`,
`coverage`.

## Rules
- **TI is enrichment, not the sole decision-maker** — a finding is not created or
  suppressed on a single feed signal alone.
- **Reuse, don't rebuild.** Future Phase-5 ingestion adds **net-new** feeds
  (ThreatFox, OTX) and fetch clients for the partial ones (OpenPhish, AbuseIPDB),
  reusing `feed_normalizer` + `feed_manager` + `threat_indicator`. It must NOT
  duplicate the existing URLHaus/VirusTotal clients or create a parallel store.

## Phase 3 scope
**Documentation only.** No threat-intel code or behavior changed.

**Review status:** curated (seeded Phase 3). **Authority:** trusted_local +
Tier-D feeds (enrichment).
