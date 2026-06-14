# ThreatFox API — Technical Reference

Source: https://threatfox.abuse.ch/api/
Provider: abuse.ch / ThreatFox | Authority: Tier A
Ingested: 2026-06-13 | Terms: Free fair use; commercial use requires paid subscription per abuse.ch ToU; attribution required.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## What ThreatFox is

abuse.ch ThreatFox is a platform for sharing indicators of compromise (IOCs) associated with malware. Focuses on confirmed, vetted malware infrastructure — botnet C2, payload delivery, skimming endpoints. Malware labels sourced from Malpedia.

## Authentication

`Auth-Key` header required. Registration at auth.abuse.ch. Same key system as URLHaus.

## API Endpoint

Single endpoint: `POST https://threatfox-api.abuse.ch/api/v1/`
All queries use `query` parameter to select operation type.

## Query Operations

| Query | Parameters | Purpose |
|---|---|---|
| `get_iocs` | `days` (1-7, default 3) | Recent IOCs |
| `ioc` | `id` | Single IOC by ID |
| `search_ioc` | `search_term`, `exact_match` | Search IOCs |
| `search_hash` | `hash` (MD5/SHA256) | Lookup by payload hash |
| `taginfo` | `tag`, `limit` | IOCs by tag (max 1000) |
| `malwareinfo` | `malware`, `limit` | IOCs by malware family (max 1000) |
| `submit_ioc` | `threat_type`, `ioc_type`, `malware`, `iocs` | Submit new IOC |
| `get_label` | `malware`, `platform` | Malware label lookup |
| `malware_list` | — | All known malware families |
| `types` | — | All threat/IOC types |
| `tag_list` | — | All available tags |

## IOC Types Supported

- `url` — full URL
- `domain` — domain name
- `ip:port` — IP address with port (C2 beacons)
- `md5_hash`, `sha256_hash` — file hashes

## Threat Type Taxonomy

- `botnet_cc` — command & control infrastructure
- `payload_delivery` — malware download URL
- `cc_skimming` — card skimming (Magecart-style) endpoints
- (Additional types available via `types` endpoint)

## Confidence Levels

- Range: 0–100 integer
- Default submission value: 50
- Higher values = higher submitter confidence in IOC accuracy
- No automated verification; relies on submitter vetting

## IOC Lifecycle / Age Policy

As of 2025-05-01: IOCs older than 6 months are expired to minimize false positives on reused cloud infrastructure.

## Submission Requirements

- Only confirmed/vetted IOCs accepted
- Repeated low-quality submissions → account ban
- Anonymous submissions supported (optional)

## Export Formats

- JSON export (all IOCs)
- CSV export (all IOCs)
- API limited to 7-day recent IOCs; full exports available separately at threatfox.abuse.ch/export/

## Confidence Semantics

`confidence_level` = submitter's self-reported certainty. Treat as:
- 0–30: low confidence, likely needs corroboration
- 31–70: moderate — likely malicious, verify with additional sources
- 71–100: high confidence — treat as strong indicator

## False Positive Risk

- `ip:port` IOCs on cloud/CDN ranges: high FP risk (shared infrastructure)
- `domain` IOCs on compromised legitimate domains: URL-specific maliciousness may not apply to whole domain
- Expired IOCs (>6 months) may match recycled infrastructure — ThreatFox's own expiry policy helps here

## License / Terms

- https://abuse.ch/terms-of-use/
- Free fair use; commercial use may require subscription
- Malware data sourced from Malpedia (check Malpedia ToU separately)

## WebHound Scanner Relevance

Existing gap: no ThreatFox client in `scanner/webhound/threat_intel/` — URLHaus client exists; ThreatFox uses same auth system.
Key use case: detect C2/skimming infrastructure (`botnet_cc`, `cc_skimming` threat types) in third-party script URLs loaded on customer pages — highest-priority detection scenario.
