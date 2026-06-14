# MISP Threat Intelligence Platform — Authored Reference

Source: https://www.misp-project.org/documentation/ (limited content returned; MISP OpenAPI at misp-project.org/openapi/)
Provider: MISP Project (open source, community-maintained) | Authority: Tier B (authored synthesis + partial live content)
Ingested: 2026-06-13 | Terms: MISP is open-source (AGPL); individual MISP instance data governed by sharing community policies (TLP, PAP).
Note: AUTHORED synthesis note — MISP project docs page returned limited content.
live_fetch_status: partial (MISP project docs page fetched but had minimal extractable technical content)

## What MISP is

MISP (Malware Information Sharing Platform) is an open-source threat intelligence sharing platform. Organizations deploy their own MISP instances and share events/attributes with trusted communities (ISACs, sector-specific groups, government CERTs). Not a single-provider API — a federated platform.

## Core Data Model

### Event
Top-level container for a threat intelligence report:
- `uuid` — globally unique event ID
- `info` — event title/description
- `date` — event date
- `threat_level_id` — 1 (High), 2 (Medium), 3 (Low), 4 (Undefined)
- `analysis` — 0 (Initial), 1 (Ongoing), 2 (Completed)
- `distribution` — sharing scope
- `Attribute` — array of IOCs

### Attribute (IOC)
Per-indicator entry:
- `type` — attribute type (see below)
- `value` — the indicator value
- `to_ids` — boolean: should this indicator be used for IDS/blocking rules?
- `comment` — contextual note
- `first_seen`, `last_seen` — indicator observation timestamps
- `confidence` — 0–100 (not always populated)
- `category` — IOC category (Network activity, Payload delivery, etc.)

## Attribute Types (Indicator Types)

Network indicators: `domain`, `hostname`, `ip-src`, `ip-dst`, `ip-src|port`, `ip-dst|port`, `url`, `uri`, `domain|ip`

File indicators: `md5`, `sha1`, `sha256`, `sha512`, `filename`, `filename|md5`, `filename|sha256`, `ssdeep`, `tlsh`

Email indicators: `email-src`, `email-dst`, `email-subject`, `email-body`

Behavioral: `mutex`, `regkey`, `regkey|value`, `windows-service-name`

Vulnerability: `vulnerability` (CVE), `weakness`

Attribution: `threat-actor`, `campaign-name`, `malware-type`, `comment`

## Sharing / Distribution Levels

| Level | Description |
|---|---|
| 0 | Organization only — not shared |
| 1 | Community only — shared within local MISP community |
| 2 | Connected communities — shared to directly connected MISP instances |
| 3 | All communities — publicly available |
| 4 | Sharing group — specific pre-defined sharing group |

## TLP Markings

Traffic Light Protocol used alongside distribution:
- `TLP:WHITE` — unrestricted sharing
- `TLP:GREEN` — shareable within community
- `TLP:AMBER` — restricted to need-to-know
- `TLP:RED` — not for sharing

## IDS Flag (`to_ids`)

Critical field: `to_ids: true` means the attribute was specifically tagged as suitable for use in automated blocking/detection (IDS rules, firewall blocks, etc.). `to_ids: false` = informational context only, not for automated action.

**WADE should only act automatically on attributes with `to_ids: true`.**

## MISP API Endpoints (REST)

Base: `https://<your-misp-instance>/` with `Authorization: YOUR_API_KEY` header.

| Endpoint | Purpose |
|---|---|
| `GET /events` | List events |
| `GET /events/{id}` | Event detail |
| `POST /events/restSearch` | Search events/attributes |
| `GET /attributes/restSearch` | Search attributes |
| `GET /feeds` | List public feeds |

## Galaxy / Clusters

MISP Galaxies provide pre-built threat actor, malware, and TTP context:
- `mitre-attack-pattern` — ATT&CK techniques
- `threat-actor` — known APT groups
- `malpedia` — malware families
- `ransomware` — ransomware families

## TAXII / STIX Integration

MISP supports STIX 1.x and STIX 2.0 export for interoperability with TAXII-based threat sharing networks.

## Confidence Semantics

- `threat_level_id`: crude severity (High/Medium/Low/Undefined)
- `analysis`: maturity of the analysis (Initial vs Completed)
- `confidence` attribute field: rarely populated; no standard semantics
- `to_ids` flag: primary automated-action gating

## False Positive Risk

- Federated model: quality varies enormously by contributing organization
- Community-shared events may include unverified IOCs
- Shared infrastructure IOCs (CDN IPs, cloud ranges) common in feeds
- Always check `to_ids` flag, `distribution`, `last_seen` freshness before automated action

## License / Terms

- MISP platform: AGPL-3.0 open source
- Data in MISP instances: governed by sharing community policies — check TLP + PAP
- No single license — depends on which MISP instance/community you connect to

## WebHound Scanner Relevance

Use case: if WebHound has access to a shared MISP instance (e.g., sector ISAC), can pull structured IOCs with context for customer site indicators.
Gap: no MISP client in `scanner/webhound/threat_intel/`.
Key constraint: MISP requires your own instance or invitation to an existing community — not a public SaaS API.
