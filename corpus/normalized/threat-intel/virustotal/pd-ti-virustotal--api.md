# VirusTotal API v3 — Technical Reference

Source: https://docs.virustotal.com/reference/overview
Provider: VirusTotal (Google) | Authority: Tier A
Ingested: 2026-06-13 | Terms: VirusTotal ToS; free public API key; premium for higher quotas; no redistribution of raw data without permission.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## What VirusTotal is

Multi-engine malware and URL analysis platform. Aggregates results from 70+ antivirus engines, 10+ sandbox environments, and crowdsourced community detections. Supports files, URLs, domains, and IPs.

## Authentication

`x-apikey: YOUR_API_KEY` HTTP header. API key from personal dashboard at virustotal.com. Free and premium tiers.

## Primary Endpoint Categories

| Resource | Endpoint | Key Identifiers |
|---|---|---|
| Files | `GET /api/v3/files/{id}` | MD5, SHA1, SHA256 |
| URLs | `POST /api/v3/urls` (scan) + `GET /api/v3/urls/{url_id}` | URL base64-encoded |
| Domains | `GET /api/v3/domains/{domain}` | domain string |
| IPs | `GET /api/v3/ip_addresses/{ip}` | IPv4 string |

## Key Response Fields (`data.attributes`)

### For URLs/Domains/IPs:
| Field | Description |
|---|---|
| `last_analysis_stats` | `{malicious: N, suspicious: N, harmless: N, undetected: N, timeout: N}` |
| `last_analysis_results` | Per-engine verdict map |
| `reputation` | Community reputation score (positive = trustworthy, negative = malicious) |
| `total_votes` | `{harmless: N, malicious: N}` community votes |
| `last_analysis_date` | Unix timestamp of last scan |
| `categories` | Map of vendor → category label (e.g. "malware site") |
| `tags` | String array of classification tags |

### For Domains additionally:
| Field | Description |
|---|---|
| `registrar` | Domain registrar |
| `creation_date` | Domain creation Unix timestamp |
| `last_dns_records` | Recent DNS resolution data |
| `whois` | WHOIS data string |

### For IPs additionally:
| Field | Description |
|---|---|
| `asn` | ASN number |
| `as_owner` | ASN owner name |
| `country` | Country code |
| `network` | CIDR block |

## Multi-Engine Confidence Semantics

`last_analysis_stats.malicious` = count of engines flagging as malicious.
Rule of thumb:
- 0 malicious: clean across all engines (but may be newly observed — engines have delays)
- 1–4 malicious: ambiguous — could be FP from one aggressive engine; check which engines
- 5+ malicious: high confidence malicious; cross-reference reputation and community votes
- `reputation` < -50: strong community consensus malicious
- `reputation` > 25: community-trusted

## Rate Limits (Public API)

- 4 requests/minute
- 500 requests/day
- 15,500 requests/month

Premium quotas significantly higher. Rate limit exceeded → HTTP 429.

## Quotas

Public key quotas available at `GET /api/v3/users/{id}/api_usage`.

## Indicator Relationship Mapping

VirusTotal supports relationship traversal:
- Domain → IPs (historical resolutions)
- File → URLs (contacted during execution)
- URL → Files (downloaded files)
- IP → Domains (hosted domains)

Useful for infrastructure pivot analysis.

## False Positive Risk

- One engine flagging ≠ malicious: some AV vendors are aggressive/experimental
- Old `last_analysis_date`: engines change signatures — stale results may not reflect current state
- Domain-level reputation vs URL-level: a domain with one malicious path is NOT fully malicious
- CDN domains: `akamaized.net`, `cloudflare.net`, `googleapis.com` will have malicious detections for hosted content — domain itself is not malicious
- Newly registered domains: high `reputation` risk ≠ confirmed malicious — just suspicious

## License / Terms

- VirusTotal ToS: virustotal.com/terms-of-service/
- Public API: free but limited quotas; no bulk re-distribution of raw scan data
- Premium: higher quotas, retrohunt, livehunt, private scanning
- Attribution: cite "VirusTotal" when reporting VT-sourced findings

## WebHound Scanner Relevance

Existing client: `scanner/webhound/threat_intel/virustotal.py` — VirusTotal client already implemented.
Key use cases:
1. Scan customer site's third-party script URLs against VT domain/URL database
2. Check IP addresses of hosts for `last_analysis_stats.malicious` count
3. Cross-reference with URLHaus/ThreatFox for multi-source confirmation
WADE caution: do NOT report "malicious" from VT alone with < 5 engine detections or old `last_analysis_date`.
