# GreyNoise Community API — Technical Reference

Source: https://docs.greynoise.io/docs/using-the-greynoise-community-api
Provider: GreyNoise Intelligence | Authority: Tier A
Ingested: 2026-06-13 | Terms: GreyNoise ToS; community tier is free with registration; enterprise for higher quotas and full data.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## What GreyNoise is

GreyNoise passively observes internet background noise using a global network of sensors (honeypots). It classifies IPs by whether they are mass-scanning the internet vs. conducting targeted attacks. Key insight: most IPs flagged by WAFs/firewalls are mass-scanners, not targeted attackers.

## Community API Endpoint

```
GET https://api.greynoise.io/v3/community/{ip}
```

Optional auth: `key: YOUR_API_KEY` header. Unauthenticated requests allowed with strict rate limits.

## Response Fields

| Field | Type | Description |
|---|---|---|
| `ip` | string | Queried IPv4 address |
| `noise` | boolean | Observed scanning internet in last 90 days |
| `riot` | boolean | In RIOT (Business Services Intelligence) dataset |
| `classification` | string | `benign`, `malicious`, or `unknown` |
| `name` | string | Organization owning the IP |
| `link` | string | Visualization URL at viz.greynoise.io |
| `last_seen` | date | Date of last observation |
| `message` | string | Status/error description |

## Key Concepts

### Noise
`noise: true` = IP has been observed actively scanning the internet (port scans, exploit probes, credential stuffing at scale) in the past 90 days. This is **background noise** — automated mass activity, NOT targeted attack against specific customers.

### RIOT (Business Services Intelligence)
`riot: true` = IP belongs to a known legitimate business service: CDNs, cloud providers, security scanners (Shodan, Censys), search engine crawlers, payment processors. RIOT IPs should almost never be blocked.

### Classification Values
- `benign` = known legitimate scanner (Shodan research, security vendor, CDN)
- `malicious` = known attacker/botnet/exploit scanner
- `unknown` = observed scanning but intent/classification unclear

## Rate Limits

| Tier | Limit |
|---|---|
| Unauthenticated | 10 IP lookups/day |
| Community (free, registered) | 50 searches/week |
| Enterprise | Custom — much higher |

HTTP 429 when exceeded.

## HTTP Status Codes

| Code | Meaning |
|---|---|
| 200 | Successful (IP found or not found) |
| 400 | Invalid IPv4 format |
| 401 | Invalid/missing API key |
| 404 | IP not in GreyNoise datasets (not observed) |
| 429 | Rate limit exceeded |
| 500 | Server error |

**404 means the IP has never been observed scanning** — not that it's safe.

## Confidence Semantics

- `noise: false, riot: false`: IP not in GreyNoise data (normal internet traffic, no special classification)
- `noise: true, riot: true, classification: benign`: legitimate scanner (e.g. Shodan research bot) — do NOT block
- `noise: true, riot: false, classification: malicious`: active attacker scanner — strong block signal
- `noise: true, riot: false, classification: unknown`: scanning but purpose unclear — suspicious, not definitive

## False Positive Risk for WAD/WADE

**RIOT IPs are extremely high FP risk for blocking:**
- Cloudflare, AWS, Google, Fastly edge IPs are RIOT
- Security scanner IPs (Shodan, Censys, security researchers) are RIOT
- Blocking RIOT IPs would block legitimate business services

**AbuseIPDB vs GreyNoise conflict:**
- AbuseIPDB may report a Shodan scanner IP as "abusive" because some users report it
- GreyNoise correctly classifies Shodan as `riot: true, classification: benign`
- Trust GreyNoise classification for internet-noise IPs over AbuseIPDB for these

## License / Terms

- GreyNoise ToS: greynoise.io/terms
- Community API: free with registration
- Enterprise: paid subscription
- No bulk re-distribution of raw classification data
- Attribution: cite "GreyNoise Intelligence" in reports

## WebHound Scanner Relevance

GreyNoise is critical for distinguishing:
1. Random internet background noise IPs (noisy but not customer-targeted)
2. Legitimate business service IPs (CDNs, cloud) — RIOT flag prevents false positives
3. Actual targeted attacker IPs

WADE should check GreyNoise when an IP appears in AbuseIPDB or VT with abuse scores — if GreyNoise says `riot: true` or `classification: benign`, the AbuseIPDB score is likely due to normal scanner/CDN activity.
Gap: no GreyNoise client in `scanner/webhound/threat_intel/`.
