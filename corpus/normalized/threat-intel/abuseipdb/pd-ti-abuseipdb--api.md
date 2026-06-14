# AbuseIPDB API v2 — Technical Reference

Source: https://docs.abuseipdb.com/
Provider: AbuseIPDB | Authority: Tier A
Ingested: 2026-06-13 | Terms: Per abuseipdb.com ToS; free tier available; API key required.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## What AbuseIPDB is

Community-reported IP address abuse database. Users report abusive IPs (spam, DDoS, hacking attempts, scanning). Aggregates reports into a confidence score. Primary indicator type: IPv4 and IPv6 addresses.

## Authentication

`Key: YOUR_API_KEY` HTTP header (preferred over query parameter to avoid logging). HTTPS mandatory. Obtain at abuseipdb.com/account/api. No CORS (client-side use not supported by design).

## Core Endpoints (base: https://api.abuseipdb.com/api/v2/)

| Endpoint | Method | Purpose |
|---|---|---|
| `/check` | GET | Query single IP abuse status |
| `/reports` | GET | Paginated report history for IP |
| `/blacklist` | GET | Most-reported IPs list |
| `/report` | POST | Submit abuse report |
| `/check-block` | GET | Analyze CIDR subnet |
| `/bulk-report` | POST | Submit CSV of IPs |
| `/clear-address` | DELETE | Remove own reports |

## Key Response Fields (`/check`)

| Field | Type | Description |
|---|---|---|
| `abuseConfidenceScore` | 0–100 | Calculated abuse likelihood (non-binary) |
| `totalReports` | int | Count of reports in timeframe |
| `lastReportedAt` | ISO 8601 | Most recent report timestamp |
| `usageType` | string | e.g. "Data Center/Web Hosting/Transit" |
| `isp` | string | Internet service provider |
| `countryCode` | string | ISO 3166 alpha-2 |
| `isWhitelisted` | bool/null | Whitelist status |
| `numDistinctUsers` | int | Number of unique reporters |

## Confidence Score Semantics

Non-binary 0–100 score. Not a hard threshold — use as:
- 0–24: unlikely abusive (hard minimum prevents isolated reports from scoring below 25 on network blocks)
- 25–74: suspicious — worth review
- 75–100: recommended range for denial-of-service decisions

Documentation note: *"Our whitelists give the benefit of the doubt to many IPs, so it generally should not be used as a basis for action."*

## Rate Limits by Tier

| Endpoint | Standard | Webmaster | Supporter | Basic | Premium |
|---|---|---|---|---|---|
| `/check` | 1,000/day | 3,000 | 5,000 | 10,000 | 50,000 |
| `/blacklist` | 5/day | 10 | 20 | 100 | 500 |

HTTP 429 returned when exceeded; includes `Retry-After` header.

## False Positive Risk (Critical for WADE)

- **Shared hosting**: legitimate sites on shared IPs receive reports for other tenants' abuse — high FP risk
- **NAT**: corporate/ISP NAT means one reported IP = many users
- **VPN/Tor exit nodes**: noisy by nature — high scores don't indicate customer site maliciousness
- **Cloud/datacenter ranges**: scanners, crawlers, security researchers use cloud IPs — reports accumulate
- **Whitelist logic**: "non-binary" — high-confidence-benign IPs can still score above 0
- Test IP `127.0.0.2` simulates 15-minute rate limiting for testing
- The `numDistinctUsers` field is a FP signal: 1 reporter = much weaker signal than 50 reporters

## Report Categories

Up to 30 categories (integer IDs). Examples: port scan, SSH brute force, web app attack, email spam, DoS. Submitted as comma-separated values.

## PII Warning

Reports may contain PII in comment field. AbuseIPDB explicitly warns: *"STRIP ANY PERSONALLY IDENTIFIABLE INFORMATION (PII); WE ARE NOT RESPONSIBLE FOR PII YOU REVEAL."*

## Geolocation Data Source

IP details sourced from IPinfo.io — third-party, not AbuseIPDB's own database.

## License / Terms

- abuseipdb.com ToS applies
- API key required; no bulk re-distribution of raw data
- Attribution required for public use

## WebHound Scanner Relevance

Existing normalizer: `scanner/webhound/threat_intel/` has AbuseIPDB normalizer but no API client.
WADE caution: do NOT use raw `abuseConfidenceScore` alone to mark customer site "critical". An IP with score 80 on a shared hosting range may simply be a noisy neighbor. Required: cross-reference with `usageType`, `numDistinctUsers`, `isWhitelisted`. If `usageType` = "Data Center" and score < 50, likely false positive.
