# Censys Search API — Authored Reference

Source: https://docs.censys.com/ + https://search.censys.io/api (403 on direct fetch)
Provider: Censys | Authority: Tier B (authored synthesis)
Ingested: 2026-06-13 | Terms: Censys ToS; free researcher tier available; commercial use requires paid plan.
Note: AUTHORED synthesis note based on Censys documentation knowledge — not a live-fetched verbatim mirror.
live_fetch_status: blocked (403 on api endpoint, session limit on docs.censys.com)

## What Censys is

Censys continuously scans the entire public IPv4 address space and collects service banners, TLS certificates, and HTTP responses. Similar to Shodan but with a stronger focus on TLS/certificate analysis and structured data. Primary use: exposure assessment and certificate transparency research.

## Authentication

HTTP Basic Auth: API ID as username, API secret as password. Obtain at search.censys.io/account. Free researcher accounts available with monthly quota.

## Core Endpoints (Search 2.0, base: https://search.censys.io/api/v2/)

| Endpoint | Purpose |
|---|---|
| `GET /hosts/{ip_address}` | Full host detail for specific IP |
| `POST /hosts/search` | Search hosts with query |
| `GET /hosts/{ip}/history` | Historical service observations |
| `GET /certificates/{fingerprint}` | Certificate detail |
| `POST /certificates/search` | Search certificates |

## Key Response Fields (`/hosts/{ip}`)

### Host-level:
| Field | Description |
|---|---|
| `ip` | IP address |
| `services` | Array of observed services |
| `autonomous_system.asn` | ASN number |
| `autonomous_system.name` | ASN org name |
| `autonomous_system.bgp_prefix` | CIDR block |
| `location.country` | Country name |
| `location.country_code` | ISO code |

### Per-service (within `services`):
| Field | Description |
|---|---|
| `port` | Port number |
| `transport_protocol` | `TCP` or `UDP` |
| `service_name` | Protocol (HTTP, SSH, TLS, etc.) |
| `software` | Array of detected software with `product`, `version` |
| `tls.certificates.leaf` | TLS leaf certificate details |
| `banner` | Raw service banner text |

## Query Syntax (Censys Query Language)

Examples:
- `ip: 1.2.3.4` — specific IP
- `autonomous_system.name: "Cloudflare"` — ASN name
- `services.port: 8080` — port filter
- `services.service_name: HTTP` — protocol filter
- `services.tls.certificates.leaf.subject.common_name: example.com` — cert CN

## Certificate Focus (Distinctive Censys Feature)

Censys is particularly strong for:
- Finding all IPs hosting a given domain's TLS certificate
- Certificate transparency monitoring
- Subdomain discovery via certificate SANs
- Finding phishing infrastructure using lookalike certificates

## Exposure vs. Maliciousness (Critical Distinction)

Like Shodan, Censys data = **what's observable**, NOT **whether it's malicious**:
- Open ports = exposure, not vulnerability
- Software versions = identifiable, not confirmed exploited
- Censys has no maliciousness classification

To get maliciousness context: cross-reference Censys-found IPs/domains with VirusTotal, URLHaus, AbuseIPDB.

## Rate Limits / Quotas

- Free researcher: limited monthly searches (~250 queries/month)
- Paid plans: higher quotas
- HTTP 429 when exceeded

## False Positive Risk

- Data freshness: Censys crawls periodically — data may be hours to days old
- Port open at crawl time ≠ currently open
- Certificate-to-domain mapping: wildcard certs cover many subdomains — one bad subdomain ≠ whole cert malicious

## License / Terms

- Censys ToS: censys.io/legal/terms
- Free researcher tier for academic/security research
- Commercial use: paid plans required
- No bulk re-distribution of raw Censys data without enterprise agreement

## WebHound Scanner Relevance

Use case: for a scan target, Censys can reveal:
1. Other domains on the same IP (shared hosting context)
2. TLS certificate details (mis-issued certs, recently created certs for phishing)
3. Unexpected open ports (port 3306 MySQL open = exposure finding)
Gap: no Censys client in `scanner/webhound/threat_intel/`.
