# Shodan API — Technical Reference

Source: https://developer.shodan.io/api
Provider: Shodan | Authority: Tier A
Ingested: 2026-06-13 | Terms: Shodan ToS; API key required; free tier very limited; paid for useful search; no bulk re-distribution.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## What Shodan is

Shodan is an internet-wide port scanner and service banner database. It crawls the internet, connects to ports, collects service banners, and makes this exposure data searchable. Primary use: exposure assessment (what services are reachable), NOT threat/malice assessment.

## Authentication

`key=YOUR_API_KEY` query parameter on all requests. Obtain at account.shodan.io.

## Core Endpoints

| Endpoint | Method | Credits | Purpose |
|---|---|---|---|
| `/shodan/host/{ip}` | GET | 0 | All services on specific IP |
| `/shodan/host/search` | GET | query credits | Search with filters |
| `/shodan/host/count` | GET | 0 | Result count (no data) |
| `/dns/domain/{domain}` | GET | 1 credit | Subdomains + DNS entries |
| `/dns/resolve` | GET | 0 | Hostname → IP |
| `/dns/reverse` | GET | 0 | IP → hostnames |
| `/shodan/scan` | POST | 1/IP | On-demand scan |
| `/account/profile` | GET | 0 | Account info + credits |
| `/api-info` | GET | 0 | API plan + remaining credits |

## Response Fields (`/shodan/host/{ip}`)

### Host-level:
| Field | Description |
|---|---|
| `ip_str` | IP address string |
| `ports` | Array of open port numbers |
| `hostnames` | Associated domain names |
| `org` | Organization name |
| `country_code` | ISO country code |
| `asn` | Autonomous System Number (e.g. "AS13335") |
| `tags` | Array of classification tags |
| `domains` | Associated domains |

### Per-service (within `data` array):
| Field | Description |
|---|---|
| `port` | Port number |
| `transport` | `tcp` or `udp` |
| `product` | Software name (e.g. "nginx", "OpenSSH") |
| `version` | Software version string |
| `cpe` | CPE identifiers for vulnerability cross-reference |
| `timestamp` | When Shodan last observed this banner |
| `http.title` | HTTP page title |
| `http.server` | HTTP Server header value |

## Tags (Classification)

Shodan tags on hosts:
- `compromised`: host identified as compromised
- `malware`: malware-related services detected
- `scanner`: IP used for internet scanning (Shodan's own scanners, others)
- `ics`: industrial control systems
- `self-signed`: self-signed TLS certificate
- `vpn`: VPN endpoint
- `tor`: Tor exit node

## Credit System

- Query credits: consumed by paginated search (`/shodan/host/search` page > 1)
- Scan credits: 1 per IP for on-demand scanning
- `/shodan/host/{ip}` direct lookup = free (no credits)
- `/shodan/host/count` = free
- Enterprise: bulk data API for raw daily datasets

## Search Filter Syntax

`filter:value` format in search query:
- `product:nginx country:DE` — nginx servers in Germany
- `port:22` — SSH servers
- `tag:ics` — industrial control systems
- `org:"Amazon"` — Amazon-owned IPs
- `vuln:CVE-2021-44228` — Log4Shell vulnerable hosts (enterprise)
- `hostname:.example.com` — hosts associated with domain

## Exposure vs. Maliciousness Distinction

**Critical for WADE**: Shodan indicates **exposure**, not **malice**:
- An open port = exposed, not necessarily vulnerable
- Software version in banner = identifiable, not confirmed exploited
- `tags: compromised` = Shodan believes host is compromised (based on observed behavior)
- `tags: malware` = malware-related service observed on port

Shodan data on a customer-scan target IP tells you: what's visible from the internet.
Shodan data does NOT tell you: whether that IP is actively attacking the customer.

## Alert / Monitoring Triggers

`alert triggers`: `any`, `industrial_control_system`, `malware`, `new_service`, `uncommon`, `vulnerable`
Useful for monitoring customer IP ranges for new exposed services.

## False Positive Risk

- Old banner data: Shodan doesn't crawl every IP daily — `timestamp` may be weeks/months old; service may have changed
- Port open ≠ vulnerable: banner version alone insufficient for confirmed vulnerability
- Tags like `scanner` on a Shodan-monitored IP don't mean the IP is malicious

## License / Terms

- Shodan ToS: account.shodan.io/terms
- Free tier: limited searches/month
- Paid tiers: more queries and credits
- No bulk re-distribution of raw Shodan data

## WebHound Scanner Relevance

Use case: for a customer site's IP, check Shodan for:
1. What other services/ports are exposed (unexpected open ports = finding)
2. Software versions for known-vulnerable software detection
3. `tags: compromised` or `tags: malware` = high-priority finding

Gap: no Shodan client in `scanner/webhound/threat_intel/`.
