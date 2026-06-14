# AlienVault OTX (LevelBlue Open Threat Exchange) — Authored Reference

Source: https://otx.alienvault.com/ (site is JS-heavy SPA; could not fetch machine-readable content)
Provider: LevelBlue (formerly AlienVault, now part of AT&T/LevelBlue) | Authority: Tier B (authored synthesis)
Ingested: 2026-06-13 | Terms: OTX ToS at otx.alienvault.com; free for community use; API key required.
Note: AUTHORED synthesis note based on OTX documentation knowledge — not a live-fetched verbatim mirror.
live_fetch_status: blocked (JS-heavy SPA, 404 on /api/v1/docs)

## What OTX is

Open Threat Exchange (OTX) is a community-driven threat intelligence sharing platform. Users ("pulse authors") publish "pulses" — collections of IOCs grouped around a threat campaign, malware family, or attack pattern. Anyone with a free account can read and contribute.

## Authentication

`OTX-APIKey: YOUR_KEY` HTTP header. Free registration at otx.alienvault.com.

## Core API Endpoints (v1)

Base: `https://otx.alienvault.com/api/v1/`

| Endpoint | Purpose |
|---|---|
| `/indicators/domain/{domain}/general` | Domain reputation + pulse count |
| `/indicators/domain/{domain}/url_list` | URLs seen on domain |
| `/indicators/IPv4/{ip}/general` | IP reputation |
| `/indicators/IPv4/{ip}/malware` | Malware samples from IP |
| `/indicators/url/general?url={url}` | URL reputation |
| `/indicators/file/{hash}/general` | File hash reputation |
| `/pulses/subscribed` | Pulses from subscribed authors |
| `/pulses/search?q={term}` | Search pulses |
| `/pulses/{pulse_id}` | Single pulse detail |

## Indicator Types (OTX attribute types)

- `domain` — domain name
- `hostname` — FQDN
- `IPv4`, `IPv6` — IP addresses
- `URL` — full URL
- `FileHash-MD5`, `FileHash-SHA1`, `FileHash-SHA256` — file hashes
- `CVE` — CVE identifiers
- `email` — email address
- `CIDR` — network block
- `mutex` — mutex names (malware behavioral indicator)
- `URI` — URI path

## Pulse Structure

A pulse groups IOCs around a threat:
- `name`: pulse title
- `description`: threat context
- `author_name`: submitting OTX user
- `tags`: classification tags (malware family, campaign, TTPs)
- `references`: external sources (blogs, reports, CVEs)
- `indicators`: array of IOC objects with `type`, `indicator`, `description`, `created`, `expiration`
- `TLP`: Traffic Light Protocol marking (WHITE/GREEN/AMBER/RED)
- `modified`: last update time

## Confidence Semantics

OTX has no formal confidence score per indicator. Confidence factors to assess manually:
- Author reputation (verified author vs anonymous)
- Number of pulses referencing the same IOC
- Presence of `expiration` date (expired = lower confidence)
- TLP level (AMBER/RED = more vetted)
- Reference quality (links to primary sources = more credible)

## False Positive Risk

- Community-contributed: anyone can publish; quality varies widely
- No mandatory verification before publication
- IOCs may be: copy-pasted from unverified sources, overly broad (entire /24 CIDR), stale (no expiration management)
- Domain/IP IOCs may match shared hosting
- Cross-reference with VirusTotal/URLHaus before acting on OTX-only matches

## Age / Freshness

`indicators[].created` and `indicators[].expiration` fields. Treat OTX IOCs older than 90 days with reduced confidence unless corroborated by other sources.

## License / Terms

- OTX ToS: otx.alienvault.com/terms
- Free community use; no bulk re-distribution
- Attribution: cite "AlienVault OTX / LevelBlue OTX"

## WebHound Scanner Relevance

Gap: no OTX client in `scanner/webhound/threat_intel/`.
Use case: pulse-based context for newly discovered IOCs (malware campaign context, MITRE ATT&CK TTPs, threat actor attribution).
Caution: do NOT auto-report a domain as malicious based on a single low-author-reputation OTX pulse — corroborate with URLHaus, VT, or GSB first.
