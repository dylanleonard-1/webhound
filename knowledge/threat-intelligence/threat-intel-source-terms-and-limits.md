# Threat Intelligence Source Terms and Rate Limits

Category: TI knowledge synthesis | WebHound Phase 6E
Updated: 2026-06-13

## Summary Table

| Source | Free Tier | API Key | Rate Limit (Free) | Terms / Attribution | Commercial Use |
|---|---|---|---|---|---|
| URLHaus | Yes | Required | Not published | abuse.ch ToU; attribution required | Paid subscription for commercial |
| ThreatFox | Yes | Required | Not published | abuse.ch ToU; attribution required | Paid subscription for commercial |
| OpenPhish | Community feed only | Org account for paid | Moderate | Terms at openphish.com | Requires active subscription |
| PhishTank | Yes | Yes (for unrestricted) | Few/day unregistered; more with key | Cisco EULA | Check current Cisco licensing |
| OTX | Yes | Required | Not published | OTX ToS | Check LevelBlue ToS |
| AbuseIPDB | Yes | Required | 1,000 /check/day (Standard) | abuseipdb.com ToS | Paid tier for higher limits |
| VirusTotal | Yes | Required | 4 req/min, 500/day | VT ToS; no raw data redistribution | Premium required for higher quotas |
| Google Safe Browsing | Yes | Required (Cloud Console) | ~10,000/day est. | Google APIs ToS; show attribution in UI | Check Cloud Console quotas |
| GreyNoise | Yes | Optional | 50 searches/week (community) | greynoise.io/terms | Enterprise tier for higher limits |
| Shodan | Very limited | Required | Credit-based | account.shodan.io/terms | Paid tier for useful access |
| Censys | Yes (limited) | Required (ID+secret) | ~250 queries/month | censys.io/legal/terms | Paid plans for commercial |
| MISP | Self-hosted | Instance-specific | Instance-specific | AGPL-3.0 (platform); data per community policy | Self-hosted; community data per TLP/PAP |

## abuse.ch Sources (URLHaus + ThreatFox) — Detailed Terms

- **Attribution required**: when publishing reports or products using URLHaus/ThreatFox data, cite "abuse.ch"
- **Non-commercial fair use**: free for research, academic, non-profit, personal security use
- **Commercial use**: companies with commercial or for-profit needs "may require a paid subscription"
- **Submission quality**: submitting low-quality IOCs risks account ban
- ThreatFox: malware labels from Malpedia — check Malpedia license separately for malware family names

## Google Safe Browsing — Detailed Terms

- **Required attribution**: consumer-facing products using GSB data MUST display "Google Safe Browsing" in UI where results are presented
- **No list redistribution**: cannot store or redistribute raw threat list data beyond `cacheDuration`
- **Not for blocking unauthorized content**: GSB is for user safety warnings, not general IP blocking
- **Usage policy**: developers.google.com/safe-browsing/v4/terms

## PhishTank — Detailed Terms

- **Operated by Cisco Talos** — governed by Cisco end-user license agreement
- **Attribution**: cite "PhishTank (Cisco Talos)" in reports
- **API key**: required for unrestricted download access; free registration
- **Rate limiting**: generic User-Agent strings trigger stricter limits; use `phishtank/[username]`
- **Commercial use**: verify with current Cisco Talos licensing

## VirusTotal — Detailed Terms

- **No raw data redistribution**: public API responses cannot be bulk-re-distributed or sold
- **Attribution**: cite "VirusTotal" when surfacing VT-sourced findings in customer reports
- **Premium**: required for retrohunt, livehunt, higher quotas, private analysis
- **Public key**: 4 requests/minute, 500/day — sufficient for targeted lookups, not bulk scanning

## AbuseIPDB — Detailed Terms

- **Attribution**: encourage linking to abuseipdb.com when displaying results
- **No bulk re-distribution**: raw API responses not for redistribution
- **PII warning**: reports may contain PII — do not expose user-submitted report comments in customer-facing outputs without review
- **Rate limits**: strictly enforced; 429 with `Retry-After` header

## GreyNoise — Detailed Terms

- **Community API**: free with optional registration; 50 searches/week
- **Enterprise**: required for bulk lookups, full data access, GNQL advanced queries
- **Attribution**: cite "GreyNoise Intelligence" when using classification data in reports
- **No redistribution**: raw API responses not for redistribution

## Shodan — Detailed Terms

- **Free tier**: very limited; mostly useful for `/shodan/host/{ip}` direct lookups
- **API key**: required for all endpoints
- **No redistribution**: raw Shodan data cannot be bulk-re-distributed
- **Subscription**: required for useful search queries and scan credits
- **Enterprise**: bulk data API for institutional use

## Censys — Detailed Terms

- **Researcher accounts**: free but with monthly quota (~250 queries)
- **Commercial use**: paid plans required
- **Attribution**: cite "Censys" in publications using Censys data
- **Enterprise agreement**: required for bulk data access

## Key Compliance Priorities for WebHound

1. **Never expose raw TI data directly to customers** — always present as WebHound analysis with source attribution
2. **Respect cacheDuration** for GSB results — do not mark URLs unsafe beyond cache expiry without re-querying
3. **Store only anonymized summaries** — do not store verbatim API responses beyond operational need
4. **Attribute TI sources in customer reports** — "Data from VirusTotal, URLHaus, Google Safe Browsing" in report footer
5. **Respect abuse.ch commercial use terms** — if WebHound is sold/subscribed commercially, coordinate with abuse.ch
6. **Never commit API keys** — store all TI API keys in secrets manager, not in code or config files
