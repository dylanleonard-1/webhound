# OpenPhish Phishing Intelligence Feed — Technical Reference

Source: https://openphish.com/phishing_database.html
Provider: OpenPhish | Authority: Tier A
Ingested: 2026-06-13 | Terms: Contact contact@openphish.com; organizational domain verification required; terms of use at openphish.com.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## What OpenPhish is

Commercial phishing intelligence platform providing real-time phishing URL detection. Runs automated discovery and analysis pipeline (no community voting — proprietary detection). Three subscription tiers: Light, Extended, Pro.

## Indicator Types

- **Phishing URLs** (primary) — full URL strings
- Hostname, page path, SSL certificate metadata
- IP address, ASN, country of phishing host
- Impersonated brand, drop accounts (Pro tier)
- Language detection per phish page

## Feed Access

- **Format**: SQLite database (not plain text URL list)
- **Python module**: `pyopdb` (open-source, available on GitHub)
- **Authentication**: Organizational email verification required (no anonymous or personal accounts)
- **Update frequency**: 15-minute intervals (Light and Extended tiers), Daily (Pro tier)
- **Pricing**: On request via contact@openphish.com

## Subscription Tiers

| Tier | Update Frequency | Data Retention |
|---|---|---|
| Light | 15 minutes | 60 days |
| Extended | 15 minutes | 120 days |
| Pro | Daily | 180 days |

## Community Feed

OpenPhish also publishes a free community feed at `openphish.com/feed.txt`:
- Plain-text list of active phishing URLs
- No authentication required
- Less comprehensive than paid tiers
- No metadata (just raw URLs)

## Confidence Semantics

Proprietary automated detection (not community-voted). Not published. Treat as:
- Paid tier: high precision, commercially validated — high confidence
- Community feed: automated only, moderate confidence — corroborate with other sources

## False Positive Risk

- Automated detection may flag lookalike domains that are not malicious
- URL-level specificity: domain may be compromised but not fully malicious
- Paid tier has lower FP rate (proprietary validation pipeline)

## License / Terms

- Requires active subscription/agreement
- Attribution: cite "OpenPhish" in reports using their data
- No redistribution without permission
- Community feed: free but check openphish.com/terms

## WebHound Scanner Relevance

Comparison: URLHaus/ThreatFox better for malware distribution; OpenPhish better for phishing page detection.
Community feed (`openphish.com/feed.txt`) usable without auth for basic phishing URL matching.
Gap: no OpenPhish client in `scanner/webhound/threat_intel/` — community feed is accessible.
