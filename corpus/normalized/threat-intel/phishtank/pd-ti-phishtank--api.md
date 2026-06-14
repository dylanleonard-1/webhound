# PhishTank API — Technical Reference

Source: https://www.phishtank.com/developer_info.php
Provider: PhishTank (operated by Cisco Talos) | Authority: Tier A
Ingested: 2026-06-13 | Terms: Cisco EULA; free for non-commercial use with attribution; API key required for unrestricted access.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## What PhishTank is

Community-driven phishing URL verification database operated by Cisco Talos Intelligence Group. Users submit suspected phishing URLs; community members vote to verify or dispute them. Only "verified" phishes appear in the public dataset.

## Data Access Endpoints

### Database Downloads (primary method)

Format-specific URLs at `http://data.phishtank.com/data/`:
- Unauthenticated: `online-valid.json[.gz|.bz2]` / `.xml[.gz|.bz2]` / `.csv[.gz|.bz2]`
- Authenticated: `http://data.phishtank.com/data/<app_key>/online-valid.json.bz2`

Files updated **hourly**. Use HTTP HEAD with ETag to check for updates without downloading.

## Response Fields (per phish entry)

| Field | Type | Description |
|---|---|---|
| `phish_id` | int | Positive integer ID |
| `url` | string | The phishing URL (CDATA in XML) |
| `phish_detail_url` | string | Link to PhishTank detail page |
| `submission_time` | ISO 8601 | When URL was submitted |
| `verified` | "yes" | Always "yes" in public dataset |
| `verification_time` | ISO 8601 | When community verified it |
| `online` | "yes" | Only online phishes in dataset |
| `target` | string | Impersonated brand/company |
| `details` | object | IP, CIDR, announcing network, RIR |

## Indicator Types

- **Phishing URLs** only — full URL strings representing fraudulent impersonation sites
- Target brand information (Apple, PayPal, Google, banks, etc.)
- IP and network information per phish

## Verification Model

Community-voting system:
- Users submit suspected phishing URLs
- Other community members vote: valid phish or not phish
- "Verified" = passed voting threshold
- Public dataset contains only verified + currently online phishes
- Dispute mechanism exists (re-vote after initial verification)

## Rate Limits & Authentication

- Unregistered: "a few downloads per day"
- Registered (app_key): unlimited HTTP HEAD checks; more generous download limits
- User-Agent should be `phishtank/[username]` — generic/blank UA triggers more rate limiting
- HTTP 429 when limit exceeded

## Data Freshness

- Updated hourly
- `verification_time` shows when community confirmed — age indicates staleness
- `online: yes` means site was accessible at verification time (may have since gone offline)

## Confidence Semantics

High confidence: community-verified phishes are human-confirmed. Confidence factors:
- `verified = yes` + recent `verification_time` = high confidence
- Old verification_time (>30 days) + no re-check = stale IOC risk
- Target brand field helps scope: PayPal phish IOC has no bearing on unrelated domains

## False Positive Risk

- URL-level: only the specific URL is verified, not the whole domain
- Parked domains recycled: old phish URL domain may now be clean or redirected
- Shared hosting: IP in `details` not a reliable indicator of maliciousness for co-hosted sites
- Dataset is "currently online" verified — does NOT include taken-down phishes

## License / Terms

- Governed by Cisco EULA and privacy policies
- Attribution: cite "PhishTank (Cisco Talos)" when using data
- Commercial use: check current Cisco Talos licensing
- API key registration required at phishtank.org

## WebHound Scanner Relevance

Use case: check customer site's third-party script URLs against PhishTank verified phishing URLs. A customer-served URL matching a PhishTank entry = high-priority phishing redirect or malicious resource finding. Target brand field useful for contextualizing which users are at risk.
