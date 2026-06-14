# Threat Intelligence for Phishing Detection

Category: TI knowledge synthesis | WebHound Phase 6E
Updated: 2026-06-13

## Scope

This note covers how WebHound uses TI to detect phishing threats in the context of customer site scanning — not for detecting whether a customer's site IS a phishing site, but for detecting:
1. Whether a customer's site has been compromised to host phishing content
2. Whether a customer's redirects or third-party resources point to phishing destinations
3. Whether the customer's domain is being impersonated

## Phishing-Specific TI Sources

| Source | Strength | Coverage |
|---|---|---|
| OpenPhish | HIGH | Automated phishing URL discovery; real-time |
| PhishTank | HIGH | Community-verified phishing URLs; broad brand coverage |
| Google Safe Browsing (`SOCIAL_ENGINEERING`) | HIGH | Phishing + deceptive pages; widest coverage |
| URLHaus (`phishing_domain` Spamhaus tag) | MEDIUM | Phishing domains via Spamhaus DBL |
| VirusTotal (PHISHING category engines) | MEDIUM | Multi-engine phishing URL analysis |
| ThreatFox | LOW for phishing | Focuses more on malware/C2 |

## Detection Scenario 1: Customer Site Hosts Phishing Page

**Signals**:
- Customer's URL matches PhishTank or OpenPhish entry
- GSB SOCIAL_ENGINEERING match on customer's own URL
- VirusTotal shows phishing/fraud category on customer's domain

**Response**: This is a high-severity finding. The customer's site may have been compromised. Report as: "A page on your site matches known phishing databases — your site may have been compromised to host phishing content."

**Do NOT say**: "Your site is a phishing site" — it may be compromised, not intentionally malicious.

## Detection Scenario 2: Customer Site Redirects to Phishing Destination

**Signals**:
- A redirect chain from customer's site terminates at a URL in PhishTank/OpenPhish/GSB
- A script URL leads to a phishing page
- An iframe src points to a phishing URL

**Response**: HIGH severity. "This page on your site redirects visitors to a known phishing URL — `[destination]`. Visitors may be exposing credentials to attackers."

## Detection Scenario 3: Customer Domain Being Impersonated (Lookalike Phishing)

**Signals**:
- PhishTank/OpenPhish has entries with `target` = customer's brand
- Newly registered domains with lookalike names (typosquatting, IDN homograph attacks)
- Certificate transparency logs showing lookalike certificate issuance

**Sources**: PhishTank `target` field (brand impersonation lookup), Censys certificate search, VirusTotal passive DNS for lookalike domains.

**Response**: MEDIUM severity (not a compromise, but brand risk). "We identified [N] phishing URLs impersonating your brand in threat databases. Recommend monitoring and reporting these to the source TI platforms."

## PhishTank-Specific Considerations

- `target` field identifies the impersonated brand → useful for brand monitoring
- Dataset only includes `online: yes` entries — stale phishes are excluded
- API key recommended to avoid rate limiting (`User-Agent: phishtank/yourusername`)
- Response includes IP of phishing host → cross-reference with AbuseIPDB for additional context

## OpenPhish-Specific Considerations

- Community feed (`openphish.com/feed.txt`): accessible without auth; plain URL list
- Paid feed: includes brand, SSL metadata, IP/ASN → more actionable
- 15-minute update frequency makes it one of the most real-time phishing sources

## GSB for Phishing

- Threat type `SOCIAL_ENGINEERING` covers phishing, deceptive pages
- Response includes `cacheDuration` — if expired, re-query before reporting
- Up to 500 URLs per request — efficient for batch checking
- URL-level matching is exact — path matters

## False Positive Risk for Phishing Detection

- Legitimate login pages may look like phishing to automated classifiers (similar form fields)
- Security awareness training sites (test phishing campaigns) may appear in feeds
- PhishTank verification community may dispute some entries — `verified: yes` still possible to be FP
- Customer's own lookalike test domains may appear in feeds if submitted by a third party

## Reporting Language

When customer site hosts phishing content:
> "A URL on your site — `[customer_url]` — matches [PhishTank/OpenPhish/Google Safe Browsing] as a known phishing page targeting [brand] as of [date]. This indicates your site may have been compromised. We recommend immediate investigation of this URL and your site's file integrity."

When redirect to phishing:
> "Your site redirects visitors from `[customer_url]` to `[phishing_url]`, which is flagged as a phishing destination by [source]. Users following this redirect may expose their credentials."
