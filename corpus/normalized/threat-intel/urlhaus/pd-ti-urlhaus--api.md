# URLHaus API — Technical Reference

Source: https://urlhaus-api.abuse.ch/
Provider: abuse.ch / URLHaus | Authority: Tier A
Ingested: 2026-06-13 | Terms: Free fair use; attribution required; commercial use may require paid subscription per abuse.ch ToU.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## What URLHaus is

abuse.ch URLHaus tracks malware distribution URLs and their associated payloads. Primary focus: active malware download URLs (drive-by downloads, C2 payload delivery). Data is crowdsourced and moderated.

## Authentication

All requests require `Auth-Key` header. Free account registration at auth.abuse.ch. No anonymous access.

## API Endpoints (base: https://urlhaus-api.abuse.ch/v1/)

| Endpoint | Method | Purpose |
|---|---|---|
| `/urls/recent/` | GET | Recent URLs (past 3 days, up to 1000) |
| `/payloads/recent/` | GET | Recent payloads (past 3 days) |
| `/url/` | POST | Query specific URL (param: `url`) |
| `/urlid/` | POST | Query by database ID (param: `urlid`) |
| `/host/` | POST | Query host/domain (param: `host`) |
| `/payload/` | POST | Query by hash (param: `md5_hash` or `sha256_hash`) |
| `/tag/` | POST | Query by malware tag (param: `tag`) |
| `/signature/` | POST | Query by malware family (param: `signature`) |
| `/download/<sha256>` | GET | Download malware sample (ZIP, password: "infected") |

## Indicator Types Supported

- Full malware URLs
- IPv4 addresses / domains / FQDNs (hosts)
- MD5, SHA256, IMPHASH, SSDEEP, TLSH hashes (payloads)
- Malware family names (signatures)
- User-assigned tags

## Response Status Values

- `ok` — successful query
- `no_results` — no match found
- `http_get_expected` / `http_post_expected` — wrong HTTP method

## URL Status Values

- `online` — active malware distribution currently detected
- `offline` — inactive, no payload currently served
- `unknown` — status undetermined

## Blacklist Integrations (per URL response)

- SURBL: `listed` / `not listed`
- Spamhaus DBL categories: `spammer_domain`, `phishing_domain`, `botnet_cc_domain`, `abused_legit_malware`, `abused_legit_phishing`, `abused_legit_botnetcc`, `abused_redirector`

## Batch Downloads

- Hourly ZIP batches: `https://datalake.abuse.ch/urlhaus/hourly/`
- Daily ZIP batches: `https://datalake.abuse.ch/urlhaus/daily/`
- Password: `infected`

## Confidence Semantics

- `online` URLs: high confidence — actively serving malware at query time
- `offline` URLs: moderate confidence — confirmed malicious historically, but no longer active
- `unknown`: lower confidence — not recently checked
- Blacklist presence (SURBL/Spamhaus) adds independent corroboration

## False Positive Risk

- Compromised legitimate sites: a legitimate domain may host malware temporarily; `offline` + old date = stale IOC risk
- URL-level specificity: only the exact URL may be malicious, not the entire domain
- Shared hosting: IP hosting the URL may be shared; IP-level blacklisting from URLHaus data = high FP risk

## Rate Limits

Not explicitly published in docs. Batch downloads preferred for bulk use.

## License / Terms

- abuse.ch Terms of Use: https://abuse.ch/terms-of-use/
- Free for non-commercial research; commercial use requires coordination with abuse.ch
- Attribution required when using data in reports/products

## WebHound Scanner Relevance

Existing client: `scanner/webhound/threat_intel/urlhaus.py` — URLHaus client already implemented.
Detection note: a URL from customer scan matching URLHaus `online` status = strong phishing/malware delivery signal. Always check status date and whether URL matches exactly (path-level).
