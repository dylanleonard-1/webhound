# Imperva Cloud WAF

**Provider:** Imperva (formerly Incapsula) · **Authority:** Tier A summary (authored from official docs knowledge) · **Source:** https://docs.imperva.com/bundle/cloud-application-security/
**Terms note:** Authored detection-relevant summary; not a verbatim mirror.

## What Imperva Cloud WAF is

Imperva (acquired Incapsula 2014) provides a cloud-based WAF as reverse proxy.
Used primarily by enterprises and financial services. Products:
- **Cloud WAF**: reverse proxy WAF (formerly Incapsula WAF)
- **DDoS Protection**: layer 3/4 and layer 7
- **Bot Management**: behavioral analysis + challenge
- **Account Takeover Protection**: login protection

## Challenge page signatures

When Imperva/Incapsula challenges or blocks a request:

| Situation | Response |
|---|---|
| Bot challenge | 200 HTML with JavaScript challenge; sets `incap_ses_*` cookie |
| CAPTCHA challenge | 200 HTML with reCAPTCHA widget |
| Block | 403 with Imperva block page |

Cookie names: `incap_ses_{id}_{domain}`, `visid_incap_{id}` — these are Imperva session cookies.
A request without valid `incap_ses` cookie (or with an invalid one) may be challenged on every request.

## Response headers from Imperva

| Header | Notes |
|---|---|
| `x-iinfo` | Incapsula request info (format: `{cache_status},{incap_site},{request_id}`) |
| `x-cdn` | `Imperva` (on some configs) |
| `set-cookie: incap_ses_*` | Challenge session cookie |
| `set-cookie: visid_incap_*` | Visitor ID cookie for bot tracking |

## Bot Management behavioral analysis

Imperva Bot Management:
- Tracks user behavior across requests (mouse, scroll, click timing) via JS injection
- Compares fingerprint to known bot profiles
- Builds browser fingerprint from WebGL, canvas, font enumeration
- Automated clients without JS execution receive challenge on every request

## WAF rules

Imperva uses signature-based + positive security model:
- Whitelist known-good request patterns (positive security)
- Blocklist attack patterns (signatures): SQLi, XSS, OS command injection, HTTP protocol anomalies
- Custom whitelisting per URL/param to reduce false positives

## Scanner allowlisting

Imperva IP allowlisting:
- Cloud WAF Console → IP Management → Allowlisted IPs → add scanner CIDR
- Imperva API: `POST /sites/{site_id}/settings/security` with IP whitelist parameter

## Identifying Imperva-fronted sites

- `x-iinfo` response header
- `incap_ses_*` or `visid_incap_*` cookies in Set-Cookie
- `x-cdn: Imperva` header
- IP resolving to Imperva cloud ranges (AS19551 INCAPSULA)
- Block page HTML mentioning "Imperva" or "Incapsula"

**Related:** [[akamai-bot-manager]], [[cloudflare-waf-detection]].
