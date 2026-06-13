# Sucuri WAF and Malware Detection

**Provider:** Sucuri (GoDaddy subsidiary) · **Authority:** Tier A summary (connection refused; authored from official docs knowledge) · **Source:** https://sucuri.net/website-firewall/
**Terms note:** Authored detection-relevant summary; not a verbatim mirror.

## What Sucuri is

Sucuri is a website security platform primarily used by SMBs and WordPress sites, offering:
- **Sucuri Firewall (WAF)**: cloud-based reverse proxy WAF
- **Malware scanning**: remote + server-side scanner
- **DDoS protection**: volumetric and application-layer
- **CDN**: edge caching with security rules

## WAF detection and challenge pages

Sucuri WAF inspects HTTP requests before forwarding to origin:
- Blocks common web attacks (SQLi, XSS, LFI, RFI, code injection)
- Challenge types:
  - **Browser check** (JS challenge): 200 with JS redirect; sets `sucuri_cloudproxy_uuid_*` cookie
  - **CAPTCHA challenge**: displays reCAPTCHA form
  - **Block page**: custom or default HTML with Sucuri branding

Response indicators:
- `x-sucuri-id` header on passed requests (WAF node ID)
- `x-sucuri-cache` on cached responses
- Block page HTML mentions "sucuri" or "website firewall"
- `sucuri_cloudproxy_uuid_*` cookie set during JS challenge

## Malware scanning (remote scanner)

Sucuri's remote scanner fetches target URLs and analyzes response content:
- Checks for known malware signatures in HTML/JS
- Detects iframe injections, script injections, hidden redirects
- Checks links against malware/phishing blocklists
- Verifies DNSBL/blocklist status (Google Safe Browsing, etc.)

WebHound context: if scanning a Sucuri-protected site, scanner may trigger the same
detection flow Sucuri uses. A site that shows `x-sucuri-id` in responses means:
1. Scanner is reaching through WAF — payload delivery is filtered
2. Active attack payloads will be blocked/logged by Sucuri

## Allowlisting for Sucuri-protected sites

- Sucuri dashboard → Whitelist IP address → add scanner CIDR
- Sucuri API: `PUT /v2/firewall/zones/{zone_id}/whitelist` with IP entry
- Alternative: request header exception (operator-configured)

## WordPress-specific detection

Sucuri's scanner specifically checks for:
- WordPress malware signatures (plugin backdoors, theme injections)
- Unauthorized file changes (file integrity monitoring via server-side agent)
- PHP shell patterns in uploaded media
- Admin login page hardening (custom login URL, 2FA enforcement)

## Identifying Sucuri-fronted sites

- `x-sucuri-id` response header
- Sucuri WAF IP ranges (AS29802, AS6939 Hurricane Electric — used by some Sucuri nodes)
- PTR lookup showing `sucuri.net` on some edge nodes
- Block page HTML containing "Sucuri Website Firewall"

**Related:** [[akamai-bot-manager]], [[cloudflare-waf-detection]].
