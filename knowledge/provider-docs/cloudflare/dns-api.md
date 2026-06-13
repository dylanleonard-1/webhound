# Cloudflare DNS and API

**Provider:** Cloudflare · **Authority:** Tier A official docs · **Source:** https://developers.cloudflare.com/dns/ · https://developers.cloudflare.com/api/
**Terms note:** Publicly available docs; detection-relevant summary only.

## DNS API (detection use case: verify DNS record configuration)

Cloudflare's DNS API allows reading zone records. This is used by WebHound to:
- Verify SPF/DKIM/DMARC records exist for email deliverability
- Check for known scanner-bypass CNAME configurations
- Enumerate subdomains for scope discovery

Key endpoints:
- `GET /zones?name={domain}` — look up zone ID
- `GET /zones/{zone_id}/dns_records?type=TXT&name={domain}` — read TXT records (SPF, DMARC, DKIM)
- `GET /zones/{zone_id}/dns_records?type=A` — read A records

Auth: `Authorization: Bearer {api_token}` or `X-Auth-Email` + `X-Auth-Key` (legacy).

## Proxied vs DNS-only records

- **Proxied (orange cloud):** traffic routed through Cloudflare edge; scanner sees Cloudflare edge IP, not origin. WAF/rate-limiting active.
- **DNS-only (grey cloud):** record returns origin IP directly; Cloudflare is not in path.

A scanner can detect Cloudflare proxying by:
1. Checking if the IP resolves to Cloudflare ranges (`103.21.244.0/22`, `103.22.200.0/22`, `103.31.4.0/22`, `141.101.64.0/18`, etc.)
2. Looking for `cf-ray` header in HTTP response.
3. Reverse DNS lookup on IP showing `*.cloudflare.net`.

## Zone-level security settings relevant to scanning

- **SSL/TLS mode:** Full (strict), Flexible, or Off. Affects which cert the scanner sees.
- **Always-HTTPS redirect:** 301 to HTTPS if scanner hits HTTP.
- **HSTS:** `Strict-Transport-Security` header injected by CF edge.
- **TLS 1.3:** enabled by default. Scanners need TLS 1.3 support for handshake.
- **Minimum TLS version:** default 1.2. Connections below this → `SSL_ERROR_RX_RECORD_TOO_LONG` or reset.

## WebHound integration note

WebHound's Cloudflare integration (OAuth-based) can:
- Read zone DNS records to verify email/MX configuration
- Create WAF bypass firewall rules for scanner IP
- Check zone security settings for scan scope planning

**Related:** [[cloudflare-waf-detection]].
