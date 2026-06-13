# Vercel Firewall

**Provider:** Vercel · **Authority:** Tier A official docs · **Source:** https://vercel.com/docs/security/vercel-firewall
**Terms note:** Publicly available docs; detection-relevant summary only.

## What Vercel Firewall is

Vercel Firewall is a WAF and DDoS protection layer built into Vercel's edge network.
Distinct from Deployment Protection (auth gate) — Firewall inspects HTTP traffic content
and IP reputation.

## Threat detection layers

1. **DDoS mitigation**: volumetric attack detection; blocks attack IPs at edge automatically
2. **WAF (Managed rules)**: OWASP-aligned rules for SQLi, XSS, command injection, etc.
3. **IP reputation**: blocks requests from known malicious IPs via Vercel's threat intelligence
4. **JA3/JA4 TLS fingerprinting**: identifies non-browser TLS clients; can trigger challenges
5. **Bot detection**: evaluates browser-like behavior; scanners may be fingerprinted

## Response for blocked requests

- 403 Forbidden (WAF rule match)
- Body: minimal HTML or JSON `{"error":"Forbidden"}`
- `x-vercel-id` header still present
- No distinctive challenge-page like Cloudflare JS challenge

## Custom firewall rules

Vercel allows custom WAF rules via `vercel.json` or the Vercel dashboard:
```json
{
  "firewall": {
    "rules": [
      {
        "name": "block-scanners",
        "action": { "type": "deny" },
        "conditionGroup": [{"conditions": [{"type": "user_agent", "op": "contains", "value": "nikto"}]}]
      }
    ]
  }
}
```

Rule conditions: IP address, country, user-agent, path, request method, header value.
Actions: `deny` (403), `challenge` (CAPTCHA), `log` (allow but log), `bypass` (skip rules).

## Scanner bypass via firewall rules

For authorized scanning, a bypass rule can be added:
```json
{
  "action": { "type": "bypass" },
  "conditionGroup": [{"conditions": [{"type": "header", "op": "equals", "key": "x-scan-token", "value": "{secret}"}]}]
}
```
This allows the scanner header to skip WAF inspection.

## Vercel response headers (always present)

| Header | Value |
|---|---|
| `x-vercel-id` | Edge node + request ID (e.g., `iad1::abc123-456`) |
| `server` | `Vercel` |
| `x-vercel-cache` | `HIT`, `MISS`, `BYPASS`, `STALE` |
| `x-matched-path` | Route that matched the request |

## Identifying Vercel-fronted applications

- `server: Vercel` response header (most reliable)
- `x-vercel-id` header
- URL ending in `.vercel.app`
- IP in Vercel ASN (AS14618 Amazon — Vercel uses AWS infrastructure)
- DNS CNAME to `alias.zeit.co` or `cname.vercel-dns.com`

**Related:** [[vercel-deployment-protection]], [[cloudflare-waf-detection]].
