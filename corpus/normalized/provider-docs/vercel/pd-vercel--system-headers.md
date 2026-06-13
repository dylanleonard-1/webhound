# Vercel System Headers — Request and Response

Source: https://vercel.com/docs/headers/request-headers + https://vercel.com/docs/headers/response-headers
Provider: Vercel | Authority: Tier A
Ingested: 2026-06-13 | Terms: Developer docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## Request headers injected by Vercel

These headers are set by Vercel on every inbound request before reaching your function:

| Header | Value / Format | Description |
|---|---|---|
| `x-vercel-id` | `iad1::abc123-456` | Edge region + request ID; prevents infinite loops; present on all requests |
| `x-vercel-deployment-url` | `*.vercel.app` | Underlying deployment URL (not custom domain) |
| `x-forwarded-for` | `1.2.3.4` | Client public IP address; Vercel OVERWRITES this and does NOT forward external IPs (anti-spoofing) |
| `x-vercel-forwarded-for` | `1.2.3.4` | Same as x-forwarded-for; preserved even when a proxy overwrites x-forwarded-for |
| `x-real-ip` | `1.2.3.4` | Identical to x-forwarded-for |
| `x-forwarded-host` | `example.com` | Identical to host header |
| `x-forwarded-proto` | `https` / `http` | Protocol; always https in production |
| `x-vercel-ip-country` | `US` | ISO 3166-1 two-char country code for client IP |
| `x-vercel-ip-continent` | `NA` | Two-char continent code (AF/AN/AS/EU/NA/OC/SA) |
| `x-vercel-ip-country-region` | `CA` | ISO 3166-2 region portion (e.g., "England" for GB) |
| `x-vercel-ip-city` | `San+Francisco` | City name; RFC3986 encoded |
| `x-vercel-ip-latitude` | `37.7749` | Decimal latitude |
| `x-vercel-ip-longitude` | `-122.4194` | Decimal longitude |
| `x-vercel-ip-timezone` | `America/Chicago` | IANA timezone |
| `x-vercel-ip-postal-code` | `94107` | Postal code |
| `x-vercel-ja4-digest` | hash string | JA4 TLS fingerprint (preferred over JA3) |
| `x-vercel-ja3-digest` | hash string | JA3 TLS fingerprint |
| `x-vercel-signature` | hex string | HMAC-SHA1 of raw request body (webhooks/log drains only) |

### x-vercel-signature (Vercel webhook verification)

Algorithm: `HMAC-SHA1(WEBHOOK_SECRET, raw_request_body)` → hex
- Use constant-time comparison (`crypto.timingSafeEqual`)
- Do NOT parse/mutate body before verification
- Missing `x-vercel-signature` on a claimed Vercel webhook = unauthenticated request (critical finding)

## Response headers from Vercel

| Header | Values | Description |
|---|---|---|
| `server` | `Vercel` | Infrastructure identifier; may be overridden by Cloudflare in front |
| `x-vercel-cache` | `HIT`, `MISS`, `STALE`, `PRERENDER`, `REVALIDATED`, `BYPASS` | CDN cache status |
| `x-vercel-id` | `iad1::abc123-456` | Request routing trace (also in response) |
| `strict-transport-security` | `max-age=63072000` | HSTS enforced; 2-year max-age default |
| `x-robots-tag` | `noindex` | Present on preview deployments and outdated production deployments only |

## Scanner detection relevance

### Identifying Vercel infrastructure
1. Response contains `server: Vercel` → Vercel deployment (may be overridden by Cloudflare if Cloudflare in front)
2. Response contains `x-vercel-id` header → definitive Vercel edge request
3. Request receives `x-vercel-cache` in response → Vercel CDN active

### IP geolocation rules (scanner implication)
- Vercel custom rules can restrict by `x-vercel-ip-country` or `x-vercel-ip-continent`
- Scanner from unexpected country/continent may trigger deny/challenge rules
- Scanner cannot spoof `x-forwarded-for` — Vercel overwrites it from actual TCP connection IP

### TLS fingerprinting (scanner implication)
- `x-vercel-ja4-digest` / `x-vercel-ja3-digest` injected into every request
- WAF custom rules can match on JA4 fingerprint value
- Python urllib / Go crypto/tls / curl produce distinct JA4 fingerprints from browsers
- If WAF has JA4-based deny rule for scanner fingerprints → scanner blocked regardless of user-agent

### Webhook endpoint security check
- If application uses Vercel webhooks and endpoint does NOT verify `x-vercel-signature` → spoofed event attack surface (critical)
