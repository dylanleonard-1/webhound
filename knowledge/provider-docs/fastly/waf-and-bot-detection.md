# Fastly WAF and Bot Detection

**Provider:** Fastly · **Authority:** Tier A summary (direct access blocked; authored from official docs knowledge) · **Source:** https://developer.fastly.com/reference/
**Terms note:** Authored detection-relevant summary; not a verbatim mirror.

## What Fastly is

Fastly is a CDN and edge cloud platform offering:
- **Next-Gen WAF** (powered by Signal Sciences / Fastly acquired Signal Sciences in 2020)
- **DDoS protection** at the edge
- **Image optimization**, **video streaming** edge
- **Compute@Edge** (WASM-based edge compute, now called Compute)

## WAF (Next-Gen WAF / Signal Sciences)

Key detection signatures:
- Powered by Signal Sciences' behavioral engine — tracks request patterns across IPs, not just single-request rules
- Identifies attack campaigns by correlating anomalies across users/IPs
- Blocks common web attacks: SQLi, XSS, path traversal, RCE attempts, SSRF, XML injection
- **SmartParse** — parses HTTP body/query params in multiple encodings to detect evasion (Base64, URL-encode, double-encode)

## Response indicators for blocked requests

Fastly WAF typically returns:
- HTTP 406 Not Acceptable with an explanation HTML page (Signal Sciences default block page)
- Custom block pages configured by site operator
- `x-sigsci-requestid` response header on blocked requests (identifies Signal Sciences processing)
- `x-sigsci-tags` on requests flagged but passed (for logging)

## Bot detection

Fastly's bot detection:
- Checks TLS JA3 fingerprint against browser fingerprint database
- Evaluates HTTP header order, User-Agent consistency
- Rate-based detection: unusual request velocity from single IP
- **Credential stuffing detection**: detects login endpoint probing patterns

## Scanner allowlisting for Fastly

Official method: add scanner IP to WAF allowlist via:
- Fastly WAF Console → Corp → Allowlisted IPs
- Signal Sciences API: `POST /v0/corps/{corp_name}/networks` with IP range

No automated bypass header like Vercel — must be explicit allowlist by IP or CIDR.

## Edge dictionary and rate limiting

Fastly uses **Edge Dictionaries** and **Rate Limiters** configured via VCL (Varnish Configuration Language):
- `ratelimit.ratecounter_increment()` per client IP
- Rate limiter triggers custom error response (usually 429 with Retry-After)
- Scanner sees 429 with `Retry-After` header; should respect rate limits

## Detection for WebHound

Scanner can identify Fastly-fronted sites by:
- `x-served-by: cache-xxx-xxxx` response header (Fastly cache node ID)
- `x-cache: HIT` or `MISS`
- `x-cache-hits: 1`
- `via: 1.1 varnish`
- Fastly server IP ranges (AS54113 / FASTLY)

**Related:** [[cloudflare-waf-detection]], [[akamai-bot-manager]].
