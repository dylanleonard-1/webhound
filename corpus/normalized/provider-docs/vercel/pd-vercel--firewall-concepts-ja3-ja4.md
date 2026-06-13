# Vercel Firewall Concepts — JA3/JA4 TLS Fingerprinting

Source: https://vercel.com/docs/vercel-firewall/firewall-concepts
Provider: Vercel | Authority: Tier A
Ingested: 2026-06-13 | Terms: Developer docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## Request processing pipeline

1. Platform-wide firewall (DDoS mitigation) — inspects requests as they arrive at Vercel CDN
2. Deployment protection — checks access rules set at project level
3. WAF (custom rules) — per-project configurable rules
4. If not blocked: request reaches deployment

If a WAF rule with a persistent action blocks a request, the source IP is stored in the platform firewall so future requests continue to be blocked for the specified period (platform-level enforcement).

## JA3 and JA4 TLS fingerprinting

TLS fingerprinting creates a unique identifier from TLS client hello packet details: TLS version, supported cipher suites, included extensions.

**Why used:** A DDoS attack spread across multiple user agents, IPs, or geos may share the same TLS fingerprint. Vercel Firewall blocks all traffic matching that fingerprint.

**Scanner implication:** A scanner using Python urllib, curl default settings, or Go's `crypto/tls` will produce a different JA3/JA4 fingerprint than browsers (Chrome, Firefox). If a site has JA4-based blocking enabled, scanner requests may be blocked regardless of other request attributes.

### JA4 (preferred)

JA4 is part of the JA4+ suite. More granular and flexible than JA3. Helps identify, track, and categorize server-side encrypted network traffic. Better at detecting malicious traffic patterns across distributed attacks.

### JA3

Focuses on TLS client hello packet; generates hash from TLS version, cipher suites, extensions.

### Request headers

These headers are injected by Vercel into every request received by deployments:

- `x-vercel-ja4-digest` — JA4 fingerprint hash (preferred)
- `x-vercel-ja3-digest` — JA3 fingerprint hash

Both headers can be read from the `Request` object in Vercel Functions.

## Firewall response headers

Present on all Vercel-served responses:
- `x-vercel-id` — edge node + request ID (e.g., `iad1::abc123-456`)
- `server: Vercel`
- `x-vercel-cache` — `HIT`, `MISS`, `BYPASS`, `STALE`

On blocked (403) responses: minimal JSON or HTML body, `x-vercel-id` still present.

## Challenge action

When Vercel Firewall issues a challenge:
- Browser sees "Vercel Security Checkpoint" page
- Browser must execute JS to compute and submit challenge solution
- System validates browser characteristics
- Challenge session valid for 1 hour; session tied to that browser
- Non-browser clients (curl, Python requests, scanners) cannot pass JS challenge
- API routes behind challenge rules cannot be accessed by automated tools without a valid session
