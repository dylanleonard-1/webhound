# Fly.io Deployment and Infrastructure

**Provider:** Fly.io · **Authority:** Tier A official docs · **Source:** https://fly.io/docs/
**Terms note:** Publicly available docs; detection-relevant summary only.

## What Fly.io is

Fly.io is a container hosting platform that runs applications close to users via a global
anycast network. Competes with Railway, Render. Uses their own edge network (not
AWS/GCP/Azure).

## Network and TLS

- Custom domains with automatic TLS (Let's Encrypt) via `fly certs add`
- Fly-assigned domain: `{app-name}.fly.dev`
- Anycast routing — requests go to the nearest Fly edge node
- Fly Proxy (layer 7 proxy) handles TLS termination and routing

## Response headers from Fly

| Header | Notes |
|---|---|
| `fly-request-id` | Unique per request trace ID |
| `server` | Not typically set by Fly (application controls) |
| `via` | May show Fly Proxy on some configs |

Identifying Fly.io-hosted apps:
- `fly-request-id` header (most reliable)
- App URL ending in `.fly.dev`
- PTR lookup on IP resolving to `fly.io` ranges
- Fly.io uses AS398082

## Security headers (application responsibility)

Like Railway and Render, Fly.io does NOT inject security headers. Application sets:
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`

Fly.io docs recommend setting HSTS with long max-age.

## Machines API (compute model)

Fly.io uses "Machines" (ephemeral containers):
- Each request may be served by a different Machine instance
- Machines auto-start on request and can auto-stop when idle (scale to zero)
- Cold start latency possible if machine was stopped

Scanner implication: repeated requests may trigger machine start; first request may
have higher latency.

## Rate limiting

No built-in WAF or rate limiting from Fly.io. Application must implement:
- Application-level rate limiting middleware
- Or route through Cloudflare (common pattern)

## Private networking

- Apps within the same Fly organization communicate via WireGuard private network (6PN)
- Private network at `fdaa::/8` (IPv6)
- Not exposed publicly; scanner cannot reach private services directly

**Related:** [[railway-deployment]], [[render-deployment]].
