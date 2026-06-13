# Render Deployment and Infrastructure

**Provider:** Render · **Authority:** Tier A summary (large page; authored from official docs knowledge) · **Source:** https://render.com/docs
**Terms note:** Authored detection-relevant summary; not a verbatim mirror.

## What Render is

Render is a cloud hosting platform used for web services, static sites, background workers,
cron jobs, and databases. Similar to Railway and Heroku.

## Network and TLS

- Custom domains with automatic TLS (Let's Encrypt) provisioned within minutes
- Render-managed domain: `{service-name}.onrender.com`
- All services exposed on port 443 by default (HTTP on 80 redirected)
- TLS termination at Render's edge; origin service speaks HTTP internally

## Security headers

Render does NOT inject security headers by default. Applications must set:
- `Content-Security-Policy`
- `X-Frame-Options`
- `Strict-Transport-Security`

Render static sites: can set response headers via `render.yaml` `headers` config block.

## Response headers from Render

| Header | Presence |
|---|---|
| `server` | Not set by Render (application controls) |
| `x-render-origin-server` | Not standard; may appear on some responses |
| `via` | May show `1.1 render` on some configs |

Identifying Render: primarily via `.onrender.com` subdomain or known IP ranges.
Render's IP ranges are not prominently published; resolution via Render dashboard or
reverse DNS.

## Render deploy hooks (security)

Render exposes deploy hooks — URLs that trigger redeployment when called via HTTP POST.
Format: `https://api.render.com/deploy/{service-id}?key={deploy-key}`
- No auth other than the `key` param in URL
- If the deploy hook URL leaks, an attacker can trigger redeployment
- Should be treated as a secret; not safe to commit to repos

## Rate limiting

Render does not provide edge-level WAF or rate limiting. Applications must implement:
- Application-level rate limiting (express-rate-limit, fastapi-limiter, etc.)
- Or route traffic through Cloudflare in front of Render

## Scanner detection notes

- No challenge pages or bot detection from Render itself
- Scanner reaches application directly
- If Cloudflare is in front: see [[cloudflare-waf-detection]]
- Deploy hook URLs should be flagged if found in public repos (secret scanning use case)

**Related:** [[railway-deployment]], [[cloudflare-waf-detection]].
