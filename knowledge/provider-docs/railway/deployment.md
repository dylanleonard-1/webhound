# Railway Deployment and Infrastructure

**Provider:** Railway · **Authority:** Tier A official docs · **Source:** https://docs.railway.com/
**Terms note:** Publicly available docs; detection-relevant summary only.

## Overview

Railway is a PaaS (Platform-as-a-Service) used by WebHound for API hosting. It deploys
container-based services with automatic TLS, custom domains, and environment variable
management.

## Network exposure and endpoints

- **Custom domain:** user-configured (e.g., `api.webhound.app`) → Railway edge → service
- **Railway domain:** auto-assigned `*.railway.app` for internal/preview access
- **Private networking:** services communicate on `*.railway.internal` (not public)
- **Port exposure:** `PORT` env var; Railway forwards external 443 → internal `$PORT`

## TLS

- Automatic TLS provisioning via Let's Encrypt for custom domains
- Railway-provisioned subdomains (`*.railway.app`) use Cloudflare with Railway's wildcard cert
- No mTLS support out-of-box; use Cloudflare Tunnel or VPN for private channels

## Environment variables (secrets management)

- Secrets stored as Railway environment variables (encrypted at rest)
- Available as env vars in container at runtime; NOT in image layers
- Reference between services with `${{other-service.PORT}}` syntax
- Shared variables available across all services in a project via Railway shared variables

Scanner security implication: scanning a Railway-hosted API sees Railway TLS termination.
Response headers do not include a Railway-specific identifier by default (unlike Cloudflare's `cf-ray`).

## Rate limiting and bot detection

Railway does NOT include WAF or bot-mitigation at the edge — that is the
responsibility of the application or an upstream CDN (e.g., Cloudflare in front of Railway).
Scanner requests to a Railway service reach the application directly (no challenge pages).

If the application uses Cloudflare as CDN in front of Railway:
- Scanner hits Cloudflare edge first (see [[cloudflare-waf-detection]])
- Origin requests from Cloudflare include `CF-Connecting-IP` header with real client IP

## WebHound API deployment context

WebHound's API runs on Railway. Key facts for scanning context:
- Scanner testing the API itself hits Railway's TLS termination
- Health check endpoint usually at `/health` or `/` (Railway checks this)
- Cron jobs (if any) run as Railway services with `cron` start command
- Logs available via `railway logs --service <name>` or Railway dashboard

**Related:** [[cloudflare-waf-detection]], [[vercel-deployment-protection]].
