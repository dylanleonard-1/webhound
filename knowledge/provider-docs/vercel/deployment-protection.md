# Vercel Deployment Protection

**Provider:** Vercel · **Authority:** Tier A official docs · **Source:** https://vercel.com/docs/deployment-protection
**Terms note:** Publicly available docs; detection-relevant summary only.

## What it is

Deployment Protection controls who can access Vercel preview and production URLs. A
scanner hitting a protected deployment **without authorization** will not receive the
application — it receives an authentication challenge or redirect instead.

## Protection methods

| Method | Plans | What scanner sees |
|---|---|---|
| **Vercel Authentication** | All | Redirect to `vercel.com/login` (302); cookie check |
| **Password Protection** | Enterprise / Pro add-on | Password form page (HTML, 200 with auth wall) |
| **Trusted IPs** | Enterprise | 403 if source IP not in allowlist |
| **Passport** (beta) | Enterprise | Identity provider redirect |

## Protection scope

- **Standard Protection** (most common): all deployment URLs protected **except** the production domain — so `my-app.vercel.app` and preview URLs are gated, but `my-app.com` is publicly accessible.
- **All Deployments**: production domain also gated (Pro/Enterprise).
- Scanners running against preview URLs frequently encounter Standard Protection.

## Bypass for automation (WebHound scanner use)

The official bypass mechanism for CI/scanning tools:
- **Header:** `x-vercel-protection-bypass: <secret>` (recommended)
- **Query param:** `?x-vercel-protection-bypass=<secret>` (for services that can't set headers)
- Optional: add `x-vercel-set-bypass-cookie: true` to propagate bypass as a cookie for browser sessions

The bypass secret is a per-project token set in project Settings → Deployment Protection.
It is also available as system env var `VERCEL_AUTOMATION_BYPASS_SECRET`.

**What the bypass overrides:** Password Protection, Vercel Authentication, Trusted IPs,
Firewall-blocked requests, Bot protection challenges.
**What the bypass does NOT override:** Active DDoS mitigation IP blocks, rate limits
during detected attacks, security challenges triggered by attack patterns.

## WebHound scanner implications

1. Hitting a protected Vercel preview URL without bypass → 302 redirect to auth page.
   WebHound should detect `Location: https://vercel.com/...` redirects as deployment protection.
2. If scanning a Vercel deployment and encountering auth walls, look for:
   - `x-vercel-id` response header (present on all Vercel responses)
   - `server: Vercel` header
   - Redirect to `vercel.com/login` or password form
3. For legitimate scanning, configure `x-vercel-protection-bypass` header.

**Related:** [[vercel-firewall]], [[vercel-preview-deployments]].
