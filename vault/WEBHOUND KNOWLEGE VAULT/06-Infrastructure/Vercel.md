---
title: Vercel
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Vercel

## Role

Hosts the WebHound Next.js frontend. Also used as a **scanned provider** — WebHound can detect and bypass Vercel Deployment Protection on customer sites.

## Two Distinct Uses

| Use | Description |
|-----|-------------|
| Frontend host | WebHound's own Next.js app runs on Vercel |
| Scanner provider | Detects + bypasses Vercel WAF on scanned customer sites |

## Frontend Hosting

- Next.js App Router on Vercel
- Preview deployments on every PR
- Production at `main` branch
- CI check: `Vercel` + `Vercel Preview Comments`

## Provider Integration (Scanner)

- Uses a **Classic Integration** (slug install URL), NOT Sign-in-with-Vercel
- Env var: `VERCEL_INTEGRATION_SLUG`
- Scanner WAF bypass automation: blocked by "Seawall Config not found" until project Firewall enabled once in dashboard
- Services: `apps/api/services/vercel.py`, `vercel_rules.py`, `vercel_scanner_access.py`, `vercel_scanner_state.py`, `vercel_firewall_bypass.md` (memory)
- Router: `apps/api/routers/vercel.py`

## Known Issues

- Seawall config must be initialized in Vercel Dashboard before scanner bypass works
- WAF bypass automation requires project-level Firewall to be enabled first

## See Also

- [[06-Infrastructure/index|Infrastructure]] · [[10-Providers/index|Providers]]
- [[03-Frontend/index|Frontend]] · [[07-Scanner/index|Scanner]]

#webhound #infrastructure #vercel
