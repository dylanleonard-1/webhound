---
title: Frontend
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 03 — Frontend

## Stack

| Component | Technology |
|-----------|-----------|
| Framework | Next.js (App Router) |
| Language | TypeScript |
| Deployment | Vercel |
| Auth UI | Email/password + Google OAuth + GitHub OAuth |
| State | React contexts (`apps/web/contexts/`) |
| Styling | Tailwind CSS (inferred from app structure) |

## Key App Directories

```
apps/web/
  app/           — Next.js App Router pages
  components/    — Shared UI components
  lib/           — Client utilities
  contexts/      — React context providers
  providers/     — Provider wrappers
```

## Page Areas (inferred from routers)

- `/auth` — Login, register, OAuth callback
- `/dashboard` — Portfolio overview
- `/domains` — Domain management
- `/scans` — Scan jobs + results
- `/findings` — Grouped finding explorer
- `/reports` — Report download
- `/settings` — Account, subscriptions, suppressions
- `/onboarding` — Setup wizard
- `/billing` — Subscription management

## Infra

- **Host**: Vercel (production + preview deployments)
- **Domain**: `webhoundsecurity.com` (inferred)
- **WAF**: Vercel Firewall (scanner bypass needed — see [[06-Infrastructure/Vercel]])
- **CDN**: Vercel Edge Network

## See Also

- [[06-Infrastructure/Vercel|Vercel Infra]] · [[20-Authentication/index|Auth]] · [[04-Backend/index|Backend]]
- [[02-Product/index|Product]] · [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #frontend #index
