---
title: Backend
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 04 — Backend

## Stack

| Component | Technology |
|-----------|-----------|
| Framework | FastAPI (Python) |
| Deployment | Railway |
| Database | PostgreSQL via SQLAlchemy (async) |
| Auth | JWT + OAuth2 |
| Migrations | Alembic (`apps/api/migrations/`) |
| Rate limiting | Custom middleware (`rate_limit.py`) |
| Observability | OpenTelemetry (`telemetry.py`, `observability.py`) |

## Router Map

| Router | Path | Purpose |
|--------|------|---------|
| auth | `/auth` | Email login, registration, JWT |
| oauth | `/oauth` | Google + GitHub OAuth |
| websites | `/websites` | Domain CRUD |
| scan_jobs | `/scans` | Trigger + monitor scans |
| scan_results | `/results` | Findings retrieval |
| scan_schedules | `/schedules` | Cron-based scan scheduling |
| baselines | `/baselines` | Snapshot comparison |
| portfolio | `/portfolio` | Multi-domain aggregation |
| providers | `/providers` | Cloudflare / Vercel connections |
| cloudflare | `/cloudflare` | CF-specific ops |
| vercel | `/vercel` | Vercel-specific ops |
| billing | `/billing` | Subscription management |
| notifications | `/notifications` | Alerts delivery |
| suppressions | `/suppressions` | FP suppression rules |
| audit | `/audit` | Audit log access |
| trusted_access | `/trusted-access` | Scanner allowlisting |
| health | `/health` | Service health check |
| public_scan | `/public` | Unauthed scan trigger |

## Key Services

- `services/scan_jobs.py` — orchestrate scan pipeline
- `services/wade_correlation.py` — cross-scan behavioural anomalies
- `services/result_persistence.py` — store findings
- `services/threat_intel.py` — TI enrichment
- `services/engines.py` — scanner engine dispatch
- `services/provider_access_registry.py` — provider allowlist management

## See Also

- [[04-Backend/API Overview|API Overview]] · [[05-Database/index|Database]]
- [[07-Scanner/index|Scanner]] · [[08-WADE/index|WADE]]
- [[06-Infrastructure/index|Infrastructure]] · [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #backend #index
