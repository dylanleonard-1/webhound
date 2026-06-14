---
title: Product Overview
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 02 — Product

## User Journey

```
User registers → verifies domain ownership → schedules scan
  → scanner runs 14 analysis modules → findings collected
  → WADE applies confidence scoring + FP reduction
  → findings grouped + surfaced in UI
  → reports generated → notifications sent
```

## Core Features

| Feature | Description | Links |
|---------|-------------|-------|
| Domain scanning | Automated multi-module analysis | [[07-Scanner/index]] |
| WADE scoring | Confidence + FP reduction layer | [[08-WADE/index]] |
| Findings | Grouped, severity-ranked, with remediation | [[05-Database/Database Entity Map]] |
| Baselines | Snapshot diff across scans | [[04-Backend/API Overview]] |
| Suppressions | User-managed FP rules | [[08-WADE/index]] |
| Reports | PDF/JSON findings export | [[23-Reports/index]] |
| Subscriptions | Tiered access control | [[21-Billing/index]] |
| Providers | Cloudflare, Vercel integration | [[10-Providers/index]] |
| Portfolio | Multi-domain dashboard | [[04-Backend/API Overview]] |
| Threat Intel | VirusTotal + CDN/WAF reputation | [[09-Threat Intelligence/index]] |

## Onboarding Flow

1. Register (email/OAuth) → `apps/api/routers/auth.py`, `oauth.py`
2. Add domain → `apps/api/routers/websites.py`
3. Verify ownership → `apps/api/services/verification.py`
4. Configure scan schedule → `apps/api/routers/scan_schedules.py`
5. Run scan → `apps/api/services/scan_jobs.py`
6. Review findings → `apps/api/routers/scan_results.py`

## See Also

- [[01-Company/index|Company]] · [[03-Frontend/index|Frontend]] · [[04-Backend/index|Backend]]
- [[WEBHOUND_BRAIN_DASHBOARD|Brain Dashboard]]

#webhound #product #index
