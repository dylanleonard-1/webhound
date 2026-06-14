---
title: Database
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 05 — Database

## Stack

| Component | Detail |
|-----------|--------|
| Engine | PostgreSQL |
| Host | Railway |
| ORM | SQLAlchemy (async) |
| Migrations | Alembic (`apps/api/migrations/versions/`) |
| Sessions | `AsyncSessionLocal` (connection pool) |

## Entity Overview

→ [[05-Database/Database Entity Map|Full Entity Map]]

Core entities: User, Org, Website, WebsiteGroup, ScanJob, ScanResult, Finding, GroupedFinding, ScanDelta, Baseline, Subscription, Provider (Connection + Profile), ThreatIndicator, Suppression, Report, Notification, Alert, Incident, AuditLog, TrustedAccess.

## Key Relationships

```
Org → Users (many)
Org → Websites (many) → WebsiteGroups
Website → ScanSchedules → ScanJobs → ScanResults → Findings
ScanResult → ScanDelta (vs prior)
Org → Subscriptions → tier-gated features
Org → ProviderConnections (Cloudflare, Vercel)
Finding → Suppression (optional)
Website → TrustedAccessProfile (scanner allowlist)
```

## Migration History

Early migrations in `apps/api/migrations/versions/`:
- `0001_initial_schema` — baseline tables
- `0004_add_notifications`
- `0007_add_grouped_finding_description`
- `0030_suppressions`
- `0035_provider_profiles`
- `0037_trusted_access_profiles`

## See Also

- [[05-Database/Database Entity Map|Entity Map]] · [[04-Backend/index|Backend]]
- [[07-Scanner/index|Scanner]] · [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #database #index
