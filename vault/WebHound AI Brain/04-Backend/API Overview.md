---
title: API Overview
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# API Overview

FastAPI application at `apps/api/main.py`.

## Middleware Stack (in order)

1. `RequestIdMiddleware` — injects `X-Request-ID` header
2. `RateLimitMiddleware` — per-IP rate throttling
3. `MaintenanceModeMiddleware` — toggleable maintenance mode
4. `SecurityHeadersMiddleware` — CSP, HSTS, etc.
5. `CORSMiddleware` — frontend origin allowlist

## Authentication Flow

```
Request → JWT verify (auth.py) → user resolved → route handler
       → OAuth2 (oauth.py) → provider token → user upsert
```

## Scan Pipeline

```
POST /scans → scan_jobs.py → engine dispatch (engines.py)
           → scanner analysis (14 modules)
           → result_persistence.py → findings stored
           → wade_correlation.py → cross-scan anomalies
           → notifications.py → alerts sent
```

## Database Sessions

- Async SQLAlchemy via `AsyncSessionLocal`
- Connection pooling configured in `database.py`
- Session injected via FastAPI `Depends`

## Config

- `apps/api/config.py` — `get_settings()` — reads env vars
- No secrets in code; all via env

## Platform Modules

- `apps/api/platform/health/` — health probes
- `apps/api/platform/jobs/` — background job runners
- `apps/api/platform/observability/` — tracing
- `apps/api/platform/security/` — security utilities
- `apps/api/platform/onboarding/` — wizard logic

## See Also

- [[04-Backend/index|Backend Index]] · [[05-Database/Database Entity Map|Entity Map]]
- [[07-Scanner/index|Scanner]] · [[08-WADE/index|WADE]]

#webhound #backend #api
