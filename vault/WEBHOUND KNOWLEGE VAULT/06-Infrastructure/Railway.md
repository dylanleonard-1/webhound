---
title: Railway
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Railway

## Role

Hosts the WebHound backend API (FastAPI) and the primary PostgreSQL database.

## Components Hosted

| Service | Type |
|---------|------|
| WebHound API | FastAPI Python app |
| PostgreSQL | Managed database |

## Key Facts

- Environment variables managed in Railway dashboard (never in code)
- Railway CLI linked for logs, env vars, redeploys (see memory: `railway-link.md`)
- Deployments triggered by GitHub push to `main`
- Health endpoint: `GET /health` → `apps/api/routers/health.py`

## Scanner Relevance

The WebHound scanner runs from the Railway-hosted API. Provider access (Cloudflare, Vercel) uses token credentials stored as Railway env vars and referenced via `EncryptedSecret` model.

## See Also

- [[06-Infrastructure/index|Infrastructure]] · [[04-Backend/index|Backend]]
- [[05-Database/index|Database]] · [[10-Providers/index|Providers]]

#webhound #infrastructure #railway
