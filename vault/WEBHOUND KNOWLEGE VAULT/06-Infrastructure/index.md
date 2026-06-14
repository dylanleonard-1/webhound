---
title: Infrastructure
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 06 — Infrastructure

## Components

| Service | Role | Status |
|---------|------|--------|
| Railway | Backend API + PostgreSQL host | ✅ Production |
| Vercel | Frontend host + WAF + Edge CDN | ✅ Production |
| Cloudflare | DNS + WAF + CDN for scanned sites | ✅ Production |
| PostgreSQL | Primary database | ✅ Production |
| Redis | Rate limiting / session cache | ✅ Production (inferred) |
| Resend | Transactional email | ✅ Production |
| Stripe | Payment processing | ✅ Production |
| Google OAuth | Social login | ✅ Production |
| GitHub OAuth | Social login | ✅ Production |
| Ollama | Local LLM for AI Brain | ✅ Local Dev |
| Neo4j | Graph DB for AI Brain | ✅ Local Dev (Docker/WSL2) |
| Docker | Container runtime | ⚠️ Win pipe offline — WSL2 workaround |

## Detail Notes

- [[06-Infrastructure/Railway|Railway]] — backend + DB hosting
- [[06-Infrastructure/Vercel|Vercel]] — frontend + WAF bypass issue
- [[06-Infrastructure/Cloudflare|Cloudflare]] — provider integration + scanner access

## See Also

- [[04-Backend/index|Backend]] · [[03-Frontend/index|Frontend]] · [[10-Providers/index|Providers]]
- [[19-Monitoring/index|Monitoring]] · [[22-Operations/index|Operations]]
- [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #infrastructure #index
