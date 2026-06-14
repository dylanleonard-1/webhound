---
title: System Map
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# System Map

Full WebHound platform — all components and their relationships.

```
┌─────────────────────────────────────────────────────────────────┐
│                         USERS                                   │
│              Security Engineers / DevSecOps / Owners            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                    ┌───────▼────────┐
                    │   FRONTEND     │
                    │ Next.js/Vercel │
                    └───────┬────────┘
                            │ HTTPS / REST
                    ┌───────▼────────┐
                    │  BACKEND API   │
                    │ FastAPI/Railway │
                    └───┬───┬───┬───┘
                        │   │   │
           ┌────────────┘   │   └───────────────┐
           ▼                ▼                   ▼
    ┌──────────┐    ┌──────────────┐    ┌──────────────┐
    │PostgreSQL│    │   SCANNER    │    │   PROVIDERS  │
    │(Railway) │    │ 14 modules   │    │ Cloudflare   │
    └──────────┘    │ + WADE layer │    │ Vercel       │
                    └──────┬───────┘    └──────────────┘
                           │
                    ┌──────▼───────┐
                    │  AI BRAIN    │
                    │ (Local Dev)  │
                    ├──────────────┤
                    │ LightRAG     │←── Ollama (phi3:mini)
                    │ Graphiti     │←── Neo4j (bolt:7687)
                    │ HybridRetrvl │←── Embeddings (local)
                    │ Knowledge DB │←── 487 records/1161 chunks
                    └──────────────┘
```

## Component Links

| Component | Section |
|-----------|---------|
| Frontend | [[03-Frontend/index]] |
| Backend API | [[04-Backend/index]] |
| Database | [[05-Database/index]] |
| Infrastructure | [[06-Infrastructure/index]] |
| Scanner | [[07-Scanner/index]] |
| WADE | [[08-WADE/index]] |
| Providers | [[10-Providers/index]] |
| AI Brain | [[13-Knowledge Corpus/index]] + [[14-LightRAG/index]] + [[15-Graphiti/index]] + [[16-Neo4j/index]] |

#webhound #maps #system
