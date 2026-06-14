---
title: WebHound Brain Dashboard
status: active
phase: 8G
created: 2026-06-14
---
<!-- WEBHOUND-GENERATED -->

# WebHound Brain Dashboard

Central status table for the entire WebHound platform. Updated by Phase 8G.

## Platform Health

| Layer | Component | Status | Detail |
|-------|-----------|--------|--------|
| Knowledge | Corpus | ✅ Healthy | 487 records · 1161 chunks |
| Knowledge | Embeddings | ✅ Live | 1161 embeddings · 1741 KB |
| Knowledge | Hybrid Retrieval | ✅ Live | lexical mode · 3 hits/query |
| AI Brain | LightRAG | ✅ LIVE_FULL | 30 chunks indexed · 19 entities · phi3:mini |
| AI Brain | Graphiti | ✅ Ready | 13 episodes · 19 Episodic nodes · 27 Entity nodes |
| AI Brain | Neo4j | ✅ Live | 172 nodes · 191 rels · WSL2 Docker |
| AI Brain | Ollama | ✅ Live | phi3:mini + nomic-embed-text |
| AI Brain | Graphify | ✅ Live (local) | 126 nodes · 263 edges |
| AI Brain | Docker (Windows) | ⚠️ Offline | WSL2 workaround active |
| Platform | WADE Retrieval | ✅ Live | Brain v8B · 22 finding types |
| Platform | Scanner | ✅ Live | 14 analysis modules |
| Platform | Backend API | ✅ Production | FastAPI · Railway |
| Platform | Frontend | ✅ Production | Next.js · Vercel |
| Platform | Database | ✅ Production | PostgreSQL · Railway |

## Latest Phase

**Phase 8C-INFRA-LIVE** (merged PR #17 — commit `e009b910`) — All AI brain components brought live locally.

## Pending Phases

| Phase | Goal |
|-------|------|
| 8G | Full vault sync — this phase |
| 8D | Threat intel source expansion |
| 8E | Provider doc enrichment |
| 9A | WADE graph-enhanced retrieval |
| 9B | Cross-scan correlation via Neo4j |

## Platform Navigation

### Core Product
- [[01-Company/index|Company]] · [[02-Product/index|Product]] · [[24-Roadmap/index|Roadmap]]
- [[03-Frontend/index|Frontend]] · [[04-Backend/index|Backend]] · [[05-Database/index|Database]]
- [[06-Infrastructure/index|Infrastructure]] · [[19-Monitoring/index|Monitoring]]
- [[20-Authentication/index|Auth]] · [[21-Billing/index|Billing]]

### Scanner & Intelligence
- [[07-Scanner/index|Scanner]] · [[08-WADE/index|WADE]] · [[09-Threat Intelligence/index|Threat Intel]]
- [[10-Providers/index|Providers]] · [[12-Taxonomy/index|Taxonomy]]

### AI Brain
- [[13-Knowledge Corpus/index|Knowledge Corpus]] · [[14-LightRAG/index|LightRAG]]
- [[15-Graphiti/index|Graphiti]] · [[16-Neo4j/index|Neo4j]] · [[17-Ollama/index|Ollama]]
- [[18-Graphify/index|Graphify]] · [[11-External Tools/index|External Tools]]

### Maps & Records
- [[99-Maps/index|Maps]] · [[23-Reports/index|Reports]] · [[25-Decisions/index|Decisions]]

### Legacy Sections (Phase 8A)
- [[00-Maps/index|00-Maps]] · [[01-Architecture/index|Architecture]]
- [[02-Scanner Engines/index|Scanner Engines]] · [[03-WADE/index|WADE (8A)]]
- [[04-Knowledge Corpus/index|Knowledge Corpus (8A)]] · [[99-Graphify/index|Graphify (8A)]]

#webhound #dashboard #phase-8g
