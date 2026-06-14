---
title: Ollama
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 17 — Ollama

## Status: LIVE

| Metric | Value |
|--------|-------|
| Version | 0.30.6 |
| API | http://localhost:11434 |
| OpenAI-compat | http://localhost:11434/v1 |
| Models | phi3:mini (3.8B, Q4_0, 2.2GB) + nomic-embed-text (0.3GB) |
| Performance | ~17 tok/s (CPU), ~60s/chunk for LightRAG |
| Cloud API used | No |

## Models

### phi3:mini
- **Role**: LLM for entity extraction (LightRAG) + episode seeding (Graphiti)
- **Size**: 3.8B parameters, Q4_0 quantization, 2.2 GB
- **Performance**: 17 tok/s on CPU, 338s per LightRAG chunk (Phase 8C real run)
- **Context**: 131072 tokens
- **Quality note**: Produces some hallucinated entities on complex corpus chunks

### nomic-embed-text
- **Role**: 768-dim embeddings for Graphiti (nomic-embed-text via Ollama OpenAI-compat)
- **Size**: ~0.3 GB
- **Dim**: 768

## Usage in AI Brain

| Component | Uses Ollama | Model |
|-----------|-------------|-------|
| LightRAG indexing | ✅ | phi3:mini (LLM) + all-MiniLM-L6-v2 (embed, NOT Ollama) |
| Graphiti seeding | ✅ | phi3:mini (LLM) + nomic-embed-text (embed) |
| WADE retrieval | ✅ (future) | phi3:mini |

## Install

```bash
winget install Ollama.Ollama --accept-package-agreements --silent
ollama pull phi3:mini
ollama pull nomic-embed-text
```

## Stop

```powershell
Get-Process ollama -ErrorAction SilentlyContinue | Stop-Process -Force
# OR: Stop-Service ollama -ErrorAction SilentlyContinue
```

## See Also

- [[14-LightRAG/index|LightRAG]] · [[15-Graphiti/index|Graphiti]] · [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #ollama #index
