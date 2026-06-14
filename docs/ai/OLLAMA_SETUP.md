# Ollama Local LLM Setup — WebHound AI Brain

Ollama runs LLMs locally. WebHound uses it to activate:
- **Graphiti** memory seeding (entity/relationship extraction from episodes)
- **LightRAG** full graph extraction (entities + relationships from knowledge chunks)

**No cloud AI APIs are used. All inference is local.**

---

## Installation

### Option A — Native Windows (Recommended)

1. Download the installer from [ollama.com/download](https://ollama.com/download)
2. Run `OllamaSetup.exe`
3. Ollama starts automatically at `http://localhost:11434`

Verify: open a terminal and run `ollama list`

### Option B — Docker (requires Docker Desktop with WSL2 backend)

```bash
docker compose -f docker-compose.ai-brain.yml up -d ollama
```

This starts Ollama at `http://localhost:11434` inside Docker.

### Option C — WSL2 (Windows Subsystem for Linux)

```bash
# Inside WSL2
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
```

---

## Recommended Models

| Model | Size | Use Case | Command |
|-------|------|----------|---------|
| `llama3.2` | ~2GB | Graphiti entity extraction | `ollama pull llama3.2` |
| `nomic-embed-text` | ~280MB | LightRAG graph embeddings | `ollama pull nomic-embed-text` |
| `llama3.2:1b` | ~1.3GB | Faster, less accurate option | `ollama pull llama3.2:1b` |

> **Minimum**: `llama3.2` + `nomic-embed-text` (~2.3GB total)

---

## Pull Models

```bash
# Native install
ollama pull llama3.2
ollama pull nomic-embed-text

# Docker install
docker exec webhound-ollama-dev ollama pull llama3.2
docker exec webhound-ollama-dev ollama pull nomic-embed-text
```

---

## Verify Ollama is Running

```bash
# Should return JSON with model list
curl http://localhost:11434/api/tags

# Or use the check script
.venv-api/Scripts/python scripts/ai/graphiti_runtime_check.py
.venv-api/Scripts/python scripts/ai/lightrag_graph_runtime_check.py
```

---

## API Details

Ollama exposes an OpenAI-compatible REST API:

| Endpoint | Description |
|----------|-------------|
| `http://localhost:11434/api/tags` | List installed models |
| `http://localhost:11434/v1/chat/completions` | OpenAI-compatible chat |
| `http://localhost:11434/v1/embeddings` | OpenAI-compatible embeddings |

WebHound uses the `/v1` endpoints (OpenAI-compatible) so Graphiti's `OpenAIClient`
can talk to Ollama without code changes — just swap the `base_url`.

---

## Activate Full Brain Runtime

Once Ollama is running with models pulled:

```bash
# 1. Start Neo4j (also in docker-compose.ai-brain.yml)
docker compose -f docker-compose.ai-brain.yml up -d

# 2. Seed Graphiti memories (13 episodes)
.venv-api/Scripts/python scripts/ai/load_graphiti_seed_memories.py --live

# 3. Re-index LightRAG with graph extraction enabled
# (Edit build_lightrag_index.py to use ollama_model_complete instead of stub)
.venv-api/Scripts/python scripts/ai/build_lightrag_index.py

# 4. Check brain health
.venv-api/Scripts/python scripts/ai/check_brain_health.py
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ollama: command not found` | Add Ollama to PATH or use Docker option |
| Port 11434 in use | Another Ollama instance running — `ollama ps` to check |
| Model pull slow | Models are 1-4GB — wait for download to finish |
| WSL2 networking | Use `host.docker.internal:11434` from Docker containers |
| Out of memory | Use smaller model: `llama3.2:1b` instead of `llama3.2` |
