"""Phase 8C-INFRA: Graphiti runtime status check.

Checks whether Graphiti can be initialized and used for memory operations.
Requirements: graphiti-core installed, Neo4j running, Ollama running.

Status levels:
  LIVE              — Neo4j + Ollama + model available, ready to seed
  PARTIAL           — prereqs partially met (e.g. port open, no model)
  CONFIGURED_PENDING — installed, episode schema seeded, awaiting Neo4j/LLM
  NOT_INSTALLED     — graphiti-core not found

Run: .venv-api/Scripts/python scripts/ai/graphiti_runtime_check.py
"""
from __future__ import annotations
import json
import socket
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RESULTS_MD = ROOT / "docs" / "ai" / "GRAPHITI_RUNTIME_RESULTS.md"
RESULTS_JSON = ROOT / "docs" / "ai" / "graphiti_runtime.json"
SCHEMA_PATH = ROOT / "corpus" / "exports" / "graphiti_episode_schema.json"
NOW = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def check_graphiti_install() -> dict:
    try:
        import graphiti_core
        return {"installed": True, "version": getattr(graphiti_core, "__version__", "?")}
    except ImportError as e:
        return {"installed": False, "error": str(e)}


def _port_open(host: str, port: int) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=1)
        s.close()
        return True
    except OSError:
        return False


def check_ollama() -> dict:
    if not _port_open("localhost", 11434):
        return {"reachable": False, "models": []}
    try:
        resp = urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2)
        data = json.loads(resp.read())
        models = [m["name"] for m in data.get("models", [])]
        return {"reachable": True, "models": models}
    except Exception:
        return {"reachable": True, "models": []}


def check_episode_schema() -> dict:
    if not SCHEMA_PATH.exists():
        return {"exists": False, "episode_count": 0}
    data = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return {
        "exists": True,
        "episode_count": len(data.get("episodes", [])),
        "memory_types": data.get("memory_types", []),
    }


def determine_status(g: dict, neo4j: bool, ollama: dict) -> str:
    if not g.get("installed"):
        return "NOT_INSTALLED"
    if neo4j and ollama.get("reachable") and ollama.get("models"):
        return "LIVE"
    if neo4j or ollama.get("reachable"):
        return "PARTIAL"
    return "CONFIGURED_PENDING"


def write_report(status: str, graphiti: dict, neo4j: bool, ollama: dict, schema: dict) -> None:
    neo4j_s = "LIVE" if neo4j else "OFFLINE"
    oll_s = "LIVE" if ollama.get("reachable") else "OFFLINE"
    models = ", ".join(ollama.get("models", [])) or "none pulled"
    ep_count = schema.get("episode_count", 0)
    version = graphiti.get("version", "?")
    installed_label = f"INSTALLED v{version}" if graphiti.get("installed") else "NOT INSTALLED"

    blockers = []
    if not neo4j:
        blockers.append(
            "**Neo4j**: Start with `docker compose -f docker-compose.ai-brain.yml up -d`"
        )
    if not ollama.get("reachable"):
        blockers.append(
            "**Ollama**: Install and start — see `docs/ai/OLLAMA_SETUP.md`"
        )
    elif not ollama.get("models"):
        blockers.append(
            "**Ollama model**: Pull a model: `ollama pull llama3.2`"
        )

    status_desc = {
        "LIVE": "All prerequisites met — ready to seed memories.",
        "PARTIAL": "Some prerequisites available — check blockers below.",
        "CONFIGURED_PENDING": (
            "graphiti-core installed, episode schema seeded. "
            "Waiting for Neo4j + Ollama LLM to activate."
        ),
        "NOT_INSTALLED": "graphiti-core not installed — pip install graphiti-core",
    }.get(status, status)

    report = f"""<!-- WEBHOUND-GENERATED -->
# Graphiti Runtime Results — Phase 8C-INFRA

**Date:** {NOW}
**Status:** {status}

## Prerequisites

| Component | Status | Detail |
|-----------|--------|--------|
| graphiti-core | {installed_label} | pip install graphiti-core |
| Neo4j (bolt:7687) | {neo4j_s} | docker-compose.ai-brain.yml |
| Ollama (port:11434) | {oll_s} | docs/ai/OLLAMA_SETUP.md |
| Ollama models | {models} | ollama pull llama3.2 |
| Episode schema | {ep_count} episodes | corpus/exports/graphiti_episode_schema.json |

## Status: {status}

{status_desc}

## Blockers

{chr(10).join(f"{i+1}. {b}" for i, b in enumerate(blockers)) if blockers else "None — ready to seed memories."}

## Activation

```bash
# 1. Start Neo4j + Ollama (Docker required)
docker compose -f docker-compose.ai-brain.yml up -d

# 2. Wait for Neo4j to be healthy, then pull a model
docker exec webhound-ollama-dev ollama pull llama3.2
docker exec webhound-ollama-dev ollama pull nomic-embed-text

# 3. Seed {ep_count} episodes into Graphiti
.venv-api/Scripts/python scripts/ai/load_graphiti_seed_memories.py --live
```

## Ollama Integration

Graphiti uses the `OpenAIClient` pointed to Ollama's OpenAI-compatible API:
- LLM base URL: `http://localhost:11434/v1`
- LLM model: `llama3.2` (or any Ollama model)
- Embedder: `nomic-embed-text` via Ollama API (768-dim)

No cloud APIs used. All inference is local.
"""
    RESULTS_MD.write_text(report, encoding="utf-8")
    print(f"Wrote {RESULTS_MD.relative_to(ROOT)}")


def main() -> None:
    graphiti = check_graphiti_install()
    neo4j = _port_open("localhost", 7687)
    ollama = check_ollama()
    schema = check_episode_schema()
    status = determine_status(graphiti, neo4j, ollama)

    result = {
        "checked_at": NOW,
        "status": status,
        "graphiti": graphiti,
        "neo4j_live": neo4j,
        "ollama": ollama,
        "episode_schema": schema,
    }
    RESULTS_JSON.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Wrote {RESULTS_JSON.relative_to(ROOT)}")
    write_report(status, graphiti, neo4j, ollama, schema)
    print(f"Graphiti status: {status}")


if __name__ == "__main__":
    main()
