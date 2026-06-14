"""Phase 8C-INFRA: Seed episodes into Graphiti knowledge graph.

Loads the 13 pre-defined episodes from the schema file into Graphiti
using a local Ollama LLM (OpenAI-compatible API at localhost:11434/v1).

Requires:
  - Neo4j running at bolt://localhost:7687
  - Ollama running at http://localhost:11434 with a model pulled
  - graphiti-core and neo4j Python driver installed

Run: .venv-api/Scripts/python scripts/ai/load_graphiti_seed_memories.py [--live]
     Default: dry-run only (validates prereqs + episode count, no Neo4j writes)

NO cloud APIs — uses Ollama local LLM only. LOCAL DEV ONLY.
"""
from __future__ import annotations
import asyncio
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCHEMA_PATH = ROOT / "corpus" / "exports" / "graphiti_episode_schema.json"
# LOCAL DEV ONLY credentials — change before any non-local use
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "webhound-brain-local-dev"
OLLAMA_BASE_URL = "http://localhost:11434/v1"
OLLAMA_LLM_MODEL = "llama3.2"
OLLAMA_EMBED_MODEL = "nomic-embed-text"
OLLAMA_EMBED_DIM = 768
NOW = datetime.now(timezone.utc)
DRY_RUN = "--live" not in sys.argv


def _port_open(host: str, port: int) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=2)
        s.close()
        return True
    except OSError:
        return False


def check_prereqs() -> dict[str, dict]:
    result: dict[str, dict] = {}

    try:
        import graphiti_core
        result["graphiti"] = {
            "ok": True, "version": getattr(graphiti_core, "__version__", "?")
        }
    except ImportError:
        result["graphiti"] = {"ok": False, "error": "pip install graphiti-core"}

    result["neo4j_port"] = {
        "ok": _port_open("localhost", 7687),
        "error": "Neo4j not running — docker compose -f docker-compose.ai-brain.yml up -d",
    } if not _port_open("localhost", 7687) else {"ok": True}

    result["ollama_port"] = {
        "ok": _port_open("localhost", 11434),
        "error": "Ollama not running — see docs/ai/OLLAMA_SETUP.md",
    } if not _port_open("localhost", 11434) else {"ok": True}

    return result


def load_episodes() -> list[dict]:
    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(f"Episode schema not found: {SCHEMA_PATH}")
    data = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return data.get("episodes", [])


async def seed_graphiti(episodes: list[dict]) -> dict:
    from graphiti_core import Graphiti
    from graphiti_core.llm_client import OpenAIClient
    from graphiti_core.llm_client.config import LLMConfig
    from graphiti_core.embedder.openai import OpenAIEmbedder, OpenAIEmbedderConfig

    llm_config = LLMConfig(
        api_key="ollama",
        model=OLLAMA_LLM_MODEL,
        base_url=OLLAMA_BASE_URL,
    )
    llm_client = OpenAIClient(config=llm_config)

    embedder_config = OpenAIEmbedderConfig(
        api_key="ollama",
        embedding_model=OLLAMA_EMBED_MODEL,
        base_url=OLLAMA_BASE_URL,
        embedding_dim=OLLAMA_EMBED_DIM,
    )
    embedder = OpenAIEmbedder(config=embedder_config)

    graphiti = Graphiti(
        uri=NEO4J_URI,
        user=NEO4J_USER,
        password=NEO4J_PASS,
        llm_client=llm_client,
        embedder=embedder,
    )
    await graphiti.build_indices_and_constraints()

    loaded = 0
    errors = []
    for ep in episodes:
        schema = ep.get("graphiti_schema", {})
        try:
            from graphiti_core.nodes import EpisodeType
            await graphiti.add_episode(
                name=schema.get("name", ep["episode_id"]),
                episode_body=schema.get("episode_body", ep.get("content", "")),
                source=EpisodeType.text,
                source_description=schema.get("source_description", "WebHound Brain"),
                reference_time=NOW,
                group_id=schema.get("group_id", "webhound-brain"),
            )
            loaded += 1
            print(f"  [{loaded}/{len(episodes)}] {ep['episode_id']}")
        except Exception as e:
            errors.append({"episode_id": ep.get("episode_id"), "error": str(e)[:120]})
            print(f"  ERROR {ep.get('episode_id')}: {e}")

    await graphiti.close()
    return {"loaded": loaded, "errors": errors, "total": len(episodes)}


def main() -> None:
    mode = "DRY RUN" if DRY_RUN else "LIVE"
    print(f"Graphiti seed loader [{mode}]")

    prereqs = check_prereqs()
    all_ok = all(v.get("ok") for v in prereqs.values())

    print("\nPrerequisites:")
    for name, status in prereqs.items():
        icon = "OK  " if status.get("ok") else "FAIL"
        print(f"  {icon} {name:<20} {status.get('error', '')}")

    episodes = load_episodes()
    print(f"\nEpisode schema: {len(episodes)} episodes ready")

    if DRY_RUN:
        print("\nDry run complete — pass --live to seed into Graphiti.")
        print("Requires: Neo4j + Ollama running, model pulled.")
        return

    if not all_ok:
        print("\nPrerequisites not met — see blockers above. Aborting.")
        sys.exit(1)

    print(f"\nLoading {len(episodes)} episodes into Graphiti (Ollama LLM: {OLLAMA_LLM_MODEL})...")
    result = asyncio.run(seed_graphiti(episodes))

    print(f"\nResult: {result['loaded']}/{result['total']} episodes loaded")
    if result.get("errors"):
        print(f"Errors ({len(result['errors'])}):")
        for e in result["errors"]:
            print(f"  {e['episode_id']}: {e['error']}")


if __name__ == "__main__":
    main()
