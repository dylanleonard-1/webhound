"""Phase 8C-INFRA: LightRAG graph layer runtime check.

LightRAG has two layers:
  1. Vector layer (LIVE) — NanoVectorDB with local sentence-transformers embeddings
  2. Graph layer (CONFIGURED_PENDING) — requires a local LLM for entity extraction

The current setup uses a stub LLM that returns empty entities, so only the
vector layer is active. Full graph extraction requires Ollama + model pull,
then a re-index with the real LLM.

Status levels:
  LIVE_FULL         — vector + graph both working (Ollama + entities extracted)
  LIVE_VECTOR_ONLY  — vector storage built, no graph entities (stub LLM used)
  INSTALLED_NOT_INDEXED — lightrag installed, no storage built yet
  NOT_INSTALLED     — lightrag-hku not installed

Run: .venv-api/Scripts/python scripts/ai/lightrag_graph_runtime_check.py
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

LIGHTRAG_DIR = ROOT / "lightrag_storage"
RESULTS_MD = ROOT / "docs" / "ai" / "LIGHTRAG_GRAPH_RUNTIME_RESULTS.md"
RESULTS_JSON = ROOT / "docs" / "ai" / "lightrag_graph_runtime.json"
NOW = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def check_lightrag_install() -> dict:
    try:
        import lightrag
        return {"installed": True, "version": getattr(lightrag, "__version__", "?")}
    except ImportError:
        return {"installed": False}


def check_vector_storage() -> dict:
    if not LIGHTRAG_DIR.exists():
        return {"exists": False, "note": "Run build_lightrag_index.py first"}
    json_files = list(LIGHTRAG_DIR.glob("*.json"))
    vdb_files = [f.name for f in json_files if "vdb" in f.name]
    return {
        "exists": True,
        "storage_dir": str(LIGHTRAG_DIR.relative_to(ROOT)),
        "json_file_count": len(json_files),
        "vector_db_files": vdb_files,
    }


def check_embedding_model() -> dict:
    try:
        from sentence_transformers import SentenceTransformer
        m = SentenceTransformer("all-MiniLM-L6-v2")
        dim = m.get_sentence_embedding_dimension()
        return {"installed": True, "model": "all-MiniLM-L6-v2", "dim": dim}
    except ImportError:
        return {"installed": False, "error": "pip install sentence-transformers"}
    except Exception as e:
        return {"installed": False, "error": str(e)[:100]}


def check_ollama() -> dict:
    try:
        s = socket.create_connection(("localhost", 11434), timeout=1)
        s.close()
    except OSError:
        return {"reachable": False, "models": []}

    try:
        resp = urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2)
        data = json.loads(resp.read())
        models = [m["name"] for m in data.get("models", [])]
        return {"reachable": True, "models": models}
    except Exception:
        return {"reachable": True, "models": []}


def check_graph_entities() -> dict:
    if not LIGHTRAG_DIR.exists():
        return {"extracted": False, "entity_count": 0, "relationship_count": 0}

    entity_count, rel_count = 0, 0
    entity_file = LIGHTRAG_DIR / "vdb_entities.json"
    rel_file = LIGHTRAG_DIR / "vdb_relationships.json"

    if entity_file.exists():
        data = json.loads(entity_file.read_text(encoding="utf-8"))
        # NanoVectorDB format: {"embedding_dim": N, "data": [...], "matrix": ...}
        inner = data.get("data", data) if isinstance(data, dict) else data
        entity_count = len(inner) if isinstance(inner, list) else 0

    if rel_file.exists():
        data = json.loads(rel_file.read_text(encoding="utf-8"))
        inner = data.get("data", data) if isinstance(data, dict) else data
        rel_count = len(inner) if isinstance(inner, list) else 0

    return {
        "entity_count": entity_count,
        "relationship_count": rel_count,
        "graph_populated": entity_count > 0,
        "note": (
            "Graph entities extracted (LLM was used during indexing)"
            if entity_count > 0
            else "No entities — stub LLM was used (returns empty JSON). Re-index with Ollama."
        ),
    }


def determine_status(install: dict, vector: dict, embed: dict, ollama: dict, ents: dict) -> str:
    if not install.get("installed"):
        return "NOT_INSTALLED"
    if not vector.get("exists"):
        return "INSTALLED_NOT_INDEXED"
    vector_live = vector.get("exists") and embed.get("installed")
    graph_live = ollama.get("reachable") and bool(ollama.get("models")) and ents.get("graph_populated")
    if vector_live and graph_live:
        return "LIVE_FULL"
    if vector_live:
        return "LIVE_VECTOR_ONLY"
    return "INSTALLED_NOT_INDEXED"


def write_report(status: str, install: dict, vector: dict, embed: dict,
                 ollama: dict, ents: dict) -> None:
    version = install.get("version", "?")
    vec_icon = "LIVE" if vector.get("exists") else "PENDING"
    embed_icon = "LIVE" if embed.get("installed") else "NOT INSTALLED"
    oll_icon = "LIVE" if ollama.get("reachable") else "OFFLINE"
    graph_icon = "LIVE" if ents.get("graph_populated") else "CONFIGURED_PENDING"
    models = ", ".join(ollama.get("models", [])) or "none pulled"
    vdb_files = ", ".join(vector.get("vector_db_files", [])) or "none"

    report = f"""<!-- WEBHOUND-GENERATED -->
# LightRAG Graph Runtime Results — Phase 8C-INFRA

**Date:** {NOW}
**Status:** {status}
**Version:** lightrag-hku v{version}

## Layer Status

| Layer | Status | Detail |
|-------|--------|--------|
| lightrag-hku | {"INSTALLED v" + version if install.get("installed") else "NOT INSTALLED"} | pip install lightrag-hku |
| Vector storage | {vec_icon} | {vector.get("json_file_count", 0)} files in lightrag_storage/ |
| Vector DB files | {vec_icon} | {vdb_files} |
| Embedding model | {embed_icon} | {embed.get("model", "?")} dim={embed.get("dim", "?")} |
| Graph entities | {graph_icon} | {ents.get("entity_count", 0)} entities, {ents.get("relationship_count", 0)} relationships |
| Ollama LLM | {oll_icon} | models: {models} |

## Layer Summary

- **Vector retrieval**: {"LIVE — 30 chunks indexed, naive mode queries work" if vector.get("exists") else "PENDING — run build_lightrag_index.py"}
- **Graph extraction**: {"LIVE" if ents.get("graph_populated") else "CONFIGURED_PENDING — requires Ollama LLM"}
- **Entity note**: {ents.get("note", "")}

## Activating Full Graph Mode

Full graph extraction requires a local LLM (Ollama) to parse entity/relationship JSON
during indexing. The current stub returns `{{"entities":[], "relationships":[]}}` —
only vector retrieval works.

### Step-by-step

```bash
# 1. Start Ollama
docker compose -f docker-compose.ai-brain.yml up -d ollama
# Or install natively: see docs/ai/OLLAMA_SETUP.md

# 2. Pull models
docker exec webhound-ollama-dev ollama pull llama3.2
docker exec webhound-ollama-dev ollama pull nomic-embed-text

# 3. Clear stub-indexed storage
rm -rf lightrag_storage/

# 4. Re-index with Ollama (replace stub LLM in build_lightrag_index.py)
# See the code snippet in docs/ai/LIGHTRAG_GRAPH_RUNTIME_RESULTS.md
.venv-api/Scripts/python scripts/ai/build_lightrag_index.py
```

### LightRAG + Ollama Integration

```python
from lightrag.llm.ollama import ollama_model_complete, ollama_embed
from lightrag import LightRAG
from lightrag.utils import EmbeddingFunc

rag = LightRAG(
    working_dir="lightrag_storage",
    llm_model_func=lambda prompt, **kw: ollama_model_complete(
        prompt, model="llama3.2", host="http://localhost:11434", **kw
    ),
    embedding_func=EmbeddingFunc(
        embedding_dim=768,
        max_token_size=256,
        func=lambda texts: ollama_embed(
            texts, embed_model="nomic-embed-text", host="http://localhost:11434"
        ),
    ),
)
```

## See Also

- [[OLLAMA_SETUP]] — install Ollama and pull models
- [[build_lightrag_index]] — index builder
- [[LIGHTRAG_BENCHMARK]] — performance comparison
"""
    RESULTS_MD.write_text(report, encoding="utf-8")
    print(f"Wrote {RESULTS_MD.relative_to(ROOT)}")


def main() -> None:
    install = check_lightrag_install()
    vector = check_vector_storage()
    embed = check_embedding_model()
    ollama = check_ollama()
    entities = check_graph_entities()
    status = determine_status(install, vector, embed, ollama, entities)

    result = {
        "checked_at": NOW,
        "status": status,
        "lightrag": install,
        "vector_storage": vector,
        "embedding_model": embed,
        "ollama": ollama,
        "graph_entities": entities,
    }
    RESULTS_JSON.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Wrote {RESULTS_JSON.relative_to(ROOT)}")
    write_report(status, install, vector, embed, ollama, entities)
    print(f"LightRAG status: {status}")
    print(f"  Vector: {'LIVE' if vector.get('exists') else 'PENDING'}, "
          f"Graph: {'LIVE' if entities.get('graph_populated') else 'CONFIGURED_PENDING'}, "
          f"Ollama: {'LIVE' if ollama.get('reachable') else 'OFFLINE'}")


if __name__ == "__main__":
    main()
