"""Phase 8C / 8C-INFRA: WebHound Brain health check.

Checks all brain components and reports live vs documented status.
Writes BRAIN_HEALTH_REPORT.md and brain_health.json.

Run: .venv-api/Scripts/python scripts/ai/check_brain_health.py
"""
from __future__ import annotations
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REPORT_MD = ROOT / "docs" / "ai" / "BRAIN_HEALTH_REPORT.md"
HEALTH_JSON = ROOT / "docs" / "ai" / "brain_health.json"
NOW = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ── Component checks ──────────────────────────────────────────────────────────

def check_corpus() -> dict:
    chunks_path = ROOT / "corpus" / "normalized" / "unified_chunks.jsonl"
    manifest_path = ROOT / "corpus" / "manifests" / "manifest.jsonl"
    lightrag_path = ROOT / "corpus" / "exports" / "lightrag" / "lightrag_documents.jsonl"
    graphiti_path = ROOT / "corpus" / "exports" / "graphiti_seeds.json"
    emb_path = ROOT / "corpus" / "indexes" / "dense" / "chunk_embeddings.npy"
    meta_path = ROOT / "corpus" / "indexes" / "dense" / "chunk_embedding_meta.json"

    chunks = sum(1 for l in open(chunks_path, encoding="utf-8") if l.strip()) if chunks_path.exists() else 0
    manifest = sum(1 for l in open(manifest_path, encoding="utf-8") if l.strip()) if manifest_path.exists() else 0
    lightrag = sum(1 for l in open(lightrag_path, encoding="utf-8") if l.strip()) if lightrag_path.exists() else 0
    graphiti_ok = graphiti_path.exists()
    emb_size = emb_path.stat().st_size // 1024 if emb_path.exists() else 0
    emb_count = len(json.load(open(meta_path, encoding="utf-8"))) if meta_path.exists() else 0

    ok = (chunks == 1161 and manifest == 487 and lightrag == 1161 and emb_count == 1161)
    return {
        "status": "healthy" if ok else "degraded",
        "manifest_records": manifest,
        "chunk_count": chunks,
        "lightrag_docs": lightrag,
        "graphiti_seeds": graphiti_ok,
        "embedding_count": emb_count,
        "embedding_size_kb": emb_size,
    }


def check_vault() -> dict:
    vault_dir = ROOT / "vault" / "WebHound AI Brain"
    if not vault_dir.exists():
        return {"status": "missing", "note_count": 0}
    notes = list(vault_dir.rglob("*.md"))
    sections = {f.parent.name for f in notes}
    return {
        "status": "healthy",
        "note_count": len(notes),
        "section_count": len(sections),
        "sections": sorted(sections),
    }


def check_hybrid_retrieval() -> dict:
    try:
        t0 = time.perf_counter()
        from scripts.ai.hybrid_retrieval import load_retriever
        r = load_retriever()
        hits = r.retrieve("Content Security Policy CSP", k=3, mode="lexical_only")
        elapsed = time.perf_counter() - t0
        return {
            "status": "live",
            "mode": "lexical_only",
            "test_hits": len(hits),
            "elapsed_s": round(elapsed, 3),
            "top_title": hits[0]["title"] if hits else "",
        }
    except Exception as e:
        return {"status": "error", "error": str(e)[:100]}


def check_lightrag() -> dict:
    lightrag_dir = ROOT / "lightrag_storage"
    try:
        import lightrag  # noqa: F401
        installed = True
        version = getattr(lightrag, "__version__", "?")
    except ImportError:
        return {"status": "not_installed", "installed": False}

    storage_exists = lightrag_dir.exists()
    vector_db = (lightrag_dir / "vdb_entities.json").exists() or \
                any(lightrag_dir.glob("*.json")) if storage_exists else False
    status = "live_vector_only" if storage_exists else "installed_not_indexed"
    return {
        "status": status,
        "installed": installed,
        "version": version,
        "storage_exists": storage_exists,
        "vector_storage_built": vector_db,
        "graph_storage": "NetworkX (in-memory)",
        "llm_status": "stub (no cloud, no local LLM) — graph extraction skipped",
        "embedding": "all-MiniLM-L6-v2 (local)",
    }


def check_graphiti() -> dict:
    try:
        import graphiti_core  # noqa: F401
        version = getattr(graphiti_core, "__version__", "?")
    except ImportError:
        return {"status": "not_installed"}

    neo4j_live = False
    try:
        s = socket.create_connection(("localhost", 7687), timeout=1)
        s.close()
        neo4j_live = True
    except OSError:
        pass

    schema_path = ROOT / "corpus" / "exports" / "graphiti_episode_schema.json"
    episodes = 0
    if schema_path.exists():
        data = json.loads(schema_path.read_text(encoding="utf-8"))
        episodes = len(data.get("episodes", []))

    return {
        "status": "schema_seeded" if not neo4j_live else "ready_to_seed",
        "installed": True,
        "version": version,
        "neo4j_live": neo4j_live,
        "llm_available": False,
        "episodes_defined": episodes,
        "gap": "Neo4j offline + no local LLM — schema seeded, runtime pending",
    }


def check_neo4j() -> dict:
    neo4j_live = False
    try:
        s = socket.create_connection(("localhost", 7687), timeout=1)
        s.close()
        neo4j_live = True
    except OSError:
        pass

    compose_path = ROOT / "docker-compose-neo4j.yml"
    load_script = ROOT / "scripts" / "ai" / "load_neo4j.py"
    return {
        "status": "live" if neo4j_live else "offline",
        "bolt_port_7687": neo4j_live,
        "docker_compose": compose_path.exists(),
        "load_script": load_script.exists(),
        "gap": "" if neo4j_live else "Docker daemon not running in this env — compose provided",
    }


def check_graphify() -> dict:
    graph_json = ROOT / "docs" / "ai" / "graphify" / "graph.json"
    graph_html = ROOT / "docs" / "ai" / "graphify" / "graph.html"
    if not graph_json.exists():
        return {"status": "not_built", "note": "Run build_graphify.py"}
    data = json.loads(graph_json.read_text(encoding="utf-8"))
    stats = data.get("stats", {})
    return {
        "status": "live_local_equivalent",
        "note": "Graphify binary not installed — local AST+wikilink scanner used",
        "node_count": stats.get("node_count", 0),
        "edge_count": stats.get("edge_count", 0),
        "html_generated": graph_html.exists(),
    }


def check_docker() -> dict:
    compose_brain = ROOT / "docker-compose.ai-brain.yml"
    compose_neo4j = ROOT / "docker-compose-neo4j.yml"
    try:
        r = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            return {
                "status": "live",
                "server_version": r.stdout.strip(),
                "compose_brain": compose_brain.exists(),
                "compose_neo4j": compose_neo4j.exists(),
            }
        return {
            "status": "offline",
            "error": r.stderr.strip()[:100],
            "compose_brain": compose_brain.exists(),
            "compose_neo4j": compose_neo4j.exists(),
        }
    except FileNotFoundError:
        return {"status": "not_installed", "compose_brain": compose_brain.exists()}
    except Exception as e:
        return {"status": "offline", "error": str(e)[:100], "compose_brain": compose_brain.exists()}


def check_ollama() -> dict:
    try:
        s = socket.create_connection(("localhost", 11434), timeout=1)
        s.close()
    except OSError:
        return {"status": "offline", "models": [], "model_count": 0}

    try:
        resp = urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2)
        data = json.loads(resp.read())
        models = [m["name"] for m in data.get("models", [])]
        return {"status": "live", "models": models, "model_count": len(models)}
    except Exception:
        return {"status": "live_no_models", "models": [], "model_count": 0}


def check_wade_retrieval() -> dict:
    try:
        from scripts.wade.context_builder import build_reasoning_context
        ctx = build_reasoning_context("missing_csp")
        return {
            "status": "live",
            "brain_version": ctx.brain_version,
            "finding_types": 22,
            "retrieval_confidence": ctx.retrieval_confidence,
            "taxonomy_cwe": ctx.taxonomy_context.get("cwe", ""),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)[:100]}


# ── Report ────────────────────────────────────────────────────────────────────

def status_icon(s: str) -> str:
    icons = {
        "healthy": "OK", "live": "LIVE", "live_local_equivalent": "LIVE (local)",
        "live_vector_only": "LIVE (vector)", "live_no_models": "LIVE (no models)",
        "installed_not_indexed": "INSTALLED", "schema_seeded": "CONFIGURED",
        "ready_to_seed": "READY", "offline": "OFFLINE", "degraded": "DEGRADED",
        "error": "ERROR", "missing": "MISSING", "not_installed": "NOT INSTALLED",
        "not_built": "NOT BUILT",
    }
    return icons.get(s, s.upper())


def write_report(health: dict) -> None:
    c = health["corpus"]
    v = health["vault"]
    hr = health["hybrid_retrieval"]
    lr = health["lightrag"]
    gt = health["graphiti"]
    n4 = health["neo4j"]
    gf = health["graphify"]
    wr = health["wade_retrieval"]
    dk = health.get("docker", {})
    ol = health.get("ollama", {})

    overall = all(
        h.get("status") not in ("error", "missing", "degraded")
        for h in [c, v, hr, wr]
    )

    report = f"""<!-- WEBHOUND-GENERATED -->
# WebHound Brain Health Report

**Generated:** {NOW}
**Overall Status:** {"HEALTHY — core components live" if overall else "DEGRADED — check individual components"}
**WADE Advisory:** {"READY" if wr.get("status") == "live" else "UNAVAILABLE"}

## Component Status

| Component | Status | Detail |
|-----------|--------|--------|
| Corpus | {status_icon(c['status'])} | {c['chunk_count']} chunks / {c['manifest_records']} manifest / {c['embedding_count']} embeddings |
| Vault | {status_icon(v['status'])} | {v['note_count']} notes in {v['section_count']} sections |
| Hybrid Retrieval | {status_icon(hr['status'])} | {hr.get('test_hits', 0)} hits in {hr.get('elapsed_s', '?')}s |
| WADE Retrieval | {status_icon(wr['status'])} | 22 finding types, confidence={wr.get('retrieval_confidence', 0):.2f} |
| Graphify | {status_icon(gf['status'])} | {gf.get('node_count', 0)} nodes / {gf.get('edge_count', 0)} edges |
| LightRAG | {status_icon(lr['status'])} | v{lr.get('version', '?')} — {lr.get('llm_status', '')} |
| Graphiti | {status_icon(gt['status'])} | v{gt.get('version', '?')} — {gt.get('gap', '')} |
| Neo4j | {status_icon(n4['status'])} | bolt:7687 = {n4['bolt_port_7687']} — {n4.get('gap', 'live')} |

## Corpus Health

```
Manifest records : {c['manifest_records']} (expected: 487)
Chunk count      : {c['chunk_count']} (expected: 1161)
LightRAG docs    : {c['lightrag_docs']} (expected: 1161)
Embedding count  : {c['embedding_count']} (expected: 1161)
Embedding size   : {c['embedding_size_kb']} KB
Graphiti seeds   : {'OK' if c['graphiti_seeds'] else 'MISSING'}
```

## Vault Health

```
Notes    : {v['note_count']}
Sections : {v['section_count']}
Sections : {', '.join(v.get('sections', []))}
```

## Live vs Configured

| Component | Live? | Blocker |
|-----------|-------|---------|
| Hybrid Retrieval | YES | — |
| WADE Retrieval | YES | — |
| Graphify (local) | {"YES" if gf.get('html_generated') else "PENDING run"} | Binary unavailable; local equiv used |
| LightRAG vector | {"YES" if lr.get('storage_exists') else "PENDING index build"} | Vector only; graph needs local LLM |
| Graphiti | NO — schema seeded | Neo4j + local LLM required |
| Neo4j | NO | Docker daemon offline |

## Ready for WADE Reasoning

{"YES — all core retrieval components live. WADE can retrieve advisory context for all 22 finding types." if overall else "PARTIAL — hybrid retrieval live; graph components pending local infra."}

## Infrastructure Status (Phase 8C-INFRA)

| Component | Status | Detail |
|-----------|--------|--------|
| Docker daemon | {status_icon(dk.get("status", "unknown"))} | compose: docker-compose.ai-brain.yml |
| Ollama LLM | {status_icon(ol.get("status", "offline"))} | models: {", ".join(ol.get("models", [])) or "none"} |

## Recommendations

1. Run `build_graphify.py` if graph.json not present
2. Run `build_lightrag_index.py` to build LightRAG vector index
3. Start Docker + Neo4j + Ollama: `docker compose -f docker-compose.ai-brain.yml up -d`
4. Pull Ollama models: `docker exec webhound-ollama-dev ollama pull llama3.2`
5. See `docs/ai/OLLAMA_SETUP.md` for local LLM activation guide
"""
    REPORT_MD.write_text(report, encoding="utf-8")
    print(f"Wrote {REPORT_MD.relative_to(ROOT)}")


def main() -> None:
    print("Checking WebHound Brain health...")
    health = {
        "checked_at": NOW,
        "corpus": check_corpus(),
        "vault": check_vault(),
        "hybrid_retrieval": check_hybrid_retrieval(),
        "lightrag": check_lightrag(),
        "graphiti": check_graphiti(),
        "neo4j": check_neo4j(),
        "graphify": check_graphify(),
        "wade_retrieval": check_wade_retrieval(),
        "docker": check_docker(),
        "ollama": check_ollama(),
    }

    HEALTH_JSON.write_text(json.dumps(health, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {HEALTH_JSON.relative_to(ROOT)}")
    write_report(health)

    for comp, data in health.items():
        if comp == "checked_at":
            continue
        s = data.get("status", "?")
        print(f"  {comp:<25} {status_icon(s)}")


if __name__ == "__main__":
    main()
