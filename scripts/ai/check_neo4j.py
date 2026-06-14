"""Phase 8C-INFRA: Neo4j connectivity and schema check.

Reports LIVE / OFFLINE status for Neo4j.
Runs basic Cypher validation and node count checks when live.
Writes docs/ai/NEO4J_RUNTIME_RESULTS.md.

Run: .venv-api/Scripts/python scripts/ai/check_neo4j.py [--dry-run]
"""
from __future__ import annotations
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RESULTS_MD = ROOT / "docs" / "ai" / "NEO4J_RUNTIME_RESULTS.md"
RESULTS_JSON = ROOT / "docs" / "ai" / "neo4j_runtime.json"
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "webhound-brain-local-dev"  # LOCAL DEV ONLY
NOW = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
DRY_RUN = "--dry-run" in sys.argv


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def run_cypher_checks() -> dict:
    try:
        from neo4j import GraphDatabase
    except ImportError:
        return {"error": "neo4j driver not installed — pip install neo4j", "live": False}

    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        with driver.session() as session:
            val = session.run("RETURN 1 AS val").single()["val"]
            assert val == 1

            counts = {}
            for label in ["KnowledgeSource", "Chunk", "Provider", "TaxonomyEntry",
                          "ScannerEngine", "ThreatSource", "FileNode"]:
                r = session.run(f"MATCH (n:{label}) RETURN count(n) AS c")
                counts[label] = r.single()["c"]

            rels = {}
            for rec in session.run("MATCH ()-[r]->() RETURN type(r) AS t, count(r) AS c"):
                rels[rec["t"]] = rec["c"]

        driver.close()
        return {"live": True, "node_counts": counts, "relationship_counts": rels}
    except Exception as e:
        return {"live": False, "error": str(e)[:200]}


def write_report(result: dict) -> None:
    status = result["status"]
    bolt = result["bolt_7687"]
    http = result["http_7474"]
    cypher = result.get("cypher_check", {})

    bolt_icon = "LIVE" if bolt else "OFFLINE"
    http_icon = "LIVE" if http else "OFFLINE"

    node_table = ""
    if cypher.get("node_counts"):
        rows = "\n".join(f"| {k} | {v} |" for k, v in cypher["node_counts"].items())
        node_table = (
            "\n## Node Counts\n\n"
            "| Label | Count |\n|-------|-------|\n"
            f"{rows}\n"
        )

    gap = (
        "Docker daemon not running in this environment. "
        "See `docker-compose.ai-brain.yml` to start Neo4j locally."
        if not bolt
        else ""
    )

    report = f"""<!-- WEBHOUND-GENERATED -->
# Neo4j Runtime Results — Phase 8C-INFRA

**Date:** {NOW}
**Status:** {status}

## Port Status

| Port | Service | Status |
|------|---------|--------|
| 7687 | Neo4j Bolt | {bolt_icon} |
| 7474 | Neo4j HTTP browser | {http_icon} |

{("## Gap\n\n" + gap) if gap else "## Connected\n\nNeo4j is running."}

## Setup (when Docker is available)

```bash
# Start Neo4j
docker compose -f docker-compose.ai-brain.yml up -d

# Wait ~30s for Neo4j to be healthy, then:
.venv-api/Scripts/python scripts/ai/load_neo4j.py
.venv-api/Scripts/python scripts/ai/load_brain_graph_neo4j.py
.venv-api/Scripts/python scripts/ai/load_graphiti_seed_memories.py --live
```
{node_table}
## Auth (LOCAL DEV ONLY)

| Setting | Value |
|---------|-------|
| URI | bolt://localhost:7687 |
| User | neo4j |
| Password | webhound-brain-local-dev |

**Never use this password outside localhost dev.**
"""
    RESULTS_MD.write_text(report, encoding="utf-8")
    print(f"Wrote {RESULTS_MD.relative_to(ROOT)}")


def main() -> None:
    bolt = _port_open("localhost", 7687)
    http = _port_open("localhost", 7474)

    if not bolt:
        status = "OFFLINE"
        cypher = {}
    elif DRY_RUN:
        status = "LIVE_PORT_ONLY"
        cypher = {}
    else:
        cypher = run_cypher_checks()
        status = "LIVE" if cypher.get("live") else "LIVE_PORT_ONLY"

    result = {
        "checked_at": NOW,
        "status": status,
        "bolt_7687": bolt,
        "http_7474": http,
        "cypher_check": cypher,
        "compose_file": "docker-compose.ai-brain.yml",
        "load_script": "scripts/ai/load_neo4j.py",
        "brain_graph_script": "scripts/ai/load_brain_graph_neo4j.py",
    }
    RESULTS_JSON.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Wrote {RESULTS_JSON.relative_to(ROOT)}")
    write_report(result)
    print(f"Neo4j status: {status}")


if __name__ == "__main__":
    main()
