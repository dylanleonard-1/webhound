"""Phase 8C-INFRA: Load Graphify dependency graph into Neo4j.

Loads the brain's file-dependency graph (126 nodes, 263 edges from graph.json)
into Neo4j as FileNode nodes with DEPENDS_ON and WIKI_LINK relationships.

Complements load_neo4j.py (chunks/manifest) — together they give Neo4j the
full knowledge + dependency graph for Graphiti to reason over.

Requires Neo4j running at bolt://localhost:7687
Run: .venv-api/Scripts/python scripts/ai/load_brain_graph_neo4j.py [--live]
     Default is dry-run — pass --live to actually write to Neo4j.

NO cloud APIs. LOCAL DEV ONLY.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

GRAPH_JSON = ROOT / "docs" / "ai" / "graphify" / "graph.json"
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "webhound-brain-local-dev"  # LOCAL DEV ONLY
DRY_RUN = "--live" not in sys.argv


SCHEMA_CYPHER = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (f:FileNode) REQUIRE f.path IS UNIQUE;",
    "CREATE INDEX IF NOT EXISTS FOR (f:FileNode) ON (f.file_type);",
]


def load_graph_data() -> dict:
    if not GRAPH_JSON.exists():
        raise FileNotFoundError(
            f"graph.json not found — run build_graphify.py first: {GRAPH_JSON}"
        )
    return json.loads(GRAPH_JSON.read_text(encoding="utf-8"))


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'")


def build_cypher_statements(graph: dict) -> list[str]:
    stmts = list(SCHEMA_CYPHER)
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    # nodes is a list: {"id": "path/file.py", "kind": "python", ...}
    for node in nodes:
        path = _esc(node.get("id", node.get("path", "")))
        file_type = _esc(node.get("kind", node.get("type", "unknown")))
        stmts.append(
            f"MERGE (f:FileNode {{path: '{path}'}}) "
            f"SET f.file_type = '{file_type}', "
            f"f.in_degree = {node.get('in_degree', 0)}, "
            f"f.out_degree = {node.get('out_degree', 0)};"
        )

    for edge in edges:
        src = _esc(edge.get("source", ""))
        tgt = _esc(edge.get("target", ""))
        if not src or not tgt:
            continue
        edge_type = edge.get("type", "import")
        rel = "WIKI_LINK" if edge_type == "wikilink" else "DEPENDS_ON"
        stmts.append(
            f"MATCH (s:FileNode {{path: '{src}'}}), (t:FileNode {{path: '{tgt}'}}) "
            f"MERGE (s)-[:{rel}]->(t);"
        )

    return stmts


def run_load(dry_run: bool = True) -> dict:
    graph = load_graph_data()
    stats = graph.get("stats", {})
    stmts = build_cypher_statements(graph)

    result = {
        "node_count": len(graph.get("nodes", [])),
        "edge_count": len(graph.get("edges", [])),
        "graph_stats": stats,
        "statement_count": len(stmts),
    }

    if dry_run:
        result["status"] = "dry_run_ok"
        result["sample_statements"] = stmts[:3]
        return result

    try:
        from neo4j import GraphDatabase
    except ImportError:
        result["status"] = "error"
        result["error"] = "neo4j driver not installed — pip install neo4j"
        return result

    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        loaded = 0
        with driver.session() as session:
            for stmt in stmts:
                session.run(stmt)
                loaded += 1
        driver.close()
        result["status"] = "ok"
        result["statements_run"] = loaded
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)[:300]

    return result


def main() -> None:
    mode = "DRY RUN" if DRY_RUN else "LIVE"
    print(f"Brain graph loader [{mode}]")

    result = run_load(dry_run=DRY_RUN)

    print(json.dumps(result, indent=2))
    print(f"\nStatus: {result['status']}")
    if result.get("node_count"):
        print(
            f"  Nodes: {result['node_count']}, "
            f"Edges: {result['edge_count']}, "
            f"Statements: {result['statement_count']}"
        )
    if DRY_RUN:
        print("\nPass --live to write to Neo4j (requires Neo4j running).")


if __name__ == "__main__":
    main()
