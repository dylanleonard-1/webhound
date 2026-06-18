"""Phase CONTROL-2B: load production code entities into the LOCAL WSL brain graph.

Loads modules/classes from corpus/indexes/graph/production_entities.json into the
local Neo4j (bolt://localhost:7687) as :CodeModule / :CodeClass nodes tagged with
an ownership category, plus IMPORTS / DEFINES relationships. Idempotent (MERGE).
LOCAL brain DB only — never touches production data or any cloud DB.

Run: .venv-api/Scripts/python scripts/ai/load_production_neo4j.py
"""
from __future__ import annotations

import json
from pathlib import Path

from neo4j import GraphDatabase

ROOT = Path(__file__).resolve().parent.parent.parent
GRAPH = ROOT / "corpus" / "indexes" / "graph" / "production_entities.json"
URI = "bolt://localhost:7687"
AUTH = ("neo4j", "webhound-brain-local-dev")  # local dev cred (committed compose)

# category -> extra Neo4j label
CAT_LABEL = {
    "scanner_engine": "ScannerEngine", "scanner_core": "ScannerCore",
    "wade_production": "WADEComponent", "wade_advisory": "WADEAdvisory",
    "threat_intel": "ThreatIntel", "provider": "ProviderRule",
    "report": "ReportComponent", "api_route": "APIRoute",
    "api_service": "APIService", "api_model": "APIModel",
    "frontend": "Frontend", "test": "TestModule", "scanner": "ScannerModule",
    "api": "APIModule",
}


def main() -> None:
    g = json.load(open(GRAPH, encoding="utf-8"))
    modules = [n for n in g["nodes"] if n["kind"] == "module"]
    classes = [n for n in g["nodes"] if n["kind"] == "class"]
    edges = g["edges"]

    d = GraphDatabase.driver(URI, auth=AUTH)
    with d.session() as s:
        before_n = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        before_r = s.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]

        # Modules — set a generic :CodeModule label + category property.
        s.run(
            "UNWIND $rows AS r MERGE (m:CodeModule {id:r.id}) "
            "SET m.label=r.label, m.category=r.category, m.kind='module'",
            rows=[{"id": m["id"], "label": m["label"], "category": m["category"]} for m in modules],
        )
        # Add category-specific labels (one pass per category label).
        for cat, lbl in CAT_LABEL.items():
            ids = [m["id"] for m in modules if m["category"] == cat]
            if ids:
                s.run(f"UNWIND $ids AS i MATCH (m:CodeModule {{id:i}}) SET m:{lbl}", ids=ids)

        s.run(
            "UNWIND $rows AS r MERGE (c:CodeClass {id:r.id}) "
            "SET c.label=r.label, c.category=r.category, c.kind='class'",
            rows=[{"id": c["id"], "label": c["label"], "category": c["category"]} for c in classes],
        )
        # Relationships: defines (module->class), import (module->module path).
        defines = [e for e in edges if e["type"] == "defines"]
        imports = [e for e in edges if e["type"] == "import"]
        s.run(
            "UNWIND $rows AS r MATCH (m:CodeModule {id:r.source}) MATCH (c:CodeClass {id:r.target}) "
            "MERGE (m)-[:DEFINES]->(c)",
            rows=defines,
        )
        s.run(
            "UNWIND $rows AS r MATCH (m:CodeModule {id:r.source}) "
            "MERGE (t:CodeModule {id:r.target}) MERGE (m)-[:IMPORTS]->(t)",
            rows=imports,
        )

        after_n = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        after_r = s.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
        cats = s.run(
            "MATCH (m:CodeModule) RETURN m.category AS cat, count(*) AS c ORDER BY c DESC"
        ).data()
    d.close()

    print(f"nodes: {before_n} -> {after_n} (+{after_n-before_n})")
    print(f"rels:  {before_r} -> {after_r} (+{after_r-before_r})")
    print(f"modules loaded: {len(modules)}, classes loaded: {len(classes)}")
    print("by category:", json.dumps(cats))


if __name__ == "__main__":
    main()
