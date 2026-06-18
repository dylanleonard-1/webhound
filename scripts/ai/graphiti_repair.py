"""Phase CONTROL-2B: repair the LOCAL Graphiti brain memory.

1. Classify existing :Entity nodes VALID / QUESTIONABLE / HALLUCINATED.
2. Remove ONLY clearly-invalid (hallucinated) entities — record count + examples.
3. Seed production concepts as :Episodic :ProductionConcept nodes (linked to the
   real module path) via direct Cypher.

HONESTY NOTE: Ollama is NOT installed in this env, so Graphiti's LLM-based entity
extraction / semantic retrieval cannot run. We do NOT fabricate extracted
entities. Production concepts are inserted as explicit memory nodes only.

LOCAL WSL brain DB only. Run: .venv-api/Scripts/python scripts/ai/graphiti_repair.py
"""
from __future__ import annotations

import json
import re

from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
AUTH = ("neo4j", "webhound-brain-local-dev")

# Production concepts → real module path (verified to exist in the repo).
CONCEPTS = [
    ("cookie_scanner", "scanner/webhound/engines/cookies/cookie_scanner.py",
     "Cookie security scanner engine (flags, SameSite, Secure, HttpOnly)."),
    ("domain_classifier", "scanner/webhound/threat_intel/domain_classifier.py",
     "Threat-intel domain classification (reputation/category)."),
    ("tls_checker", "scanner/webhound/engines/tls_dns/tls_checker.py",
     "TLS/SSL configuration and certificate checker engine."),
    ("threat_intel", "scanner/webhound/threat_intel/__init__.py",
     "Threat-intelligence subsystem (URLHaus/VirusTotal clients, enrichment)."),
    ("run_scan", "worker/scan_tasks.py",
     "Celery task entrypoint that runs a scan via the orchestrator."),
    ("orchestrator", "scanner/webhound/core/orchestrator.py",
     "Scanner orchestrator (class Scanner.scan) — drives engines + production WADE."),
    ("WADE", "scanner/webhound/wade/",
     "Production WADE drift/anomaly engine (baseline->diff->anomaly->classify)."),
]


def is_hallucinated(name: str) -> bool:
    if not name:
        return True
    if len(name) > 60:
        return True
    if any(ch in name for ch in ("\n", "`", "|>", "http", ".png", ".jpg", "```")):
        return True
    alpha = sum(c.isalpha() or c.isspace() for c in name)
    return (alpha / max(len(name), 1)) < 0.7


def main() -> None:
    d = GraphDatabase.driver(URI, auth=AUTH)
    removed_examples, kept_examples = [], []
    with d.session() as s:
        ents = [r["n"] for r in s.run("MATCH (e:Entity) RETURN coalesce(e.name,'') AS n")]
        total = len(ents)
        hallucinated = [n for n in ents if is_hallucinated(n)]
        valid = [n for n in ents if not is_hallucinated(n)]
        removed_examples = hallucinated[:5]
        kept_examples = valid[:5]

        # Remove ONLY clearly-invalid entities.
        s.run(
            "MATCH (e:Entity) WHERE coalesce(e.name,'') IN $names DETACH DELETE e",
            names=hallucinated,
        )

        # Seed production concepts as explicit memory nodes (no LLM needed).
        for name, path, desc in CONCEPTS:
            s.run(
                "MERGE (c:Episodic:ProductionConcept {name:$name}) "
                "SET c.module=$path, c.summary=$desc, c.source='CONTROL-2B', "
                "c.group_id='production_code'",
                name=name, path=path, desc=desc,
            )
        seeded = s.run("MATCH (c:ProductionConcept) RETURN count(c) AS c").single()["c"]
        ent_after = s.run("MATCH (e:Entity) RETURN count(e) AS c").single()["c"]
        epi_after = s.run("MATCH (e:Episodic) RETURN count(e) AS c").single()["c"]
    d.close()

    print(json.dumps({
        "entities_before": total,
        "classified_hallucinated": len(hallucinated),
        "classified_valid": len(valid),
        "removed": len(hallucinated),
        "entities_after": ent_after,
        "removed_examples": removed_examples,
        "kept_examples": kept_examples,
        "production_concepts_seeded": seeded,
        "episodic_after": epi_after,
        "ollama_available": False,
        "llm_entity_extraction": "BLOCKED (Ollama not installed) — concepts seeded as explicit memory nodes only",
    }, indent=2))


if __name__ == "__main__":
    main()
