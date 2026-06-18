"""Phase CONTROL-2B: trace 8 concepts across every brain layer (PASS/PARTIAL/FAIL).

Layers: Corpus(code+doc) / HybridRetrieval / Obsidian / Graphify / Neo4j / Graphiti / LightRAG.
Read-only. Run: .venv-api/Scripts/python scripts/ai/traceability_tests.py
"""
from __future__ import annotations

import json
from pathlib import Path

from neo4j import GraphDatabase

ROOT = Path(__file__).resolve().parent.parent.parent
URI, AUTH = "bolt://localhost:7687", ("neo4j", "webhound-brain-local-dev")

CONCEPTS = ["cookie_scanner", "domain_classifier", "tls_checker", "threat_intel",
            "WADE", "Scanner Orchestrator", "Verification Flow", "API Authentication"]
# search aliases per concept (lowercased substrings)
ALIASES = {
    "cookie_scanner": ["cookie_scanner", "cookie"],
    "domain_classifier": ["domain_classifier", "domain class"],
    "tls_checker": ["tls_checker", "tls"],
    "threat_intel": ["threat_intel", "threat intel"],
    "WADE": ["wade"],
    "Scanner Orchestrator": ["orchestrator", "scan_context", "scanner.core"],
    "Verification Flow": ["verification", "verify"],
    "API Authentication": ["auth", "authentication"],
}


def _read(p):
    return p.read_text(encoding="utf-8", errors="replace").lower() if p.exists() else ""


def main() -> None:
    code = _read(ROOT / "corpus/normalized/code/production_code_chunks.jsonl")
    doc = _read(ROOT / "corpus/normalized/unified_chunks.jsonl")
    graphify = _read(ROOT / "docs/ai/graphify/graph.json")
    smoke = json.loads((ROOT / "corpus/indexes/dense_with_code/retrieval_smoke.json").read_text())
    vault = ROOT / "vault/WebHound AI Brain"
    vault_blob = " ".join(_read(f) for f in vault.rglob("*.md"))
    lightrag = _read(ROOT / "lightrag_storage/kv_store_text_chunks.json")

    d = GraphDatabase.driver(URI, auth=AUTH)
    rows = []
    with d.session() as s:
        for c in CONCEPTS:
            al = ALIASES[c]
            corpus_hit = any(a in code for a in al) or any(a in doc for a in al)
            code_hit = any(a in code for a in al)
            # hybrid: top retrieval result for this concept
            sm = smoke.get(c, {})
            hyb = "PASS" if sm.get("is_code") else ("PARTIAL" if sm else "FAIL")
            obs = any(a in vault_blob for a in al)
            gfy = any(a in graphify for a in al)
            n_count = 0
            for a in al:
                n_count += s.run(
                    "MATCH (m:CodeModule) WHERE toLower(m.id) CONTAINS $a RETURN count(m) AS c",
                    a=a).single()["c"]
            graphiti = s.run(
                "MATCH (p:ProductionConcept) WHERE toLower(p.name) CONTAINS $a OR toLower(coalesce(p.summary,'')) CONTAINS $a RETURN count(p) AS c",
                a=al[0]).single()["c"]
            lr = any(a in lightrag for a in al)

            def mark(b):
                return "PASS" if b else "FAIL"
            rows.append({
                "concept": c,
                "Corpus": "PASS" if code_hit else ("PARTIAL" if corpus_hit else "FAIL"),
                "HybridRetrieval": hyb,
                "Obsidian": mark(obs),
                "Graphify": mark(gfy),
                "Neo4j": "PASS" if n_count > 0 else "FAIL",
                "Graphiti": "PASS" if graphiti > 0 else "PARTIAL",
                "LightRAG": "PARTIAL" if lr else "FAIL",
            })
    d.close()
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
