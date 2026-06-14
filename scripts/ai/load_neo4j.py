"""Phase 8C: Neo4j knowledge graph loader.

Loads WebHound knowledge nodes and relationships into Neo4j.

Node types: KnowledgeSource, Chunk, ThreatSource, Provider,
            TaxonomyEntry, ScannerEngine

Requires Neo4j running (see docker-compose-neo4j.yml).
Requires: pip install neo4j

Run: .venv-api/Scripts/python scripts/ai/load_neo4j.py [--dry-run]
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CHUNKS_PATH = ROOT / "corpus" / "normalized" / "unified_chunks.jsonl"
MANIFEST_PATH = ROOT / "corpus" / "manifests" / "manifest.jsonl"
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "webhound-brain-local"
DRY_RUN = "--dry-run" in sys.argv


# ── Schema / Cypher ───────────────────────────────────────────────────────────

SCHEMA_CYPHER = """
CREATE CONSTRAINT IF NOT EXISTS FOR (s:KnowledgeSource) REQUIRE s.doc_id IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (c:Chunk) REQUIRE c.chunk_id IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (p:Provider) REQUIRE p.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (t:TaxonomyEntry) REQUIRE t.cwe IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (se:ScannerEngine) REQUIRE se.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (ts:ThreatSource) REQUIRE ts.name IS UNIQUE;
"""

# Known providers from Phase 8B provider_resolver
PROVIDERS = [
    "cloudflare", "vercel", "railway", "fastly", "akamai",
    "aws", "azure", "imperva", "sucuri", "netlify", "fly.io",
    "render", "stripe", "resend", "github", "google-cloud",
]

# Scanner engines from WebHound architecture
SCANNER_ENGINES = [
    {"name": "webhound-core", "type": "passive", "description": "Header/TLS/cookie analysis"},
    {"name": "dalfox", "type": "active", "description": "XSS confirmation engine"},
    {"name": "nuclei", "type": "active", "description": "Template-based vulnerability scanner"},
    {"name": "zap", "type": "active", "description": "OWASP ZAP active scanner"},
    {"name": "wappalyzer", "type": "passive", "description": "Technology fingerprinting"},
]

# Threat intelligence sources
THREAT_SOURCES = [
    {"name": "AbuseIPDB", "type": "ip_reputation", "url": "https://www.abuseipdb.com"},
    {"name": "GreyNoise", "type": "ip_reputation", "url": "https://www.greynoise.io"},
    {"name": "VirusTotal", "type": "file_url", "url": "https://www.virustotal.com"},
    {"name": "URLhaus", "type": "url_reputation", "url": "https://urlhaus.abuse.ch"},
    {"name": "ThreatFox", "type": "ioc", "url": "https://threatfox.abuse.ch"},
]


def load_chunks_sample(n: int = 50) -> list[dict]:
    chunks = []
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                chunks.append(json.loads(line))
                if len(chunks) >= n:
                    break
    return chunks


def load_manifest_sample(n: int = 50) -> list[dict]:
    docs = []
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                docs.append(json.loads(line))
                if len(docs) >= n:
                    break
    return docs


def build_cypher_batches(chunks: list[dict], docs: list[dict]) -> list[tuple[str, dict]]:
    """Return list of (cypher, params) for batch loading."""
    statements = []

    # KnowledgeSource nodes from manifest
    for doc in docs:
        statements.append((
            """MERGE (s:KnowledgeSource {doc_id: $doc_id})
               SET s.title = $title, s.source_type = $source_type,
                   s.authority_tier = $authority_tier, s.phase = $phase""",
            {
                "doc_id": doc.get("doc_id", ""),
                "title": doc.get("title", ""),
                "source_type": doc.get("source_type", ""),
                "authority_tier": doc.get("authority_tier", ""),
                "phase": doc.get("phase", ""),
            }
        ))

    # Chunk nodes
    for chunk in chunks:
        statements.append((
            """MERGE (c:Chunk {chunk_id: $chunk_id})
               SET c.doc_id = $doc_id, c.text_preview = $text_preview,
                   c.source_type = $source_type, c.phase = $phase""",
            {
                "chunk_id": chunk.get("chunk_id", ""),
                "doc_id": chunk.get("doc_id", ""),
                "text_preview": chunk.get("text", "")[:200],
                "source_type": chunk.get("source_type", ""),
                "phase": chunk.get("phase", ""),
            }
        ))
        # HAS_CHUNK relationship
        statements.append((
            """MATCH (s:KnowledgeSource {doc_id: $doc_id})
               MATCH (c:Chunk {chunk_id: $chunk_id})
               MERGE (s)-[:HAS_CHUNK]->(c)""",
            {"doc_id": chunk.get("doc_id", ""), "chunk_id": chunk.get("chunk_id", "")}
        ))

    # Provider nodes
    for name in PROVIDERS:
        statements.append((
            "MERGE (p:Provider {name: $name})",
            {"name": name}
        ))

    # Scanner engine nodes
    for se in SCANNER_ENGINES:
        statements.append((
            """MERGE (s:ScannerEngine {name: $name})
               SET s.type = $type, s.description = $description""",
            se
        ))

    # Threat source nodes
    for ts in THREAT_SOURCES:
        statements.append((
            """MERGE (t:ThreatSource {name: $name})
               SET t.type = $type, t.url = $url""",
            ts
        ))

    return statements


def run_load(dry_run: bool = False) -> dict:
    chunks = load_chunks_sample(50)
    docs = load_manifest_sample(50)
    statements = build_cypher_batches(chunks, docs)

    result = {
        "docs_to_load": len(docs),
        "chunks_to_load": len(chunks),
        "providers": len(PROVIDERS),
        "scanner_engines": len(SCANNER_ENGINES),
        "threat_sources": len(THREAT_SOURCES),
        "total_statements": len(statements),
        "dry_run": dry_run,
    }

    if dry_run:
        print(f"[DRY RUN] Would execute {len(statements)} Cypher statements")
        print(f"  KnowledgeSources: {len(docs)}")
        print(f"  Chunks: {len(chunks)}")
        print(f"  Providers: {len(PROVIDERS)}")
        print(f"  ScannerEngines: {len(SCANNER_ENGINES)}")
        print(f"  ThreatSources: {len(THREAT_SOURCES)}")
        result["status"] = "dry_run_ok"
        return result

    try:
        from neo4j import GraphDatabase  # type: ignore[import]
    except ImportError:
        print("neo4j driver not installed. Run: pip install neo4j")
        result["status"] = "neo4j_driver_missing"
        return result

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    try:
        with driver.session() as session:
            # Apply schema
            for stmt in SCHEMA_CYPHER.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    session.run(stmt)
            # Load data
            loaded = 0
            for cypher, params in statements:
                try:
                    session.run(cypher, **params)
                    loaded += 1
                except Exception as e:
                    print(f"  [warn] {e}")
        result["status"] = "ok"
        result["statements_executed"] = loaded
    except Exception as e:
        result["status"] = f"error: {e}"
    finally:
        driver.close()

    return result


def main() -> None:
    print(f"Neo4j loader — dry_run={DRY_RUN}")
    result = run_load(DRY_RUN)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
