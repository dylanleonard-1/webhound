# Neo4j Verification — Phase CONTROL-2A

**Type:** VERIFICATION-ONLY (read-only live queries; no writes, no schema changes).
**Method:** live Cypher over HTTP API `http://localhost:7474/db/neo4j/query/v2` (WSL2 Docker `neo4j:5-community`, local dev cred from `docker-compose.ai-brain.yml`).

## Service status: ✅ RUNNING

- Container live (Docker in WSL2 Ubuntu-24.04); bolt `:7687` + http `:7474` both reachable.
- Auth: local dev only (`neo4j/webhound-brain-local-dev`, committed in compose — not a production secret).

## Live counts

| Label | Count | Source |
|-------|------:|--------|
| `FileNode` | **126** | `scripts/ai/load_brain_graph_neo4j.py` (the Graphify file graph) |
| `Entity` | 27 | Graphiti entity extraction (**garbage — see below**) |
| `Episodic` | 19 | Graphiti seed memories (**coherent**) |
| **Total** | **172** | matches "~172 last seen" |

Relationships present: `WIKI_LINK`, `DEPENDS_ON` (file graph) + Graphiti `RELATES_TO`/`MENTIONS` (sparse). The corpus-loader script `scripts/ai/load_neo4j.py` defines `KnowledgeSource / Chunk / Provider / TaxonomyEntry / ScannerEngine / ThreatSource` labels — **none are present** → that loader was never run/persisted into this instance.

## Node categories — mapped vs missing

| Category | In Neo4j? | Evidence |
|----------|-----------|----------|
| Repo files / advisory scripts | ✅ 126 `FileNode` | file-import + wikilink graph |
| Graphiti memories | ✅ 19 `Episodic` | seed decisions (WADE, Cloudflare-1020, XSS→CWE-79…) |
| Graphiti entities | ⚠️ 27 `Entity` but **incoherent** | hallucinated fragments, not WebHound concepts |
| **Knowledge corpus (chunks/sources)** | ❌ | `load_neo4j.py` labels absent |
| **Scanner engines (as entities)** | ❌ | only as FileNodes if under `scripts/` — production `scanner/` not loaded |
| **Production WADE** | ❌ | not represented |
| **Threat Intel sources** | ❌ | `ThreatSource` label absent |
| **Providers** | ❌ | `Provider` label absent |
| **Reports / Infrastructure** | ❌ | not loaded |

## What entities are missing

Everything except the file-graph and Graphiti memories: **no corpus chunks, no scanner engines, no providers, no threat-intel sources, no taxonomy, no reports.** The corpus knowledge-graph loader (`load_neo4j.py`) was authored but its labels are absent from the live DB — so Neo4j today is a **file-dependency graph + a small Graphiti memory store**, not a knowledge graph of the product.

**Score: 40% (D+)** — service healthy and queryable, but the graph is thin (172 nodes) and missing all product/knowledge entities.
</content>
