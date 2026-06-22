# Neo4j Reality Verification — Phase CONTROL-2F

## Service status: ❌ OFFLINE (this phase)

| Check | Result |
|-------|--------|
| `http://localhost:7474` | HTTP 000 (refused) |
| Neo4j container in WSL2 | none running (`docker ps` shows no neo4j) |
| Ollama (`:11434`) | also down (000) |

The local WSL2 `neo4j:5-community` brain container that was LIVE in CONTROL-2A/2B has
stopped (session/host restart). Per scope (read-only, no new systems) it was **not**
restarted. This is reported honestly, not as a failure of the brain design.

## Last-known stats (from prior phases — NOT re-verified live)
- CONTROL-2A: 172 nodes (126 `FileNode`, 27 `Entity` [garbage], 19 `Episodic`), 224 rels.
- CONTROL-2B local load: **172 → 2,133 nodes** (+1,961: `CodeModule`/`CodeClass` with
  `ScannerEngine`/`WADEComponent`/`APIRoute`/`ThreatIntel`/… labels), **3,386 rels**
  (`DEFINES`/`IMPORTS`). This data lived in the local container volume and is gone
  with the stopped container — it is **regenerable**, not committed.

## Manual re-verification (when the operator brings Neo4j back up)
```bash
# 1. start the local brain Neo4j (WSL2)
wsl -d Ubuntu-24.04 -- docker run -d --name neo4j-brain -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/webhound-brain-local-dev neo4j:5-community
# 2. reload the canonical chunk graph + production entities (local, read-only over repo)
python scripts/ai/build_canonical_brain_index.py
python scripts/ai/load_production_neo4j.py
# 3. verify entities (read-only Cypher)
#   MATCH (m:ScannerEngine) RETURN count(m);
#   MATCH (m:CodeModule {category:'wade_production'}) RETURN m.id LIMIT 10;
#   MATCH (m:CodeModule)-[:IMPORTS]->(t) RETURN m.id,t.id LIMIT 10;
```

## Verdict
**OFFLINE — not verifiable live this phase.** The loader (`load_production_neo4j.py`)
and canonical builder are committed and deterministic, so the graph is fully
reproducible; but as of CONTROL-2F there is no running Neo4j to query.

**Neo4j reality score: N/A live · 35%** (regenerable + documented, but not currently
queryable; do not trust the "LIVE" wording in older vault notes).
