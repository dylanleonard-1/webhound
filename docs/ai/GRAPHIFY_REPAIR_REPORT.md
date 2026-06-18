# Graphify Repair Report — Phase CONTROL-2B

**Type:** KNOWLEDGE-INGESTION. Extends the local graph builder to ingest production code.
**Change:** `scripts/ai/build_graphify.py` extended (tooling only) to scan `scanner/webhound/` + `apps/api/` and to treat `webhound.*` / `apps.*` imports as graph edges (previously only `scripts.*` / `tests.*`). Output: `docs/ai/graphify/graph.{json,html,md}` (regenerated).

## Before → After

| Metric | CONTROL-2A | CONTROL-2B | Δ |
|--------|-----------:|-----------:|---|
| Total nodes | 126 | **892** | +766 |
| Total edges | 263 | **2,584** | +2,321 |
| Python edges | (scripts only) | 1,912 | — |
| **`scanner/webhound/` nodes** | **0** | **133** | +133 |
| **`apps/api/` nodes** | **0** | **249** | +249 |
| Production nodes total | **0** | **382** | +382 |

## Coverage

- Production **Python** modules (scanner + api, excl. frontend/tests) ≈ 405; Graphify now represents **382** of them via import/define edges → **~94% of production Python**.
- The richer entity graph (`ingest_production_code.py` → `production_entities.json`) holds the full **1,566 nodes / 3,514 edges** (modules + classes), used for the Neo4j load.
- **Known limitation:** `build_graphify.py` is Python-AST based, so `apps/web` (TypeScript, 168 modules) is **not** in the Graphify graph — captured instead by the corpus code chunks and `production_entities.json` (regex TS parse).

## What's now visible (was 0% in 2A)

Scanner engines (cookies/tls_dns/javascript/…), scanner core (orchestrator, scan_context), production WADE, threat_intel (incl. domain_classifier), providers, reporting, API routers/services/models — all now appear as graph nodes with import/define relationships.

**Result:** the graph went from *"advisory scripts talking to themselves"* (126 nodes, 0 production) to a **892-node graph that includes the real scanner + API**. Frontend TS coverage remains a gap for Graphify specifically.
</content>
