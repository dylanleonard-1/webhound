# Production Code Inventory — Phase CONTROL-2B

**Type:** KNOWLEDGE-INGESTION (read-only over production code). No production code edited.
**Branch:** `feat/control-2b-production-code-ingestion` off `main` @ `ace3fab`.
**Generator:** `scripts/ai/ingest_production_code.py` (AST for Python, regex for TS/TSX). Output artifacts (regenerable, not committed): `corpus/normalized/code/production_code_chunks.jsonl`, `corpus/indexes/graph/production_entities.json`.

## Scope ingested

`scanner/webhound/`, `apps/api/`, `apps/web/src/`, `tests/`, `scanner/tests/`, `apps/api/tests/` — deduped.

## Totals

| Metric | Count |
|--------|------:|
| Production module files (chunks) | **746** |
| Classes extracted | 820 |
| Graph nodes (modules + classes) | 1,566 |
| Graph edges (imports + defines) | 3,514 |

## By ownership category (modules, deduped — from Neo4j load)

| Category | Modules | Maps to |
|----------|--------:|---------|
| test | 179 | `tests/`, `scanner/tests/`, `apps/api/tests/` |
| frontend | 168 | `apps/web/src/` (.ts/.tsx) |
| scanner (other) | 84 | `scanner/webhound/{asm,auth,browser,frameworks,graph,...}` |
| api (other) | 60 | `apps/api/{config,security,...}` |
| api_service | 55 | `apps/api/services/` |
| scanner_engine | 44 | `scanner/webhound/engines/*` (cookies, tls_dns, javascript, …) |
| api_model | 34 | `apps/api/models/` |
| scanner_core | 26 | `scanner/webhound/core/` (orchestrator, scan_context) |
| api_route | 25 | `apps/api/routers/` |
| threat_intel | 20 | `scanner/webhound/threat_intel/` (incl. `domain_classifier.py`) |
| report | 19 | `scanner/webhound/reporting/` |
| provider | 16 | `scanner/webhound/providers/` |
| wade_production | 13 | `scanner/webhound/wade/` |
| wade_advisory | 3 | `scripts/wade/` (advisory; counted for contrast) |

## Per-module record (each chunk carries)

`chunk_id`, `doc_id`, `file_path`, `module`, `source_type=production_code`, `authority_tier=A`, `title`, `topic_tags=[category]`, `phase=CONTROL-2B`, and a code-aware `text` block: **path · category · module docstring (purpose) · symbols (classes/functions) · internal imports**. Provenance is the real source path — every chunk traces back to a committed file.

## Key modules now represented (sample)

| Module | Category | Purpose (from docstring) |
|--------|----------|--------------------------|
| `scanner/webhound/core/orchestrator.py` | scanner_core | `Scanner.scan()` — drives engines + production WADE |
| `scanner/webhound/engines/cookies/cookie_scanner.py` | scanner_engine | cookie security flags |
| `scanner/webhound/engines/tls_dns/tls_checker.py` | scanner_engine | TLS/cert checks |
| `scanner/webhound/threat_intel/domain_classifier.py` | threat_intel | domain reputation/classification *(was a total blind spot in 2A)* |
| `scanner/webhound/wade/diff_engine.py` | wade_production | baseline→diff WADE |
| `apps/api/routers/auth.py` | api_route | 2-step OTP auth |
| `apps/api/services/wade_correlation.py` | wade_production | cross-scan behavioural correlation |

**Result:** the brain corpus now contains a code-aware, provenance-stamped representation of all 746 production modules — closing the CONTROL-2A "production code invisible to the brain" CRITICAL gap at the corpus layer.
</content>
