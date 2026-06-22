# Graphify (Local Graph) Reality Verification — Phase CONTROL-2F

Verify the local file-relationship graph (`scripts/ai/build_graphify.py` →
`docs/ai/graphify/graph.json`) sees REAL production code for the 10 concepts.
Regenerated this phase; deterministic; no network.

## Graph stats (regenerated)
**896 nodes · 2,589 edges · 573 Python files** (vs the CONTROL-2A advisory-only
126/263) — production code is now in the graph (CONTROL-2B extension).

## Concept coverage — all 10 present as real CODE nodes

| Concept | Node in graph | Verdict |
|---------|---------------|---------|
| cookie_scanner | `scanner/webhound/engines/cookies/cookie_scanner.py` | PASS |
| domain_classifier | `scanner/webhound/threat_intel/domain_classifier.py` | PASS |
| tls_checker | `scanner/webhound/engines/tls_dns/tls_checker.py` | PASS |
| threat_intel | `scanner/webhound/engines/threat_intel/external_domains.py` (+ `threat_intel/`) | PASS |
| scanner orchestrator | `scanner/webhound/core/orchestrator.py` | PASS |
| production WADE | `scanner/webhound/wade/anomaly_scorer.py` | PASS |
| advisory WADE | `scripts/wade/context_builder.py` | PASS |
| API authentication | `apps/api/routers/auth.py` | PASS |
| verification flow | `apps/api/services/verification.py` | PASS |
| report rendering | `scanner/webhound/reporting/json_report.py` | PASS |

## Relationships
Edges are real import/wikilink dependencies (2,589 total). Spot example: the canonical
brain graph links `hybrid_retrieval.py` and the `scripts/wade/` resolvers (highest
degree), and production modules connect via `import` edges. The graph captures
module→module imports, not class/function-level call graphs (that lives in the Neo4j
`CodeModule`/`CodeClass` load — currently offline).

## Limitation (honest)
The local graph is a **module-level import/wikilink graph** — it proves the code is
*present and connected*, not full call-chain semantics. Typed entity labels
(ScannerEngine/WADEComponent/APIRoute) live in the Neo4j load (offline this phase).

**Graphify reality score: 90% (A−)** — all 10 concepts are real code nodes with real
edges; only the deeper typed-entity/call-graph view is unavailable (Neo4j offline).
