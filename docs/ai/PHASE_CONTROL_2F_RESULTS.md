# Phase CONTROL-2F — Brain Reality Verification: Results

**Branch:** `feat/control-2f-brain-reality-verification` off `main` @ `c883baa`.
**Type:** reality-verification only (read-only). No scanner/WADE/reports/provider/billing/auth/`.mcp.json` changes; no installs; no deploys; no new systems.

## What was physically verified
- **Retrieval** — 10 real questions via `scripts/ai/verify_brain_reality.py` (canonical hybrid, 6,886 chunks).
- **Graphify** — regenerated local graph (896 nodes / 2,589 edges / 573 py); checked all 10 concept code nodes.
- **Obsidian** — dashboard + engine/WADE/graph/MCP notes for accuracy/freshness/links.
- **Neo4j** — live read-only check (found OFFLINE; reported with last-known stats + manual commands).
- **End-to-end** — 5 concept traces across code → finding → WADE → report → docs.
- Service status (honest): **Neo4j OFFLINE, Ollama OFFLINE** (WSL containers stopped; not restarted per scope).

## Scores
| Layer | Score |
|-------|------:|
| Obsidian reality | **75%** |
| Graphify / local graph reality | **90%** |
| Neo4j reality | **35%** (offline) |
| Retrieval reality (NL questions) | **6 PASS / 1 PARTIAL / 3 FAIL = ~65%** |
| Concept traceability (symbol queries) | **10/10 PASS** |
| End-to-end traces | **4/5 PASS, 1 PARTIAL** (Neo4j hop offline) |
| Composite (reproducible layers) | **~83%** · (incl. offline DB tier) **~65%** |

## Stale / duplicate findings (report-only — see BRAIN_STALE_DUPLICATE_REPORT.md)
- **3 vaults**, no canonical one (typo'd `KNOWLEGE VAULT`); dual-numbered AI-Brain sections.
- Vault graph-runtime notes overstate liveness (Neo4j/Ollama actually OFFLINE).
- Phase-8G engine/WADE notes are architectural, not code-linked.
- Legacy `corpus/indexes/dense` doc index coexists with the canonical index.
- Graphiti entity layer historically hallucinated (offline now).

## Biggest remaining issue
**Verbose natural-language implementation questions return docs, not engine code** —
"where is production WADE implemented" / "what handles threat intelligence" surface
WADE_FOUNDATION.md / threat-intel notes instead of `scanner/webhound/wade/` /
`threat_intel/`. This is the inverse of the CONTROL-2E knowledge-query guard (which
correctly sends prose to docs) — it also catches code-locating prose. Symbol/short
queries resolve code perfectly (10/10).

## STATE OF BRAIN REALITY
1. **Can Obsidian accurately explain WebHound today?** Yes via the dashboard (current); deeper notes are architectural/8G-dated, and graph-runtime notes overstate liveness. (75%)
2. **Does Graphify see real code?** Yes — 896 nodes, all 10 concepts are real code nodes with real import edges. (90%)
3. **Does Neo4j represent real code?** Not verifiable now — OFFLINE; regenerable via committed loaders (last-known 2,133 nodes). (35%)
4. **Does retrieval answer real questions correctly?** Mixed honestly: symbol/short queries 10/10; verbose NL implementation questions 6/10 (docs win for WADE/threat-intel); knowledge questions correct.
5. **Can concepts trace end-to-end?** Yes at the code level (4/5 traces PASS); the Neo4j typed-entity hop is offline (trace 5 PARTIAL).
6. **What's stale/duplicated?** 3 vaults, dual-numbered sections, overstated-liveness runtime notes, legacy dense index, historical Graphiti junk.
7. **Next single action:** CONTROL-2G — make retrieval detect **code-locating intent** ("where is … implemented", "what handles …") and apply the code-symbol boost to those prose questions, lifting WADE/threat-intel implementation answers from doc→code (target retrieval reality 9–10/10), then add a guard test.

## Validation
- `pytest tests/ai`: see PR (all green incl. new reality tests).
- `verify_brain_reality.py`: 6 PASS / 1 PARTIAL / 3 FAIL (honest).
- `check_brain_traceability.py --mode hybrid`: 10/10 PASS; dense-quality-gate unaffected (read-only phase).
