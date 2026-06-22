# Brain End-to-End Traces — Phase CONTROL-2F

Five concept traces across the real system. ✅ verified link · ⚠️ weak/indirect · ❌ gap.

## Trace 1 — Cookie finding path
`engines/cookies/cookie_scanner.py` ✅ (retrieval PASS, graph node) → emits `Finding`
(`scanner/webhound/models/finding.py`) ✅ → orchestrator dedup/score (`core/orchestrator.py`)
✅ → persisted `FindingRecord` (`apps/api/models/finding.py`) ✅ → report
(`reporting/json_report.py`) ✅ → Obsidian `07-Scanner/Engine - Cookies.md` ⚠️ (generated, not code-linked).
**Verdict: PASS** (code chain intact; doc layer architectural).

## Trace 2 — Domain classification path
`threat_intel/domain_classifier.py` ✅ (retrieval PASS) → shared-hosting / reputation
(`threat_intel/domain_reputation.py`, `threat_correlation.py`) ✅ → threat-intel engine
✅ → WADE/advisor enrichment ⚠️ (advisor_engine.py reachable; WADE-engine link weak in
prose retrieval) → report ✅. **Verdict: PASS** (classification + FP logic present).

## Trace 3 — TLS path
`engines/tls_dns/tls_checker.py` ✅ (retrieval PASS, graph node) → CDN/TLS wording in
knowledge (`knowledge/threat-intelligence/…`, MDN/CDN docs) ✅ → `Finding` → report
(`reporting/`) ✅. **Verdict: PASS.**

## Trace 4 — Scan → report (production flow)
frontend (`apps/web/src/app/scan/page.tsx`) ✅ → API (`routers/public_scan.py`,
`scan_jobs.py`) ✅ → orchestrator (`core/orchestrator.py`, `scan()` → `_run_wade`) ✅ →
engines (11 families) ✅ → production WADE (`webhound/wade/`) ✅ → DB
(`result_persistence.py`, 42 migrations) ✅ → report (`reporting/*`) ✅.
**Verdict: PASS** (matches CONTROL-1 production trace; retrieval surfaces the doc first
for the *prose* "how does a scan become a report" question — PARTIAL on retrieval, but
the code chain itself is intact and graph-connected).

## Trace 5 — Brain path (meta)
production source → canonical chunks (`build_canonical_brain_index.py`, 5.7k code chunks)
✅ → dense retrieval (`build_dense_brain_embeddings.py`, 6,886 vectors) ✅ → ranking
(`hybrid_retrieval.py`, code-symbol boost) ✅ → local graph (`graphify`, 896 nodes) ✅ →
Neo4j ❌ (offline this phase) → Obsidian dashboard ✅.
**Verdict: PARTIAL** — the corpus→chunks→dense→graph→Obsidian chain works end-to-end;
the Neo4j hop is offline.

## Summary
4/5 traces PASS at the **code** level; Trace 5 PARTIAL (Neo4j offline). The recurring
weak link is **prose retrieval of WADE/threat-intel engine code** and the **offline
Neo4j typed-entity layer** — neither breaks the actual production chain, which is intact.
