# WebHound — Crawler Visibility Layer: Audit & Implementation Plan (STEP 0)

**Status:** Audit only — no code written. Awaiting go-ahead before Phase 1.
**Date:** 2026-06-11
**Mission:** Add a *visibility / discovery* layer that maximizes discovery of every public/customer-approved page, route, form, API endpoint, script, asset, and hidden entry point — producing a site graph + visibility/coverage score. This is **discovery/visibility, NOT exploit scanning.** It is built **around** the existing scanner and runs **before** the security engines. The existing security engines must not be rewritten or broken.

---

## 1. TL;DR — What I found

WebHound already has a **mature, safe-mode discovery substrate** — far more than a greenfield crawler. Most of the *raw signal extraction* the 12-phase spec asks for already exists and is battle-tested:

- A BFS crawler with canonicalization, scope enforcement, budgets, dedup ([`core/crawler.py`](scanner/webhound/core/crawler.py), [`core/scan_context.py`](scanner/webhound/core/scan_context.py), [`core/scope.py`](scanner/webhound/core/scope.py)).
- A rich static **artifact extractor** (links, scripts, forms, iframes, 14+ external-URL surface types) ([`core/extractor.py`](scanner/webhound/core/extractor.py), [`core/url_discovery.py`](scanner/webhound/core/url_discovery.py)).
- A real **Playwright browser pass** capturing network (fetch/XHR/WS/EventSource/iframe), rendered DOM, forms, scripts, **SPA client-routes**, with SSRF pre-screen, scope filter, and `DANGEROUS_WORDS` interaction safety ([`browser/*`](scanner/webhound/browser/)).
- **Form discovery** (static + rendered), **parameter discovery**, **API/endpoint discovery** (static + browser-observed) ([`engines/forms/*`](scanner/webhound/engines/forms/), [`engines/api_discovery/endpoint_discovery.py`](scanner/webhound/engines/api_discovery/endpoint_discovery.py)).
- **ASM-lite** (CT-log subdomains + DNS-prefix probe + asset map) ([`asm/asset_discovery.py`](scanner/webhound/asm/asset_discovery.py)).
- A **provider/stack discovery** pass ([`providers/discovery.py`](scanner/webhound/providers/discovery.py)).
- A full **security graph** (16 node types, 15 edge types, dedup, summary export) ([`graph/*`](scanner/webhound/graph/)).
- **Authenticated-crawl** plumbing (storage_state / session cookies, secret-free `AuthContext`) ([`auth/*`](scanner/webhound/auth/)).
- A **coverage summary** (counts) in `metadata.coverage_summary` ([`core/orchestrator.py:933-973`](scanner/webhound/core/orchestrator.py)).

**The gap is not signal extraction — it's orchestration, unification, and a first-class visibility product.** Three structural holes:

1. **The crawl frontier is anchor-only.** `Crawler.crawl()` seeds the queue from the root URL and then enqueues **only `artifacts.all_links` (`<a href>`)** ([`crawler.py:74,89`](scanner/webhound/core/crawler.py)). Nothing feeds back into the frontier: **sitemap.xml URLs are parsed but only emitted as findings** ([`engines/recon/robots_sitemap.py`](scanner/webhound/engines/recon/robots_sitemap.py)), **SPA client-routes are explicitly "discovery output only — Phase 2 does NOT crawl them"** ([`browser/route_extractor.py:5-7`](scanner/webhound/browser/route_extractor.py)), JS-discovered route/path literals are never visited, form `action`/API paths are never visited, and ASM subdomains are never crawled. → **Discovery breadth is capped by what the homepage links to.**
2. **No unified discovery model.** Discovered URLs live scattered across `PageArtifacts`, `BrowserTelemetry.client_routes`, `HostInventoryEntry`, `AssetMap`, `AuthContext`, grouped-finding `affected_urls`. There is **no single canonical `DiscoveredUrl` inventory** with provenance, status, depth, and skip-reason, and **no `visibility_score`** (the existing `graph_scoring` is *security severity* context; `production_readiness` is *evidence quality* — neither measures crawl coverage).
3. **No persistence or dashboard for the inventory.** Everything lands in the `scan_results.scanner_metadata` JSON blob; there is **no `discovered_*` table** and **no site-graph/page-tree UI** ([`apps/api/models/scan_result.py`](apps/api/models/scan_result.py), [`apps/web/src/app/dashboard/results/[id]/page.tsx`](apps/web/src/app/dashboard/results/[id]/page.tsx)).

**So the visibility layer = a thin orchestration + unification layer that (a) widens the frontier by feeding every discovery source back into it, (b) folds all discovered surfaces into one canonical inventory + site graph + visibility score, and (c) persists + renders it — reusing the existing extractor, browser pass, endpoint/form discovery, ASM, graph, and auth wholesale.**

---

## 2. Current crawl entrypoint & scan flow

**Entrypoint:** `Scanner.scan()` in [`core/orchestrator.py:448`](scanner/webhound/core/orchestrator.py). Triggered by the Celery worker (`worker/scan_tasks.py` → `Scanner.scan()` → `persist_scan_result()`), or directly by `scanner/run_scan.py`.

Flow today (simplified):

```
Scanner.scan()
  └─ ScanContext(target)                         # queue + scope + budgets + telemetry
  └─ SafeHttpClient(...)                          # GET/HEAD only, rate-limited, SSRF-guarded
  ├─ 1. _run_target_engines()                    # sensitive_paths probe, robots/sitemap (FINDINGS ONLY)
  ├─ 2. Crawler(ctx, client).crawl()             # BFS — seeds root, enqueues ONLY <a href> links
  ├─ 3. per-page engines (security)              # headers/csp/cors/js/forms/secrets/endpoint_discovery/threat_intel/...
  ├─ 3b. _run_browser_pass()                     # Playwright: network + rendered DOM + client_routes (discovery-only)
  ├─ 3b-ii. _record_authenticated_surface()      # folds auth browser pass into AuthContext
  ├─ 3c. CSP/redirect host inventory extension
  ├─ 4. TLS/DNS
  ├─ 4b. scan-wide threat-intel inventory pass    # aggregate_host_inventory(host_contributions)
  ├─ 4c. _run_asm()                              # ASM-lite subdomains + asset map (asm_enabled)
  ├─ 4d. framework detection / 4e. vuln libs
  ├─ 5. WADE baseline/diff / 5b. supply-chain
  ├─ 6-9. dedup → FP filter → correlation → trust/calibration → grouping → risk score
  └─ 9c. build_graph(...) → metadata.security_graph_summary
       + metadata.coverage_summary (counts)
```

**Key insight for insertion:** the crawl (step 2) and browser pass (step 3b) are where discovery happens, but they're driven by the security pipeline and the frontier is narrow. The visibility layer wraps/feeds these without changing the security engines that consume their output.

---

## 3. Capability map — existing vs. the 12-phase spec

| # | Spec phase | Status | Where it lives today / what's missing |
|---|------------|--------|----------------------------------------|
| 1 | **Map Engine + canonicalization** (`DiscoveredUrl`, `normalize_url`) | 🟡 **Partial** | `normalize_url` exists as [`UrlNormalizer.normalize`](scanner/webhound/core/scope.py) (lowercase host, strip default ports, drop fragments, collapse `//`). **Missing:** a first-class `DiscoveredUrl` record (provenance/source, depth, status, content-type, skip-reason, discovered-but-not-crawled) and a canonical inventory that aggregates ALL sources. Today only `QueueItem(url, depth)` + a `set` of visited URLs exist. |
| 2 | **URL Frontier** | 🟡 **Partial** | A real frontier exists: `ScanContext` queue + `_visited`/`_queued` dedup + budgets + scope ([`scan_context.py:149-206`](scanner/webhound/core/scan_context.py)). **Missing:** the frontier is fed **only** anchor `<a href>` ([`crawler.py:89`](scanner/webhound/core/crawler.py)); no priority ordering; sitemap/route/form/API/ASM sources are not enqueued; skip reasons are not logged per-URL (only `out_of_scope_reason()` exists, unused by the crawl loop). |
| 3 | **JS route discovery** | 🟢 **Mostly exists** | `route_extractor` pulls routes from `__NEXT_DATA__`, `__BUILD_MANIFEST`, `__NUXT__`, `data-href`, anchors, and inline-script literals ([`browser/route_extractor.py`](scanner/webhound/browser/route_extractor.py)). `url_discovery.extract_js_urls` pulls fetch/xhr/ws/eventsource/import/sourcemap/literal URLs from JS source. **Missing:** framework-hint-driven route *expansion* and feeding in-scope routes back to the frontier (Phase 2). |
| 4 | **Safe browser explorer** (Playwright, `DANGEROUS_WORDS`) | 🟢 **Exists** | [`browser/playwright_runner.py`](scanner/webhound/browser/playwright_runner.py) + [`browser/safe_interactions.py`](scanner/webhound/browser/safe_interactions.py): deny-list (submit/pay/delete/login/logout/confirm/...), allow-list (menu/expand/toggle/...), scroll, capped clicks, SSRF pre-screen, scope filter, storage_state auth. **Reuse as-is.** Minor: ensure explorer-discovered links/routes route into the unified frontier. |
| 5 | **Form discovery** | 🟢 **Exists** | [`engines/forms/form_discovery.py`](scanner/webhound/engines/forms/form_discovery.py) (`DiscoveredForm`: action/method/inputs/external/origin, static+rendered) + [`parameter_discovery.py`](scanner/webhound/engines/forms/parameter_discovery.py) + classifier in [`input_analysis.py`](scanner/webhound/engines/forms/input_analysis.py). Browser `form_extractor` adds `action_is_external` safety. **Reuse.** Missing: fold into the visibility report shape. |
| 6 | **API discovery** | 🟢 **Exists** | [`endpoint_discovery.py`](scanner/webhound/engines/api_discovery/endpoint_discovery.py): static (`analyze`) + browser-observed (`analyze_observed_requests`); REST/GraphQL/WS/SOAP/spec classification; `network_capture.looks_like_api`. **Reuse.** Missing: surface the *inventory* (not just findings) in the visibility report. |
| 7 | **Asset intelligence** | 🟢 **Exists** | `url_discovery` covers 14+ external-asset surfaces (srcset/media/preload/preconnect/manifest/favicon/jsonld/...); `HostInventoryEntry` tracks per-host provenance + classification; ASM `AssetMap`; provider/stack discovery. **Reuse.** Missing: a consolidated per-asset-type inventory view. |
| 8 | **Authenticated crawling** (`storage_state`) | 🟢 **Exists** | [`auth/*`](scanner/webhound/auth/): `build_auth`, `AuthMode` (public_only/authenticated_only/combined/deep_authenticated), `storage_state` + `session_loader` (secret-free metadata), `AuthContext` tracks authenticated pages/apis/forms/routes/third-parties. Browser pass accepts `auth_state`. **Reuse.** |
| 9 | **Site graph** | 🟢 **Exists** | [`graph/*`](scanner/webhound/graph/): `SecurityGraph` with 16 node types (SITE/PAGE/RENDERED_PAGE/SCRIPT/FORM/API_ENDPOINT/THIRD_PARTY_DOMAIN/VENDOR/IFRAME/REDIRECT/...) + 15 edge types (CONTAINS/LOADS/CALLS/SUBMITS_TO/REDIRECTS_TO/...), deterministic dedup, `build_graph`, `export_summary`, `export_json`, `graph_query`. **Reuse + extend** with a page-tree/navigation view + DiscoveredUrl ingestion. |
| 10 | **Visibility / coverage score** | 🔴 **Missing** | `coverage_summary` has raw **counts** ([`orchestrator.py:933-973`](scanner/webhound/core/orchestrator.py)) but there is **no 0-100 visibility score**. `graph_scoring` = security severity context (sensitive-page/login/checkout flags), `production_readiness` = evidence quality — neither is crawl coverage. **Build new.** |
| 11 | **Persistence** | 🔴 **Missing (as structured tables)** | All discovery metadata persists only as JSON in `scan_results.scanner_metadata` ([`apps/api/models/scan_result.py`](apps/api/models/scan_result.py)). **No `discovered_pages/routes/forms/endpoints/assets` tables.** Findings tables exist but are security-oriented. **Build new tables (or a JSON `visibility_report` column first, tables later).** |
| 12 | **Dashboard** | 🔴 **Missing** | Results view ([`apps/web/.../results/[id]/page.tsx`](apps/web/src/app/dashboard/results/[id]/page.tsx)) shows findings/risk/external-domains but **no site graph, page tree, or coverage view.** `browser_coverage` reporting exists server-side only. **Build new tab + components.** |

**Bottom line:** Phases 3-9 are largely *built* (extraction substrate). Phases 1-2 are *partially* built but the frontier is too narrow. Phases 10-12 (the visibility *product* — score, persistence, dashboard) are genuinely *new*.

---

## 4. Where the visibility layer inserts (architecture)

The layer is a **discovery orchestrator** that wraps the existing crawl + browser pass, runs **before** the security engines consume page artifacts, and feeds a **unified frontier**. It owns a new `VisibilityContext` (the canonical `DiscoveredUrl` inventory) that lives alongside `ScanContext`.

```
Scanner.scan()
 ┌─────────────────────────────────────────────────────────────────────────┐
 │  NEW: Visibility layer (core/visibility/*) — runs BEFORE security engines │
 │                                                                           │
 │   Phase 1  MapEngine: DiscoveredUrl + canonical inventory (wraps          │
 │            UrlNormalizer; one record per URL w/ provenance+status+depth)   │
 │   Phase 2  Frontier seeding from EVERY source (the key fix):              │
 │              • robots/sitemap URLs  ← reuse robots_sitemap parser          │
 │              • static anchors/forms ← reuse extractor                      │
 │              • SPA client_routes    ← reuse route_extractor (now ENQUEUED) │
 │              • JS fetch/route paths ← reuse url_discovery.extract_js_urls   │
 │              • ASM subdomains       ← reuse asm (when asm_enabled)         │
 │            All gated by ScopeChecker + robots policy; skip reasons LOGGED. │
 │   Phase 3-4 reuse browser pass + route/JS extractors (no duplication)      │
 │   Phase 5-7 reuse form_discovery / endpoint_discovery / url_discovery      │
 │   Phase 8  reuse auth (storage_state) for authenticated frontier           │
 └─────────────────────────────────────────────────────────────────────────┘
        │ writes ctx.visibility (canonical inventory)
        ▼
   existing crawl loop + per-page security engines  (UNCHANGED — they still
        read PageArtifacts; the frontier just hands them MORE in-scope pages)
        ▼
   existing browser pass + threat-intel inventory + ASM + graph (UNCHANGED)
        ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │   Phase 9   build_graph(...) — EXTEND to ingest DiscoveredUrl + page tree  │
 │   Phase 10  NEW visibility_score(inventory, graph) → metadata.visibility   │
 │   Phase 11  persist visibility_report (JSON col first; tables next)        │
 │   Phase 12  dashboard: Visibility tab (site graph + page tree + coverage)  │
 └─────────────────────────────────────────────────────────────────────────┘
```

**Design rules honored:** reuse `UrlNormalizer`, the `ScanContext` queue, `ScopeChecker`, `robots_sitemap` parser, `route_extractor`, `url_discovery`, the Playwright pass, `form_discovery`/`endpoint_discovery`, `asm`, `graph`, and `auth`. The visibility layer **adds an orchestrator + a canonical model + a score + persistence/UI**; it does **not** re-implement extraction.

**Integration choice (recommended):** introduce the frontier-widening as an **opt-in `VisibilityContext`** attached to `ScanContext` (`ctx.visibility`), and have the existing `Crawler.crawl()` consult it for seed/enqueue sources. The security per-page loop is unchanged — it simply receives more in-scope `CrawlResult`s. A profile/option flag (`visibility_enabled`, default off → behavior identical to today) keeps the change safe and reversible.

---

## 5. Per-phase plan — files to MODIFY vs. CREATE

> Each phase: tests first/with, then a small safe commit. `.venv-api` + `PYTHONPATH=scanner`; targeted `--noconftest` tests only; never alembic/full-tree; wrap shell in `timeout`.

### Phase 1 — Map Engine + canonicalization
- **CREATE** `scanner/webhound/core/visibility/__init__.py`
- **CREATE** `scanner/webhound/core/visibility/discovered_url.py` — `DiscoveredUrl` dataclass (`url`, `normalized`, `source` enum: sitemap/anchor/js_route/js_fetch/form_action/api/asm/redirect/manual, `depth`, `discovered_from`, `status`: pending/crawled/skipped, `skip_reason`, `content_type`, `status_code`, `is_in_scope`) + `normalize_url()` thin wrapper delegating to `UrlNormalizer.normalize` (single source of truth — do NOT fork canonicalization).
- **CREATE** `scanner/webhound/core/visibility/inventory.py` — `DiscoveredUrlInventory` (dedup by normalized URL, merge provenance, query by source/status).
- **CREATE** `scanner/tests/test_visibility_discovered_url.py`, `test_visibility_inventory.py`.
- **MODIFY** none yet (pure additive model).

### Phase 2 — Frontier (the core fix)
- **CREATE** `scanner/webhound/core/visibility/frontier.py` — `VisibilityFrontier`: wraps `ScanContext.enqueue`, adds priority + per-URL skip logging via `ScopeChecker.out_of_scope_reason` + robots policy; exposes `seed_from(sources)`.
- **CREATE** `scanner/webhound/core/visibility/context.py` — `VisibilityContext` holding the inventory + frontier; attaches as `ScanContext.visibility`.
- **MODIFY** `scanner/webhound/core/scan_context.py` — add optional `self.visibility` slot (default `None`; no behavior change when absent).
- **MODIFY** `scanner/webhound/core/crawler.py` — when `ctx.visibility` is present, record every dequeued URL + every discovered link into the inventory with provenance and **log the skip reason for every URL not enqueued**. Anchor enqueue stays; new sources are added through the frontier.
- **MODIFY** `scanner/webhound/engines/recon/robots_sitemap.py` — expose the already-parsed sitemap `<loc>` URLs + robots `Allow`/`Disallow` as a **returnable list** (not only findings) so the frontier can seed them. (Additive method; existing `analyze` untouched.)
- **CREATE** `test_visibility_frontier.py` (incl. robots-respect + skip-reason logging tests).

### Phase 3 — JS route discovery → frontier
- **REUSE** `browser/route_extractor.py` + `core/url_discovery.extract_js_urls` (no rewrite).
- **CREATE** `scanner/webhound/core/visibility/route_harvester.py` — collects `client_routes` + JS path literals, filters to in-scope navigable routes, hands them to the frontier (this is what flips routes from "discovery-only" to "optionally crawled").
- **CREATE** `test_visibility_route_harvester.py`.
- **MODIFY** none in `route_extractor` (read its output).

### Phase 4 — Safe browser explorer
- **REUSE** `browser/playwright_runner.py` + `safe_interactions.py` as-is (DANGEROUS_WORDS safety already enforced).
- **MODIFY** `scanner/webhound/core/orchestrator.py` (`_run_browser_pass`) — route explorer-surfaced links/routes into `ctx.visibility` frontier (additive; gated on `ctx.visibility` presence).
- **CREATE** `test_visibility_browser_integration.py` (uses existing browser test fixtures/mocks).

### Phase 5-7 — forms / API / assets inventories
- **REUSE** `engines/forms/form_discovery.py`, `engines/api_discovery/endpoint_discovery.py`, `core/url_discovery.py`, `asm/asset_discovery.py`.
- **CREATE** `scanner/webhound/core/visibility/surfaces.py` — folds `DiscoveredForm`, endpoint inventory, `HostInventoryEntry`, `AssetMap` into the visibility report's `forms/api/assets/third_party` sections (read-only aggregation; no new extraction).
- **CREATE** `test_visibility_surfaces.py`.

### Phase 8 — Authenticated crawl
- **REUSE** `auth/*` + browser `auth_state`. **MODIFY** the frontier to accept an authenticated seed set from `AuthContext.authenticated_routes/apis`. Respect verified-domain boundaries.
- **CREATE** `test_visibility_auth_frontier.py`.

### Phase 9-10 — Graph + visibility score
- **MODIFY** `scanner/webhound/graph/graph_builder.py` — ingest `DiscoveredUrl` inventory so the graph includes discovered-but-uncrawled pages/routes as nodes (clearly flagged), and build a navigation/page-tree edge set. Keep existing security-graph behavior intact.
- **CREATE** `scanner/webhound/core/visibility/score.py` — `visibility_score(inventory, graph, budgets)` → 0-100 with transparent breakdown (pages_found vs crawled ratio, route coverage, API/form/asset coverage, depth reached, skip-reason rollup, limitations). Mirrors the `risk_breakdown` "show WHY" pattern.
- **CREATE** `test_visibility_score.py`, extend `test_graph_builder.py`.

### Phase 11 — Persistence
- **CREATE** `scanner/webhound/core/visibility/report.py` — `build_visibility_report(ctx)` → the canonical JSON: `{domain, crawl_mode, pages_found, pages_crawled, forms, api, js_routes, assets, third_party counts, site_graph_generated, visibility_score, limitations}`.
- **MODIFY** `scanner/webhound/core/orchestrator.py` — after graph build, write `result.metadata["visibility_report"]` (best-effort, mirrors existing metadata blocks).
- **MODIFY (API)** `apps/api/services/result_persistence.py` — persist `visibility_report` (Step 1: it already flows via `scanner_metadata`; Step 2: dedicated `visibility_reports` / `discovered_*` tables + a new Alembic migration — **migration authored but NOT auto-run per env rules**).
- **CREATE** API tests under `apps/api/tests/`.

### Phase 12 — Dashboard
- **CREATE (web)** `apps/web/src/components/results/visibility-tab.tsx`, `site-graph.tsx` (Cytoscape/D3), `page-tree.tsx`, `coverage-score-card.tsx`, `skip-reasons-panel.tsx` (explainability: WHY each URL was skipped).
- **MODIFY (web)** `apps/web/src/app/dashboard/results/[id]/page.tsx` — add a "Visibility" tab; `apps/web/src/lib/api.ts` — fetch the report.
- **MODIFY (API)** add `GET /scan-results/{id}/visibility` router/schema.

---

## 6. Reuse map (do NOT duplicate)

| Need | Reuse (don't rebuild) |
|------|------------------------|
| URL canonicalization | `core/scope.py::UrlNormalizer.normalize` |
| Scope/budget/queue | `core/scan_context.py`, `core/scope.py::ScopeChecker` |
| Static extraction | `core/extractor.py`, `core/url_discovery.py` |
| SPA routes | `browser/route_extractor.py` |
| Browser render + network + safety | `browser/playwright_runner.py`, `safe_interactions.py`, `network_capture.py` |
| Forms / params | `engines/forms/form_discovery.py`, `parameter_discovery.py` |
| API endpoints | `engines/api_discovery/endpoint_discovery.py` |
| Host/asset inventory | `core/url_discovery.py::aggregate_host_inventory`, `asm/asset_discovery.py` |
| Provider stack | `providers/discovery.py` |
| Site graph | `graph/graph_builder.py`, `graph/models.py`, `graph/graph_export.py` |
| Auth | `auth/*` |
| Robots/sitemap parse | `engines/recon/robots_sitemap.py` |

---

## 7. Suggested order & Definition of Done

**Order (small safe commits, tests per phase):** 1 → 2 → 3 → 4 → 5-7 → 8 → 9-10 → 11 → 12.

**Definition of Done:** a `visibility_report` JSON is produced for every scan (when enabled) containing: `domain`, `crawl_mode`, `pages_found`, `pages_crawled`, `forms`/`api`/`js_routes`/`assets`/`third_party` counts, `site_graph_generated`, `visibility_score`, and `limitations`. Every discovered URL carries provenance + status, and **every skipped URL has a logged, dashboard-explainable reason.**

---

## 8. Safety & constraints carried into every phase

- **Default off / no regression:** gate behind `visibility_enabled` (option/profile). With it off, the scan behaves exactly as today.
- **Don't break security engines:** the per-page security loop and all engines are untouched; they only ever receive *more in-scope pages*.
- **Destructive behavior DISABLED:** never submit destructive forms, purchase, or click delete/logout/pay/confirm/cancel/deactivate — already enforced by `safe_interactions.DENY_RE`; the frontier never enqueues a form *submission*, only navigable GET URLs.
- **Scope + robots:** every frontier add is gated by `ScopeChecker`; respect `robots.txt` by default, override only when the verified customer explicitly opts in (`respect_robots_txt`).
- **Verified-domain boundaries** respected for authenticated crawl.
- **Rate/concurrency limits, timeouts, retries** inherited from `SafeHttpClient` / browser pass; no new uncapped loops.
- **Tests for every new parser/aggregator.** Never log secrets (auth stays secret-free via existing `*Meta` models).

---

*End of STEP 0 audit. Standing by for go-ahead to begin Phase 1.*
