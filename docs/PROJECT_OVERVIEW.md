# WebHound Security — Project Overview & Handoff

> Living handoff document. Written 2026-06-06 so any session (desktop,
> phone, web) can pick up with full context. Update when architecture
> or goals shift.

## What WebHound is

WebHound Security (**webhoundsecurity.com**) is a website attack-surface
discovery and monitoring SaaS. Customers add their site, WebHound scans
it passively (safe-mode: GET/HEAD only, never submits forms, never
destructive), reports trustworthy findings, and monitors for changes
over time (WADE). The product promise: **accuracy over quantity — never
create panic from weak evidence.**

## Monorepo layout

```
WebHound/
├── apps/
│   ├── web/        Next.js frontend (marketing site + dashboard) — Vercel
│   └── api/        FastAPI backend (auth, orgs, scans, billing) — Railway
├── worker/         Celery workers (scan execution, reports, alerts) — Railway
├── scanner/        `webhound` Python package — the scan engine itself
│   ├── webhound/
│   │   ├── core/         orchestrator, crawler, extractor, scope, SSRF guard,
│   │   │                 trust_policy, severity_calibrator, risk_scoring,
│   │   │                 finding_presenter, finding_grouper, correlation
│   │   ├── browser/      Playwright pass: runner, models (BrowserDiscovery),
│   │   │                 network_capture, form_extractor, script_collector,
│   │   │                 route_extractor, safe_interactions
│   │   ├── engines/      headers, cookies, tls_dns, forms, javascript,
│   │   │                 secrets, recon (sensitive_paths), compromise,
│   │   │                 cms (wordpress/shopify/wix), api_discovery,
│   │   │                 threat_intel
│   │   ├── wade/         Website Anomaly Detection Engine (baseline → diff
│   │   │                 → anomaly score → classify)
│   │   ├── threat_intel/ domain_classifier (risk tiers + vendor categories),
│   │   │                 URLhaus + VirusTotal clients (opt-in via env)
│   │   ├── models/       Finding, Evidence, GroupedFinding, ScanResult,
│   │   │                 Severity, Target/ScanOptions
│   │   └── reporting/    summary, json, markdown, csv, sarif, pdf,
│   │                     compliance, production_readiness
│   └── tests/      ~1850 pytest tests, fully offline (mocked transports)
├── packages/       shared JS packages
├── infra/, scripts/, docs/
└── docker-compose*.yml, railway.toml
```

## Infrastructure

| Piece | Where | Notes |
|---|---|---|
| Frontend (`apps/web`) | **Vercel** | Push to `main` auto-deploys. NOT on Railway. |
| API (`apps/api`) | **Railway** | FastAPI; service IDs are in the local memory file `reference_railway_services.md` (use `railway` CLI). |
| Worker (`worker/`) | **Railway** | Celery; queues scan jobs, reports, alerts, threat-intel refresh, fraud checks, guest cleanup. |
| Postgres | **Railway** | Prod inspection: `railway run` + `DATABASE_PUBLIC_URL`. Invariant: owned websites/scans must have `org_id` (`chk_websites_owned_has_org`); use `ensure_personal_org`. |
| Redis | **Railway** | Celery broker + API rate limiting. `apps/api` tests need a REAL Redis running (no mock). |
| Domain / DNS | **Cloudflare** | `webhoundsecurity.com` (migration from webhound.io complete). |
| Billing | **Stripe** | Inspect via Stripe curl helpers (see memory `reference_query_prod_db_and_stripe.md`). |
| Browser pass | Worker boxes | Playwright Chromium; gated by `WEBHOUND_BROWSER_ENABLED=1` env on the worker + profile flag. |

## How a scan flows

1. API receives scan request → validates target/ownership → enqueues Celery job.
2. Worker runs `scanner` package: `Scanner.scan()` (orchestrator).
3. Pipeline: target engines → BFS crawl (SafeHttpClient: SSRF-guarded,
   rate-limited) → per-page engines → **browser pass** (Playwright,
   ENTERPRISE/STANDARD/DEEP profiles, operator-gated) → rendered-DOM
   engine pass → TLS/DNS → threat-intel inventory → ASM (enterprise)
   → WADE baseline/diff → dedup → FP filter → correlation →
   **trust policy + severity calibration** → grouping →
   **centralized risk scoring** → report sections → coverage summary.
4. Results persisted via API; dashboard renders from JSON metadata.

## Scan profiles

`quick` (5pg) · `standard` (25pg, browser-enabled) · `deep` (100pg,
browser-enabled) · `monitor` (WADE-optimized) · `enterprise` (200pg,
browser + ASM). Browser only actually launches when the worker has
`WEBHOUND_BROWSER_ENABLED=1` AND Playwright + Chromium installed;
otherwise it defers cleanly and the scan completes statically.

## The trust system (core product differentiator)

- Every finding: `finding_type` ∈ confirmed_risk / likely_risk /
  heuristic_signal / hardening / inventory, plus `confidence_label`
  ∈ confirmed / high / medium / low / heuristic
  (`core/trust_policy.py`).
- Severity calibrator (`core/severity_calibrator.py`): demotion-only
  clamps — heuristics can't be CRITICAL, missing CSP caps MEDIUM,
  COOP/COEP/Server-header cap LOW, threat-intel heuristics cap MEDIUM
  without URLhaus/VT confirmation. Every demotion recorded in
  `metadata.calibration`.
- Risk scoring (`core/risk_scoring.py`): CRITICAL 35 / HIGH 20 /
  MEDIUM 8 / LOW 2 × type factor (confirmed 1.0, likely 0.75,
  heuristic 0.15, hardening 0.20, inventory 0) × confidence factor
  (medium ×0.5, low ×0.25). Caps: hardening ≤15, heuristic ≤10,
  headers ≤12, repeats damped. Legacy algorithm preserved for old
  results (annotation-driven selection).
- Reporting sections (`core/finding_presenter.py`): Security Risks /
  Hardening Recommendations / Inventory / WADE Changes, with calm
  wording (Fix immediately / Fix soon / Review and schedule /
  Hardening improvement / Discovered asset).

## Roadmap status (as of 2026-06-06)

| Phase | Scope | Status |
|---|---|---|
| 1 | Browser-aware discovery: rendered DOM/links/forms capture + rendered engine pass | ✅ pushed |
| 2 | Browser discovery collection: network/API classification, scripts, routes, cookies, console, safe interactions, scope/SSRF nav screen | ✅ pushed |
| 3 | Feed discovery into engines: BrowserDiscovery on ScanContext, JS/third-party/API engines on rendered data, vendor categories, coverage summary | ✅ pushed |
| 4 | Trustworthy scoring: trust policy, severity calibrator, centralized risk scoring, presenter + report sections | ✅ code complete; full suite was running at handoff — verify green, then push if not already pushed |
| 5 | WADE 2.0 intelligence: expanded baselines (dom_hash, third-party, API, iframe, redirect, tech), change taxonomy + classifier, vendor awareness, suppression (alert fatigue), timeline | ✅ pushed |
| 6 | Correlation engine: customer-facing security stories (admin/auth/payment/supply-chain/compromise/website-mod/api/header/cookie), 11 standardized CorrelationTypes, confidence by converging evidence, no-double-count scoring | ✅ code complete; verify full suite then push |
| 7 | Framework-aware discovery: `webhound/frameworks/` profile system (WordPress/Shopify/Wix/Webflow/Next.js/React/Vue/Angular), detection + known-surface inventory + coverage metrics + WADE platform normal-change suppression | ✅ code complete; verify full suite then push |
| 8 | Authenticated scanning: `webhound/auth/` (session cookies, Playwright storageState, login recordings), read-only AuthGuard, auth page-context classification, authenticated discovery/WADE, `auth_mode` option | ✅ code complete; verify full suite then push |
| 9 | Monitoring & alerting: `webhound/monitoring/` — cross-scan change history, alert tiers, suppression, risk-delta, notification policies, monitor engine | ✅ code complete; verify full suite then push |
| 10 | Validation lab: `scanner/validation/` — ground-truth mock targets, real-scanner benchmark runner, precision/recall/coverage, framework + engine scorecards, quality score, regression gate | ✅ code complete; verify full suite then push |
| 11 (next) | Recommended: wire monitoring into the worker (persist ChangeHistory in BaselineStore, run_monitoring after each scan, actual notification delivery: email/SMS/webhook) + dashboard timeline UI | ⬜ |
| Later | Crawl in-scope client routes, wire dormant js_fetcher / vulnerable_libs / source_map_probe (live script fetching — own reviewed change), login-recording live replay, expand validation ground truth | ⬜ |

## Validation lab (Phase 10)
`scanner/validation/` (top-level package, sibling of `webhound/`) — runs
the REAL scanner against safe ground-truth mock targets and measures
accuracy. `ground_truth` (clean per-platform sites + vulnerable +
compromised), `benchmark_runner` (mock transport + full pipeline),
`finding_validator` (TP/FN/FP), `precision_report`/`recall_report`/
`coverage_report` (quality score + marketing metrics), framework +
engine scorecards, `regression_runner` (gate changes on quality floor +
FP-clean + delta vs baseline). Run: `python -c "from validation.benchmark_runner import run_targets_sync; from validation import build_coverage_report, validate_run; print(build_coverage_report(validate_run(run_targets_sync())).to_dict())"`.

## Monitoring & alerting (Phase 9)
`webhound/monitoring/` — pure layer consuming scan metadata.
`change_history` (ChangeEvent/ChangeHistory, AlertTier informational→
critical, ChangeCategory, TrackedAsset); `change_tracker` accumulates
WADE timeline across scans; `risk_delta` explains score moves;
`alert_manager` builds tiered+suppressed alerts with human stories;
`notification_policy` (immediate/daily/weekly/critical-only/custom +
monitoring cadences); `monitor_engine.run_monitoring()` orchestrates →
MonitorResult (updated history, risk delta, alerts, delivery plan,
timeline). No UI, no actual delivery yet — that's the worker
integration in Phase 10.

## Authenticated scanning (Phase 8)
`webhound/auth/` — read-only authenticated scanning. Three methods:
session cookies, Playwright storageState (preferred), login recordings
(secrets as `{{placeholder}}`, never plaintext). `AuthGuard` is
deny-by-default for any state-changing action (purchase/delete/save/
logout/...); `assert_read_only` raises on non-GET/HEAD. Cookie/token
VALUES are never stored — `AuthContext.to_dict()` is secret-free.
`Scanner(auth_session_cookies=..., auth_storage_state=...)` + `ScanOptions.auth_mode`
(public_only/authenticated_only/combined/deep_authenticated). Browser
real-path stays operator-gated (`WEBHOUND_BROWSER_ENABLED`).

## Frameworks (Phase 7)
`webhound/frameworks/` — data-driven `FrameworkProfile`s with detection
signals + known surface (routes/assets/APIs/admin/forms/vendors) +
WADE normal-change patterns. `registry.detect_scan()` runs over page
artifacts + rendered global vars; coverage lands in
`metadata.frameworks`. Passive: known surface is inventory candidates,
never auto-fetched. `is_normal_framework_change()` lets WADE suppress
routine platform deploys.

## Correlation / stories (Phase 6)
`core/security_stories.py` builds customer-facing stories over grouped
findings + the WADE timeline. `core/correlation.py` is the lower-level
threat-chain engine (confidence bumps + cluster findings, runs
pre-grouping). Stories annotate members with `correlation_id`/`type`/
`confidence` and land in `metadata.security_stories` — they create no
scored findings, so they never inflate risk.

## Build / test / deploy

```bash
# Scanner (pure Python, offline tests)
cd scanner && python3 -m pytest tests/ -q       # ~17 min full, target: 0 failures
python3 -m compileall scanner

# API tests — need running Redis; SQLite fixture; see conftest gotchas
cd apps/api && pytest tests

# Web
cd apps/web && npm run build

# Deploys: push to main → Vercel (web) auto-deploys; Railway deploys api/worker.
```

Conventions: small safe commits, compile+test after every change,
commit and push after changes without asking (standing preference).
Keep files <500 lines. Never commit secrets.

## Key env vars (worker/scanner)

- `WEBHOUND_BROWSER_ENABLED=1` — allow Playwright browser pass
- `VIRUSTOTAL_API_KEY` / `ENABLE_URLHAUS=1` — threat-intel enrichment (opt-in)
- `WEBHOUND_DEFAULT_ENGINE_TIMEOUT`, `WEBHOUND_ENGINE_TIMEOUT_<ENGINE>` — engine timeouts
- `WEBHOUND_ASM_ALLOW_NETWORK=0` — disable CT-log lookup in ASM

## Safety contract (never violate)

GET/HEAD only · never submit forms · never replay POST · no
destructive actions · browser clicks are deny-list-first with positive
safe signal required and never inside a form · SSRF guard on every
fetch and browser navigation · scope respected everywhere · cookie
values never stored · secrets masked in evidence.
