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
| 5 (next) | Recommended: WADE browser baselining (new script/domain/API/form detection), crawling in-scope client routes, wiring dormant js_fetcher / vulnerable_libs / source_map_probe engines (adds live script fetching — own reviewed change) | ⬜ |
| Later | Authenticated scanning (storage state, session cookies, read-only crawl), framework-specific support depth | ⬜ |

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
