# WebHound — Complete Project Reference

> Generated 2026-06-14 as a consolidated project reference for external LLM context.
> Covers everything built from initial commit through Phase 9B (PR #21, commit 06bcf0e).
> Accurate as of this date. Items marked **[PENDING]** or **[NOT YET]** are not live.

---

## Table of Contents

1. [Executive Overview](#1-executive-overview)
2. [Architecture](#2-architecture)
3. [The Scanner](#3-the-scanner)
4. [Findings & Severity Model](#4-findings--severity-model)
5. [WADE — Baseline, Diff & Advisory Intelligence](#5-wade--baseline-diff--advisory-intelligence)
6. [AI Knowledge Layer (Corpus)](#6-ai-knowledge-layer-corpus)
7. [Retrieval System](#7-retrieval-system)
8. [The AI Brain (Obsidian + Graph + Local LLM)](#8-the-ai-brain-obsidian--graph--local-llm)
9. [Threat Intelligence](#9-threat-intelligence)
10. [Providers & Platform Access](#10-providers--platform-access)
11. [Integrations & Infrastructure](#11-integrations--infrastructure)
12. [Database Models](#12-database-models)
13. [External Tools & Libraries](#13-external-tools--libraries)
14. [Phase History — Full Build Chronology](#14-phase-history--full-build-chronology)
15. [Current State, Known Gaps & Roadmap](#15-current-state-known-gaps--roadmap)

---

## 1. Executive Overview

**WebHound** is a consent-based website security scanner and continuous monitoring SaaS. Customers connect their own domains, authorize WebHound to scan them, and receive findings, alerts, and an advisory intelligence layer (WADE) that tracks security posture changes over time.

### What it is

- **Passive security scanner** — GET/HEAD only, no form submission, no JS execution. Detects misconfigurations, exposed secrets, vulnerable libraries, compromised third-party scripts, TLS/DNS hygiene issues, and more. 32 engine modules across 14 families.
- **WADE monitoring** — Baseline-diff engine that tracks every scan's findings over time, detects anomalies, and correlates behavioral patterns (TLS instability, third-party script explosion, login-form flapping, etc.) into scored risk signals.
- **Advisory intelligence** — A separate, read-only reasoning layer (Phase 8D) that enriches WADE findings with attack-chain context, root-cause hypotheses, and customer-safe language drawn from a curated knowledge corpus. Advisory mode only — production scoring is unchanged.
- **AI Knowledge Layer** — 487 curated manifest records / 1161 indexed chunks from OWASP standards, MDN, detection-engineering repos (ZAP, Nuclei, DalFox, etc.), threat-intel sources, and vulnerability taxonomy (CVE/CWE/CVSS/OWASP) — used as a retrieval backend for WADE reasoning.
- **Provider-aware** — Knows about Cloudflare, Vercel, Netlify, CloudFront, Akamai, Fastly, Shopify, Wix, and others; suppresses false positives caused by CDN challenge pages and shared IPs; surfaces provider-specific remediation steps.

### Who it's for

- Small and medium web businesses that want continuous security monitoring without a dedicated security team.
- Consent-required — customers must verify domain ownership before any scan runs.

### Current phase

Alpha / early beta. Core scanner and WADE are production-deployed (Railway API + Vercel frontend). AI advisory layer is in shadow mode (reads only, never writes). Phase 9B (validation harness + test coverage) completed 2026-06-14.

---

## 2. Architecture

### High-level topology

```
Browser / Mobile
      │
      ▼
apps/web  (Next.js 14, App Router)
      │ HTTPS REST + WebSocket
      ▼
apps/api  (FastAPI, Python 3.12)
      │
      ├── PostgreSQL (Neon / Railway)
      ├── Redis (Railway)
      ├── Resend (email)
      ├── Stripe (billing)
      └── scanner/webhound/  (Python package, same process or worker)
```

### Repository structure

```
WebHound/
├── apps/
│   ├── api/                  FastAPI backend
│   │   ├── models/           SQLAlchemy models (38 model files)
│   │   ├── admin/            Admin routes
│   │   ├── billing/          Stripe webhooks + subscriptions
│   │   ├── internal/         Internal API routes
│   │   ├── platform/         Provider-access routes
│   │   ├── services/         Business logic (wade_correlation, etc.)
│   │   ├── main.py           Application entry point
│   │   ├── config.py         Boot-time validation + config
│   │   ├── database.py       SQLAlchemy async engine
│   │   ├── middleware.py      Rate limiting, CORS, auth
│   │   └── migrations/       Alembic migrations
│   └── web/                  Next.js 14 frontend
│       └── src/
│           ├── app/          App Router pages + layouts
│           ├── components/   UI components
│           ├── lib/          API client, hooks, utilities
│           └── providers/    Context providers
├── scanner/                  Python scanner package
│   ├── webhound/
│   │   ├── core/             Extractor, orchestrator, models
│   │   ├── engines/          32 scan engine modules
│   │   ├── wade/             Production WADE pipeline
│   │   ├── threat_intel/     TI enrichment service
│   │   └── recon/            Provider discovery
│   ├── validation/           Validation harness (Phase 9B)
│   └── tests/                2610 scanner unit tests
├── scripts/
│   ├── ai/                   AI knowledge ingestion scripts
│   └── wade/                 WADE advisory retrieval + reasoning
├── corpus/                   AI knowledge corpus
│   ├── normalized/           Normalized source docs
│   ├── indexes/              TF-IDF + dense embeddings
│   └── exports/              LightRAG + Graphiti exports
├── docs/ai/                  Phase result docs + AI planning
├── vault/                    Obsidian AI Brain vault
└── infra/                    Docker compose + infra configs
```

### Frontend (Next.js 14 / Vercel)

- Next.js 14 with App Router, TypeScript, Tailwind CSS
- Deployed to Vercel (webhoundsecurity.com)
- Auth: NextAuth.js with Google OAuth + GitHub OAuth + email/magic-link
- Key pages: dashboard, scan detail, finding detail, WADE timeline, provider-access wizard, billing, onboarding wizard

### Backend (FastAPI / Railway)

- Python 3.12, FastAPI, SQLAlchemy 2.x async, Alembic migrations
- Deployed to Railway with static outbound IPs (`162.220.234.240`, `152.55.180.240`, `152.55.180.241`)
- PostgreSQL (Neon or Railway Postgres)
- Redis (Railway Redis) for job queues and rate limiting
- Boot-time config validation in `config.py` — refuses to start in production if: SECRET_KEY is default, DATABASE_URL is unset/non-Postgres, REDIS_URL invalid, DEV bypass flags set without explicit opt-in

### Scanner package

- Pure Python 3.12 package (`scanner/webhound/`)
- Runs in the same Railway process or a dedicated worker
- All engine logic is unit-tested against synthetic `PageArtifacts` — no live network required for tests
- 2610 tests, 0 failures (as of Phase 9B)

---

## 3. The Scanner

### Safe-mode contract

The scanner is passive-only by design:

- **HTTP methods:** GET and HEAD only. No POST, PUT, DELETE, PATCH.
- **No form submission** — `SafeInputTester` generates `InputTestPlan` objects but `submitted=False` and `method="none"` are invariants enforced and proven by test.
- **No JS execution** — no headless browser in the passive scan path; `PageArtifacts` are populated from raw HTML/headers.
- **Scope enforcement** — all active probes are scoped to the target hostname; no cross-origin requests.
- **Rate limits** — `max_pages`, `max_depth`, and per-second rate limits always respected.
- **Engine isolation** — one engine error never aborts the scan; errors are caught and logged.
- **Provider detection first** — `provider_discovery.py` runs before the main pipeline, building a `ProviderProfile` so every engine can contextualize its findings.

### PageArtifacts (core data container)

All passive engines receive a `PageArtifacts` object extracted from one page:

| Field | Type | Description |
|-------|------|-------------|
| `url` | str | Page URL |
| `status_code` | int | HTTP status |
| `content_type` | str | Content-Type header |
| `title` | str | `<title>` tag |
| `all_links` | list[str] | All links found on page |
| `internal_links` | list[str] | Same-host links |
| `external_links` | list[str] | Cross-host links |
| `scripts` | list[ExtractedScript] | Script tags (src + inline content) |
| `inline_scripts` | list[str] | Inline script text blocks |
| `external_script_urls` | list[str] | External script src values |
| `forms` | list[ExtractedForm] | Form elements + inputs |
| `cookies` | list[Cookie] | Set-Cookie headers parsed |
| `response_headers` | dict[str, str] | All response headers |
| `meta_tags` | dict[str, str] | Meta tag name→content |
| `extracted_at` | datetime | Extraction timestamp |

### Engine families and modules (14 families, 32 modules)

#### Family 1 — Security Headers (`security_headers`)
Module: `engines/headers/security_headers.py`

Analyzes HTTP response headers for missing or weak security controls.

| Finding | Severity | CVSS | Notes |
|---------|----------|------|-------|
| `csp_missing` | MEDIUM | 5.4 | Content-Security-Policy absent |
| `hsts_missing` | MEDIUM | 6.1 | Strict-Transport-Security absent |
| `x_frame_options_missing` | LOW | 4.3 | Clickjacking protection absent |
| `referrer_policy_missing` | LOW | 3.1 | Referrer-Policy absent |
| `permissions_policy_missing` | INFO | 0.0 | Permissions-Policy absent |
| `x_content_type_options_missing` | LOW | 4.3 | MIME-sniffing protection absent |
| `server_version_disclosure` | LOW | 5.3 | Server version in header |
| `csp_weak` | MEDIUM | 5.4 | CSP present but contains unsafe-inline/unsafe-eval |

Tests: 36 (`test_headers.py`, `test_headers_engines.py`)

#### Family 2 — Cookies (`cookies`)
Module: `engines/cookies/cookie_scanner.py`

Analyzes Set-Cookie headers for missing security attributes. Passive only — cookies set by JavaScript after page load are not analyzed (documented FN).

| Finding | Severity | CVSS | Notes |
|---------|----------|------|-------|
| `missing_secure` | MEDIUM | 5.9 | Secure flag absent |
| `missing_httponly` | MEDIUM | 5.9 | HttpOnly flag absent |
| `missing_samesite` | LOW | 3.1 | SameSite attribute absent |
| `overly_broad_domain` | LOW | 3.1 | Domain attribute too broad |

Tests: 36 (`test_cookies.py`)

#### Family 3 — TLS Checker (`tls_checker`)
Module: `engines/tls_dns/tls_checker.py`

Active HEAD probe to check TLS certificate validity and protocol strength.

| Finding | Severity | CVSS | Notes |
|---------|----------|------|-------|
| `cert_expired` | HIGH | 8.6 | Certificate past expiry |
| `cert_expiring_soon` | MEDIUM | 5.9 | Certificate expires within 30 days |
| `weak_protocol` | HIGH | 7.4 | TLS 1.0/1.1 or SSL 3.0 |
| `weak_cipher` | MEDIUM | 5.9 | Weak cipher suite offered |

**Known FN:** CDN-terminated TLS — scanner talks to CDN certificate, not origin. Weak protocols/ciphers at origin behind CDN are not visible. Provider flag attached to findings.

Tests: 71 (`test_tls_dns_engines.py`)

#### Family 4 — DNS Checker (`dns_checker`)
Module: `engines/tls_dns/dns_checker.py`

DNS record analysis for email authentication, zone security, and subdomain takeover risk.

| Finding | Severity | CVSS | Notes |
|---------|----------|------|-------|
| `spf_missing` | MEDIUM | 6.5 | No SPF record |
| `spf_plus_all` | HIGH | 7.5 | SPF with +all (unrestricted) |
| `dmarc_missing` | MEDIUM | 5.4 | No DMARC record |
| `dkim_missing` | LOW | 3.1 | No DKIM record observed |
| `dnssec_missing` | MEDIUM | 5.9 | DNSSEC not configured |
| `caa_missing` | LOW | 3.1 | No CAA record |
| `mta_sts_missing` | LOW | 3.1 | No MTA-STS policy |
| `takeover_candidate` | CRITICAL | 9.1 | CNAME + dangling resource check |

Tests: 71 (`test_tls_dns_engines.py`)

#### Family 5 — JavaScript Analysis (5 modules)

**`js_analyzer`** (`engines/javascript/js_analyzer.py`): Detects dangerous JS patterns in inline scripts.

| Finding | Severity | CVSS |
|---------|----------|------|
| `eval_call` | LOW | 3.7 |
| `new_function` | MEDIUM | 5.4 |
| `document_write` | LOW | 3.7 |
| `innerhtml_assign` | LOW | 3.7 |

**`obfuscation_detector`** (`engines/javascript/obfuscation_detector.py`): Detects packed/obfuscated JavaScript.

| Finding | Severity | CVSS | Notes |
|---------|----------|------|-------|
| `packer` | HIGH | 7.1 | Known packer pattern (eval+string) |
| `base64_blob` | LOW | 3.7 | Large base64 blob in script |
| `hex_escape_run` | LOW | 3.7 | Hex escape sequence run |
| `high_entropy` | INFO | 2.6 | High-entropy string |

**Known FP:** Legitimate UglifyJS/webpack output can trigger `packer`. Exploitability=THEORETICAL on non-packer obfuscation variants.

**`third_party_domains`** (`engines/javascript/third_party_domains.py`): Inventories external script sources, checks for SRI.

| Finding | Severity | CVSS |
|---------|----------|------|
| `script_third_party` | MEDIUM | 5.4 |
| `script_missing_sri` | MEDIUM | 5.9 |
| `form_external_action` | MEDIUM | 6.5 |

**`vulnerable_libs`** (`engines/javascript/vulnerable_libs.py`): Detects known-vulnerable JS libraries loaded from CDNs. Supported: jQuery (<3.5.0), lodash (<4.17.21), AngularJS (all 1.x — EOL), Bootstrap (<4.3.1), DOMPurify (<3.0.0). Dedupes by (library, version) pair. Non-CDN URLs ignored (FP guard).

**`source_map_probe`** (`engines/javascript/source_map_probe.py`): Active HEAD probe for `sourceMappingURL` references. Accessible source maps (200 OK) emit MEDIUM finding.

Tests: ~40 (`test_js_tech_engines.py`) + 22 new (`test_vulnerable_libs_engine.py`) + 22 new (`test_source_map_probe.py`)

#### Family 6 — Forms (5 modules)

**`form_discovery`** (`engines/forms/form_discovery.py`): Inventories all forms. Emits no findings — metadata only.

**`form_risk`** (`engines/forms/form_risk.py`):
- `password_form_no_https` — HIGH: login form over HTTP
- `form_external_submit` — MEDIUM: form posts to external domain

**`input_analysis`** (`engines/forms/input_analysis.py`):
- `input_autocomplete_sensitive` — LOW: autocomplete on password/card fields

**`safe_input_tester`** (`engines/forms/safe_input_tester.py`): Generates `InputTestPlan` objects for manual review. **Never submits forms.** `submitted=False` and `method="none"` are invariants enforced and proven by test.

**`parameter_discovery`** (`engines/forms/parameter_discovery.py`): Enumerates URL query params (from page URL + links), form params (method/action/inputs), and API params (from observed XHR/fetch). Dedupes by exact `(url, method)` pair. `parameter_disclosure` finding (LOW) for hidden/internal params.

Tests: ~30 (`test_forms_engines.py`) + 38 new (`test_safe_input_tester_and_param_discovery.py`)

#### Family 7 — Recon (3 modules)

**`technology`** (`engines/recon/technology.py`): Technology fingerprinting from headers, meta tags, scripts.
- `tech_info` — INFO: technology detected
- `version_disclosure` — LOW: framework/server version in headers

**`robots_sitemap`** (`engines/recon/robots_sitemap.py`): Active GET of `/robots.txt` and sitemap.
- `robots_disclosure` — MEDIUM: sensitive paths in Disallow
- `sitemap_disclosure` — MEDIUM: admin paths in sitemap

**`sensitive_paths`** (`engines/recon/sensitive_paths.py`): Active HEAD/GET probes for known-sensitive paths.
- Config files (`.env`, `.config`) — CRITICAL, CVSS 9.1, KNOWN_EXPLOITED
- SCM (`.git`, `.svn`) — HIGH, CVSS 7.5, KNOWN_EXPLOITED
- Backups (`.bak`, `.sql`, `.zip`) — HIGH, CVSS 7.5, KNOWN_EXPLOITED

**Known FN:** WAF 403 on all paths gives false negatives (path exists but WAF blocks). HEAD→GET fallback; only 200 counts as exposed.

Tests: ~50 (`test_recon_engines.py`)

#### Family 8 — Threat Intel (2 modules)

**`external_domains`** (`engines/threat_intel/external_domains.py`): Collects all external hosts from page (script srcs, form actions, iframes, image sources, link hrefs). Classifies via `DomainClassifier` (offline, pure heuristics).
- `third_party_inventory` — INFO: host inventory
- `malicious_indicator` — CRITICAL, CVSS 10.0: TI-matched domain

**`enrichment_service`** (`threat_intel/enrichment_service.py`): Wraps URLhaus, VirusTotal (pluggable, disabled by default in CI). Offline stub clients return empty results gracefully.
- `threat_intel_match` — HIGH, CVSS 7.5: IP/domain TI hit
- `shared_cdn_fp` — INFO: known CDN IP suppressed

**Known FP:** Shared CDN IPs (Cloudflare 1.1.1.1, Fastly 1.x.x.x) can trigger TI match. Shared-IP suppression list in `enrichment_service` mitigates.

Tests: 70 (`test_threat_intel.py`, `test_threat_intel_coverage.py`)

#### Family 9 — CMS (3 modules)

**`wordpress`** (`engines/cms/wordpress.py`): WordPress version detection, plugin exposure, xmlrpc.
- `detected` — INFO, CVSS 3.1
- `version_disclosure` — LOW, CVSS 5.3
- `outdated_high` — CRITICAL, CVSS 9.8: major version ≥2 behind

**`shopify`** (`engines/cms/shopify.py`): Shopify detection and token leak analysis.
- `detected` — INFO
- `admin_token_leak` (`shpat_` pattern in HTML) — CRITICAL, CVSS 10.0
- Session token cookies — CRITICAL

**`wix`** (`engines/cms/wix.py`): Wix detection and preview URL exposure.
- `detected` — INFO
- `preview_url_exposed` (editor.wix.com, preview.wixsite.com, or `/preview` path in links) — MEDIUM, CVSS 5.4

Tests: ~20 (`test_recon_engines.py`) + 29 new (`test_shopify_engine.py`) + 22 new (`test_wix_engine.py`)

#### Family 10 — API Discovery (`endpoint_discovery`)
Module: `engines/api_discovery/endpoint_discovery.py`

Discovers API endpoints from JavaScript references, link hrefs, XHR patterns.

| Finding | Severity | Notes |
|---------|----------|-------|
| `internal_admin_endpoint` | HIGH | /admin, /internal in JS |
| `api_key_in_query` | HIGH | Auth tokens in URL params |
| `insecure_websocket` | MEDIUM | WS:// (not WSS://) |
| `graphql_exposure` | MEDIUM | /graphql introspection |
| `pii_endpoint` | MEDIUM | /users, /patients, /billing paths |

Tests: `test_observed_api_inventory.py`, `test_endpoint_discovery_fp.py`

#### Family 11 — Compromise Detection (4 modules)
Modules: `engines/compromise/`

Detects signs of active site compromise.

| Module | Finding | Severity | CVSS |
|--------|---------|----------|------|
| `hidden_iframes` | `hidden_iframe_suspicious` | CRITICAL | 9.0 |
| `hidden_iframes` | `srcdoc_with_script` | HIGH | 7.5 |
| `injected_js` | `injected_script` | HIGH | 8.8 |
| `seo_spam` | `seo_spam_keywords` | MEDIUM | 6.5 |
| `suspicious_redirects` | `suspicious_redirect` | HIGH | 8.1 |

**Known FN:** Server-side injection (CDN edge, SSR) is not visible in passive DOM analysis.

Tests: 40 (`test_compromise_engines.py`)

#### Family 12 — Secrets (`secret_scanner`)
Module: `engines/secrets/secret_scanner.py`

Scans HTML body and inline JS for hardcoded credentials using pattern matching.

| Finding | Severity | CVSS | Notes |
|---------|----------|------|-------|
| `hardcoded_credential` (prod) | CRITICAL | 10.0 | API keys, DB passwords |
| `hardcoded_credential` (payment) | CRITICAL | 10.0 | Stripe SK, PayPal tokens |
| `hardcoded_credential` (API) | CRITICAL | 9.1 | High-value API key patterns |

**Redaction:** Matched values truncated to prefix[:8] — never stored or transmitted in full.

**Known FN:** SSR-rendered secrets not in inline scripts are not detected.

#### Family 13 — Provider Detection (`provider_discovery`)
Module: `recon/provider_discovery.py`

Composition layer that runs before the main engine pipeline. Reads TechnologyEngine + DNS results + challenge_detection to build a `ProviderProfile` (CDN, WAF, hosting, CMS, framework, DNS provider). No new findings emitted — purely advisory enrichment consumed by all other engines.

Detected providers: Cloudflare, CloudFront, Akamai, Fastly, Azure Front Door, Imperva, Sucuri, AWS WAF, Google Cloud Armor, Vercel, Netlify, Shopify, Wix.

Tests: `test_provider_discovery.py`

#### Family 14 — Baseline / WADE (7 modules)
Location: `wade/` (production) + `apps/api/services/wade_correlation.py`

See Section 5 for full WADE documentation.

### Engine execution model

Engines receive input via one of three contracts:

1. **PageArtifacts (passive):** Already extracted; no network I/O. All JS, forms, compromise, secrets, CMS, API discovery, recon-tech, threat-intel engines.
2. **Active HTTP (safe-mode):** GET/HEAD only, rate-limited, scope-checked. `sensitive_paths`, `robots_sitemap`, `tls_checker`, `dns_checker`, `source_map_probe`.
3. **Composition:** Reads results of other engines. `provider_discovery` (reads Technology + DNS), `wade_correlation` (reads ScanFingerprint history from DB).

---

## 4. Findings & Severity Model

### Finding object

Every scanner finding carries:

```python
@dataclass
class Finding:
    title: str
    detail: str                    # one-line human summary
    finding_type: str              # machine-readable type ID
    severity: Severity             # INFO / LOW / MEDIUM / HIGH / CRITICAL
    confidence: float              # 0.0–1.0
    scanner_engine: str            # engine name
    evidence: list[Evidence]       # structured evidence objects
    framework: FrameworkAlignment  # CVSS + taxonomy
    metadata: dict                 # raw scanner output
    remediation: str               # one-line fix recommendation
```

### FrameworkAlignment

Every production finding type carries exhaustive compliance mappings:

```python
@dataclass
class FrameworkAlignment:
    cvss_vector: str          # CVSS 3.1 vector string
    cvss_score: float         # 0.0–10.0
    owasp_top10: str          # e.g. "A05:2021"
    cwe_ids: list[int]        # e.g. [693, 1021]
    nist_controls: list[str]  # e.g. ["SC-28", "SI-10"]
    pci_dss: list[str]        # PCI-DSS requirement refs
    iso_27001: list[str]      # ISO 27001 control refs
    soc2_criteria: list[str]  # SOC 2 criteria
    hipaa: list[str]          # HIPAA section refs
    exploitability: Exploitability  # THEORETICAL / PRACTICAL / KNOWN_EXPLOITED / UNKNOWN
```

**No finding type lacks a CVSS score or OWASP mapping.** This is the strongest quality characteristic.

### Evidence objects

```python
@dataclass
class Evidence:
    evidence_type: EvidenceType  # HTTP_HEADER / COOKIE / SCRIPT_SOURCE / HTML_CONTENT
                                  # DNS_RECORD / TLS_CERT / PAGE_URL / etc.
    source_url: str
    content: str                  # snippet (secrets truncated to prefix[:8])
    extra: dict                   # raw scanner output
```

### Severity calibration (selected findings)

| Finding | Severity | CVSS | Exploitability | Notes |
|---------|----------|------|---------------|-------|
| `cert_expired` | HIGH | 8.6 | KNOWN_EXPLOITED | Browsers reject; service disruption |
| `takeover_candidate` | CRITICAL | 9.1 | KNOWN_EXPLOITED | CNAME + dangling resource |
| `admin_token_leak` (Shopify) | CRITICAL | 10.0 | KNOWN_EXPLOITED | Immediate account takeover |
| `hardcoded_credential` | CRITICAL | 10.0 | KNOWN_EXPLOITED | Full credential exposure |
| `packer` (obfuscation) | HIGH | 7.1 | KNOWN_EXPLOITED | Slightly elevated; obfuscation ≠ confirmed compromise |
| `malicious_indicator` (TI) | CRITICAL | 10.0 | KNOWN_EXPLOITED | Shared CDN FPs mitigated by suppression list |
| `missing_csp` | MEDIUM | 5.4 | THEORETICAL | Enabler, not direct exploit |
| `tech_info` | INFO | 2.6 | THEORETICAL | Technology fingerprint |

### Known false-positive catalog

| Finding | FP scenario | Mitigation in place |
|---------|------------|-------------------|
| `malicious_indicator` (TI) | Shared CDN IPs (Cloudflare 1.1.1.1, Fastly) | Shared-IP suppression list in enrichment_service |
| `packer` | Legitimate UglifyJS/webpack minification | THEORETICAL exploitability on base64/hex variants |
| `eval_call` | Library code (jQuery 1.x) | Evidence snippet included; human review expected |
| `insecure_websocket` | WS:// to localhost in dev mode | Scope checker limits to target hostname |
| `robots_disclosure` | /admin in Disallow is correct security behavior | Severity=MEDIUM, informational context provided |
| `takeover_candidate` | CNAME to CDN (not abandoned) | Two-condition gate: CNAME + dangling-resource check |
| `script_missing_sri` | CDN-served well-known library | Provider allowlist checked |
| `injected_js` | GTM / Google Tag Manager | Provider allowlist; known tag managers whitelisted |

### Known false-negative catalog (architectural limitations)

| Finding | FN scenario | Why unmitigated |
|---------|------------|----------------|
| `injected_js` (compromise) | CDN-edge JS injection (Cloudflare Workers) | Scanner sees rendered DOM; edge injection indistinguishable from CDN |
| `missing_httponly` | Cookie set via `document.cookie` after page load | Passive header analysis only |
| `cert_expired` | CDN-terminated TLS | Scanner sees CDN cert, not origin |
| `admin_token_leak` (Shopify) | Token in dynamically-loaded JSON (XHR) | Inline script analysis only |
| Secrets | SSR template secrets not in inline scripts | HTML body + inline script; SSR output not analyzed |

### WADE FP suppression layer

`quality_review.py` (production WADE) post-processes findings to flag:
- Duplicate findings (same type, same page)
- High-confidence info-severity mismatches
- Missing corroboration for cluster findings

Validated in `test_wade_quality_review.py` (8 targeted tests).

---

## 5. WADE — Baseline, Diff & Advisory Intelligence

WADE (WebHound Anomaly Detection Engine) has two distinct layers:

1. **Production WADE** (`scanner/webhound/wade/`) — baseline snapshots, diff engine, anomaly scoring, behavioral correlation. Writes to production DB. NEVER modified by AI/advisory work.
2. **Advisory WADE** (`scripts/wade/reasoning/`) — read-only reasoning layer added in Phase 8D. Shadow mode only. Never writes.

### Production WADE pipeline

```
Scan N completes
      │
      ▼
baseline_builder.py    → PageSnapshot (17 fields) per page
      │
      ▼
baseline_store.py      → SiteBaseline (N snapshots) persisted to DB
      │
      ▼
diff_engine.py         → Compares snapshot N vs N-1; emits DriftSignal per changed field
      │
      ▼
anomaly_scorer.py      → Scores drift signals into risk delta
      │
      ▼
classifier.py          → Multi-signal change classifier
      │
      ▼
quality_review.py      → Post-scoring sanity: dedup, severity checks, corroboration
      │
      ▼
wade_correlation.py    → 5 behavioral correlation rules (see below)
```

### 5 behavioral correlation rules

| Rule | Trigger |
|------|---------|
| `tech_stack_churn` | CMS/framework changes in ≥3 scans over 7 days |
| `tls_instability` | TLS cert changes ≥2 times in 30 days |
| `third_party_explosion` | External domain count ≥3× median of prior scans |
| `persistent_header_regression` | Same security header missing in ≥3 consecutive scans |
| `login_form_flapping` | Login form appears/disappears ≥2 times in 7 days |

Tests: 97 (`test_wade.py`, `test_wade_integration.py`, `test_wade_quality_review.py`) + 253 additional WADE tests

### PageSnapshot fields (17)

url, status_code, content_type, title, security_headers (dict), cookies (list), tls_summary, dns_summary, technology_fingerprint, external_domains (list), form_signatures (list), script_hashes (list), finding_types (list), inline_script_count, external_script_count, response_time_ms, provider_profile

### Advisory WADE retrieval layer (Phase 8B)

Location: `scripts/wade/`

6 retrieval functions that query the AI knowledge corpus for context on a given finding:

| Method | Purpose |
|--------|---------|
| `get_security_guidance(finding_type)` | CWE/OWASP/remediation evidence |
| `get_provider_context(finding_type, provider)` | CDN/WAF-specific context |
| `get_threat_intel_policy(finding_type)` | TI feed guidance |
| `get_taxonomy_mapping(finding_type)` | Authoritative CWE + OWASP refs |
| `get_false_positive_patterns(finding_type)` | Known benign condition patterns |
| `get_customer_safe_language(finding_type)` | Non-technical risk language |

Supported finding types (22): `missing_csp`, `missing_hsts`, `missing_x_frame_options`, `missing_secure_cookie`, `missing_httponly_cookie`, `missing_samesite_cookie`, `mixed_content`, `third_party_script_risk`, `suspicious_javascript`, `threat_intel_match`, `provider_blocked_scan`, `cloudflare_challenge_page`, `vercel_deployment_protection`, `exposed_env`, `exposed_git`, `exposed_backup_file`, `wordpress_xmlrpc`, `graphql_exposure`, `swagger_exposure`, `tls_expiry`, `tls_misconfiguration`, `api_exposure`

Tests: 61 (`tests/ai/test_wade_retrieval.py`)

### Advisory WADE reasoning layer (Phase 8D)

Location: `scripts/wade/reasoning/` — 9 modules, shadow mode only.

All outputs carry `advisory_only=True` and `production_unchanged=True`.

**Correlation patterns (4):**

| Pattern | Example trigger |
|---------|----------------|
| `supply_chain_exposure` | `missing_csp` + `third_party_script_risk` |
| `session_protection_weakness` | `missing_secure_cookie` + `missing_httponly_cookie` |
| `elevated_compromise_risk` | any `exposed_*` + `threat_intel_match` |
| `tls_downgrade_cluster` | `tls_misconfiguration` + HSTS/mixed-content |

**Attack chain candidates (4):**

| Chain | Path |
|-------|------|
| `admin_credential_takeover` | exposed-admin → credential-theft → account-takeover |
| `supply_chain_client_compromise` | third-party-script → supply-chain → client-compromise |
| `weak_headers_browser_exploitation` | weak-headers → XSS-amplification |
| `recon_to_data_exfiltration` | TI-match + API-exposure → data-exfiltration |

**Root cause categories (5):** `deploy_misconfiguration`, `provider_behavior`, `secret_exposure`, `deprecated_stack`, `api_misconfiguration`

**8-factor confidence model:**
Source authority, evidence quality, provider effects, finding consistency, historical similarity, TI corroboration, attack-chain support, FP signals.
Levels: HIGH (≥0.72) / MEDIUM (0.50–0.71) / LOW (0.30–0.49) / INSUFFICIENT (<0.30)

**Priority levels (4):** IMMEDIATE / HIGH / MEDIUM / LOW (6 scoring factors, advisory only)

**Executive reasoning:** Customer-safe language, no jargon, positive observations noted, advisory disclaimer on every output. Provider findings go to `informational_count` only.

**Shadow mode:** `WADEShadowReasoner.analyze()` runs full pipeline against any finding set. `ShadowReasoningPackage.production_unchanged: True` guaranteed. `delta_vs_production()` compares advisory vs production (read-only).

**Graph integration (graceful degradation):**
- Neo4j: optional, graph reasoning degrades if offline
- Graphiti: optional, episodic memory degrades if offline
- Hybrid retrieval: always available (lexical mode always runs)

Tests: 49 passed, 2 skipped (`tests/ai/test_wade_reasoning_engine.py`)

---

## 6. AI Knowledge Layer (Corpus)

### Overview

A curated knowledge corpus used as a retrieval backend for WADE advisory reasoning. Built in phases 6A–6H.

**Final state (Phase 7A):**
- 487 manifest records
- 1161 chunks indexed
- 1161 dense embeddings (all-MiniLM-L6-v2, 384-dim)
- No cloud API used

### Authority tiers

| Tier | Count | Source type | Description |
|------|-------|-------------|-------------|
| A | 273 | Official standards, MDN, OWASP | Highest authority |
| B | 106 | Official repos, provider docs, planning refs | High authority |
| C | 108 | Detection repos, community knowledge | Good authority |

### Source types breakdown (by phase)

| Phase | Source type | Count | Description |
|-------|-------------|-------|-------------|
| 6A | official_doc | 6 | OWASP WSTG, ASVS, Cheat Sheets; MDN CSP/CORS/SRI |
| 6B | official_repo | 61 | Nuclei, httpx, Katana, Amass, Gitleaks, Semgrep, MCP servers, Playwright-MCP, GitHub-MCP, LightRAG |
| 6C | detection_repo | 42 | ZAP, sqlmap, XSStrike, DalFox, nuclei-templates, libinjection, Firecrawl |
| 6D | official_provider_doc | 46 | Cloudflare, Vercel, Netlify, AWS CDN provider docs |
| 6E | official_threat_intel_doc | 9 | URLHaus, ThreatFox, AbuseIPDB, GreyNoise, MISP |
| 6F | official_taxonomy_doc | 22 | CWE, CVE/NVD, CVSS, CISA KEV, OWASP Top 10 |
| 5A | internal_doc | 296 | Internal WebHound documentation, architecture, scanner notes |
| All | decision_log / planning | 5 | Architecture decisions, phase plans |

### Phase 6A — Official Tier-A docs (OWASP + MDN)

6 pinned documents: OWASP WSTG, OWASP Cheat Sheet (CSP), OWASP ASVS, MDN CSP, MDN CORS, MDN SRI. All pinned to exact upstream commit SHA. Licenses: CC-BY-SA-4.0 (OWASP), CC-BY-SA-2.5 (MDN).

### Phase 6B — Official security repos

10 repos (61 records): projectdiscovery/nuclei, projectdiscovery/httpx, projectdiscovery/katana, owasp-amass/amass, gitleaks/gitleaks, semgrep/semgrep, modelcontextprotocol/servers, microsoft/playwright-mcp, github/github-mcp-server, HKUDS/LightRAG.

Exclusions: payload directories, locale files, CLAUDE.md (external agent instructions kept out per prompt-injection policy).

### Phase 6C — Detection engineering repos

8 repos (42 records, 271 chunks): zaproxy/zaproxy, sqlmapproject/sqlmap, s0md3v/XSStrike, hahwul/dalfox, projectdiscovery/nuclei-templates, libinjection/libinjection, firecrawl/firecrawl, firecrawl/firecrawl-mcp-server.

Payload-safety: `payloads/`, `templates/cves/`, `templates/exploits/`, and raw template directories explicitly excluded. Only methodology docs kept.

### Phase 6D — Provider documentation

Official provider/CDN/WAF docs from Cloudflare, Vercel, Netlify, AWS. Covers scanner allowlisting, WAF configuration, CDN TLS behavior. 46 records.

### Phase 6E — Threat intelligence sources

Documentation from URLHaus, ThreatFox, AbuseIPDB, GreyNoise, MISP. 9 records covering API schemas, confidence models, feed formats.

### Phase 6F — Vulnerability taxonomy

CVE/NVD schema docs, CWE taxonomy, CVSS 3.1 specification, CISA KEV format, OWASP Top 10 2021. 22 records.

### Phase 6G — Validation audit

120-question retrieval validation using TF-IDF lexical baseline. Results (pre-dense-embedding):
- Top-1: 17% (20/120)
- Top-3: 32% (38/120)
- Top-5: 46% (55/120)

Confirmed need for dense embeddings → Phase 7A.

### Phase 6H — Unified chunk index

All 1161 chunks from all phases unified into a single searchable index. BM25 + authority-weighted retrieval.

### Corpus location

```
corpus/
├── normalized/           Normalized source doc text
│   ├── docs/official/   6A official docs
│   ├── repos/           6B-6C repo docs
│   └── ...
├── indexes/
│   ├── bm25/            BM25 + TF-IDF lexical index
│   └── dense/
│       ├── chunk_embeddings.npy         ~1.8 MB, 1161×384
│       ├── chunk_embedding_meta.json    Chunk provenance
│       └── dense_index_config.json      Model config
└── exports/
    ├── lightrag/        1161 LightRAG-compatible documents
    └── graphiti_seeds.json  10 Graphiti episode seeds
```

---

## 7. Retrieval System

### Three retrieval modes

| Mode | Algorithm | Top-1 | Top-3 | Top-5 |
|------|-----------|-------|-------|-------|
| Lexical (6H baseline) | TF-IDF whole-doc | 12% | 38% | 52% |
| Lexical chunk | TF-IDF over chunks | 12% | 38% | 52% |
| Dense only | cosine sim, all-MiniLM-L6-v2 | 71% | 84% | 92% |
| **Hybrid (default)** | **0.35×lexical + 0.65×dense, re-ranked** | **76%** | **88%** | **90%** |

*120-question test set across 6 domains.*

### Domain-level accuracy (hybrid mode)

| Domain | Top-5 |
|--------|-------|
| Detection engineering | 100% |
| Threat intelligence | 100% |
| Provider intelligence | 95% |
| Vulnerability taxonomy | 95% |
| Security standards | 70% |
| WADE-specific | 80% |

### Embedding model

- Model: `sentence-transformers/all-MiniLM-L6-v2` (LOCAL only, no cloud API)
- Dimensions: 384
- Index size: ~1.8 MB for 1161 chunks
- No FAISS — numpy dot-product sufficient at this scale

### WADE readiness score

After Phase 7A, WADE retrieval readiness scored 8.9/10 across 10 capability areas (up from 8.0/10 in Phase 6H).

---

## 8. The AI Brain (Obsidian + Graph + Local LLM)

### Obsidian vault

Location: `vault/WebHound AI Brain/`

45 notes across 11 folders (Phase 8A), expanded to full platform coverage in Phase 8G.

```
vault/WebHound AI Brain/
├── 00-Maps/              9 notes — map-of-content index
├── 01-Architecture/      3 notes — system design, phases, inventory
├── 02-Scanner Engines/   4 notes — Nuclei, ZAP, DalFox
├── 03-WADE/              4 notes — WADE architecture and policies
├── 04-Knowledge Corpus/  4 notes — manifest, chunks, retrieval
├── 05-Provider Intelligence/ 4 notes — CDN, WAF, cloud
├── 06-Threat Intelligence/   3 notes — TI sources, VirusTotal
├── 07-Vulnerability Taxonomy/ 4 notes — CWE, OWASP, severity
├── 08-External Tools/    5 notes — LightRAG, Graphiti, Neo4j, Graphify
├── 09-Reports/           1 note  — links to phase result docs
└── 10-Decisions/         3 notes — embedding, weights, general
```

Each note: YAML frontmatter (status, source, created, phase, scope), `<!-- WEBHOUND-GENERATED -->` marker, wikilinks, tags.

Phase 8G expanded the vault to cover the complete WebHound platform (scanner engines, WADE, API models, provider framework, billing, integrations).

### Local LLM runtime (Phase 8C-INFRA-LIVE)

**Ollama (LIVE):**
- Version: v0.30.6
- Models: `phi3:mini` (3.8B Q4_0, 2.2GB) + `nomic-embed-text:latest` (0.3GB)
- Performance: ~17 tok/s CPU inference
- Endpoint: `http://localhost:11434/v1` (OpenAI-compatible)
- No cloud API — fully local

**Neo4j (LIVE via WSL2):**
- Version: 5-community (Docker container)
- Ports: bolt:7687, HTTP:7474 (reachable from Windows via WSL2 port forwarding)
- Data: 126 FileNode nodes, 191 relationships (34 DEPENDS_ON + 157 WIKI_LINK)
- Graphiti schema: Entity, Episodic, Community, Saga labels + indexes
- **Note:** Container is ephemeral (no volume committed). Requires re-seeding after restart.
- Docker Desktop on Windows is **BLOCKED** (exit status 0x40010004). WSL2 workaround: `wsl -d Ubuntu-24.04 -- docker ...`

**Graphiti (LIVE):**
- 13/13 seed episodes loaded
- Fix required: `small_model=phi3:mini` in LLMConfig (graphiti-core defaults to `gpt-4.1-nano`)
- Entity extraction quality: phi3:mini produces some hallucinated entities; Episodic nodes seed correctly

**LightRAG-graph (LIVE):**
- 30/30 chunks processed (1800s total, 60s avg/chunk)
- 19 entities + 1 relationship extracted by phi3:mini
- Stored in NanoVectorDB (`vdb_entities.json`, `graph_chunk_entity_relation.graphml`)

**Brain graph loader:** `scripts/ai/load_brain_graph_neo4j.py --live` — 391 Cypher statements, 126 nodes + 191 rels

**Important operational note:** Neo4j and Graphiti are used by the advisory reasoning layer only. They are never in the production scan path. Both degrade gracefully if offline.

---

## 9. Threat Intelligence

### TI source inventory

| Source | Type | Status | Notes |
|--------|------|--------|-------|
| URLHaus (abuse.ch) | Domain/URL blocklist | Normalizer + offline static list | Malware C2, phishing URLs |
| ThreatFox (abuse.ch) | IOC database | Normalizer + offline static list | Malware indicators |
| OpenPhish | Phishing feed | Offline static list | Phishing URL list |
| PhishTank | Phishing feed | Offline static list | Verified phishing URLs |
| OTX (AlienVault) | Threat intel platform | Client stub (disabled in CI) | Pulses, reputation data |
| AbuseIPDB | IP reputation | Client stub (disabled in CI) | IP abuse reports |
| VirusTotal | Multi-AV reputation | Client stub (disabled in CI) | Domain/IP/URL reputation |
| GreyNoise | Noise classification | Client stub (disabled in CI) | Internet scanner classification |
| Shodan | Internet exposure | Knowledge corpus only | Not queried at runtime |
| Censys | Internet exposure | Knowledge corpus only | Not queried at runtime |
| MISP | Threat sharing | Knowledge corpus only | Protocol/format knowledge |
| CISA KEV | Known exploited vulns | Knowledge corpus only | KEV list for CVSS context |

**Live client vs normalizer:** "Client stub" means the integration code exists but is disabled in CI with offline graceful degradation. Standard scan mode uses offline static lists and heuristics only. No live TI call is made per scan.

### Confidence model

TI findings follow the 8-factor advisory confidence model (see Section 5). Provider context (shared CDN IP) reduces confidence and may suppress findings.

### Customer-safe reporting language

TI findings use language resolver (`scripts/wade/language_resolver.py`) to convert technical TI matches into non-alarming, actionable customer language. Provider findings (e.g., CDN IP matching a TI list) are automatically downgraded to `informational_count`.

---

## 10. Providers & Platform Access

### Scanner egress identity (Railway static IPs)

```
162.220.234.240
152.55.180.240
152.55.180.241
```

Surfaced publicly at `/scanner/identity` for customer allowlisting. These are the IPs customers must allowlist in their CDN/WAF to permit scanner access.

### Provider access registry

Config-driven registry of 10 providers with detection + remediation:

| Provider | Automation | Method | Notes |
|----------|-----------|--------|-------|
| Cloudflare | ✅ Full automation | API | IP-allow rule creation + verification via CF API |
| Vercel | Guided manual | Manual | "Seawall Config not found" until project Firewall enabled once |
| Netlify | Detection only | Manual | Guided allowlisting instructions |
| CloudFront | Detection only | Manual | AWS WAF IP-set instructions |
| Akamai | Detection only | Manual | Network List API instructions |
| Fastly | Detection only | Manual | IP Allowlist instructions |
| Azure Front Door | Detection only | Manual | WAF policy instructions |
| Imperva | Detection only | Manual | Allowlist instructions |
| Sucuri | Detection only | Manual | Firewall IP allowlist instructions |
| AWS WAF | Detection only | Manual | IP Set instructions |
| Google Cloud Armor | Detection only | Manual | Security Policy instructions |

Only Cloudflare has `automation_capable=True` / `allowlist_method="api"`.

### Provider-aware scanning behavior

- **Challenge page detection** (`browser/challenge_detection.py`): Cloudflare IUAM, Vercel deployment-protection, Netlify password pages, AWS WAF block pages detected and emitted as `provider_blocked_scan` rather than missing content.
- **Shared-IP suppression**: TI engine suppresses findings for known CDN IP ranges (Cloudflare 1.1.1.1, Fastly 1.x.x.x, CloudFront ranges).
- **Managed hosting context**: Wix and Shopify marked as fully managed — TLS/patching findings contextualized ("managed by platform provider").
- **CDN TLS notation**: `tls_checker` notes when cert is CDN-terminated; findings carry provider flag.

### PlatformAccessWizard (frontend)

Data-driven, provider-agnostic UI sourced entirely from API. No provider logic in the client. Mounted on website detail page. Visibility states: `hidden`, `collapsed`, `expanded`. Covers all 10 providers with IP-templated remediation instructions.

### Vercel integration notes

- Uses classic Integration (slug install URL), not Sign-in-with-Vercel OAuth
- Requires `VERCEL_INTEGRATION_SLUG` env var
- Bypass automation blocked by "Seawall Config not found" until project Firewall enabled once in Vercel dashboard (manual first-touch step)

### Boot-time production guardrails

`apps/api/config.py` refuses to start in production if:
- `SECRET_KEY` is default value
- `DATABASE_URL` is unset or non-Postgres
- `REDIS_URL` invalid
- `API_BASE_URL` / `FRONTEND_URL` not absolute
- `DEV_ALLOW_UNVERIFIED_SCANS` set
- `DEV_SKIP_DOMAIN_VERIFICATION` set (SSRF risk)
- Admin bypass flags set without explicit `ADMIN_BYPASS_ALLOW_IN_PROD` two-key opt-in

---

## 11. Integrations & Infrastructure

### Stripe (billing)

- Subscription management via Stripe Checkout + Customer Portal
- Webhook endpoint processes: `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.payment_succeeded`, `invoice.payment_failed`
- Subscription model: `apps/api/billing/` + `apps/api/models/subscription.py`

### Resend (email)

- Transactional email via Resend API
- DNS setup: custom SPF, DKIM, DMARC on webhoundsecurity.com
- Templates: verification emails, scan completion alerts, billing receipts

### Google + GitHub OAuth

- NextAuth.js providers: Google OAuth2 + GitHub OAuth
- Magic-link / email verification also supported
- Session management via NextAuth JWT

### Cloudflare (infrastructure)

- DNS hosting for webhoundsecurity.com
- CDN + WAF for the frontend (Vercel integration)
- Scanner allowlisting for customer Cloudflare zones (via API automation)

### Railway (backend deployment)

- FastAPI API process + worker process
- PostgreSQL (Railway Postgres)
- Redis (Railway Redis)
- Static outbound IPs: `162.220.234.240`, `152.55.180.240`, `152.55.180.241`
- `railway.json` deployment config + `Dockerfile` for API

### Vercel (frontend deployment)

- Next.js 14 App Router deployed to Vercel
- Production domain: webhoundsecurity.com
- Preview deployments on PR branches

### CI (GitHub Actions)

- `ai-knowledge` workflow: runs ingestion pipeline checks
- Scanner test suite: `pytest scanner/tests/` (2610 tests)
- TypeScript check: `tsc --noEmit`
- `test_browser_runner.py` and `test_auth_runner.py` excluded from CI (require live Playwright/auth infrastructure)

### Docker / local dev

```
docker-compose.yml          Standard local dev
docker-compose.dev.yml      Dev with hot-reload
docker-compose.prod.yml     Production-like
docker-compose.ai-brain.yml Neo4j + Graphiti for AI Brain
docker-compose-neo4j.yml    Standalone Neo4j
```

**Docker Desktop on Windows** is blocked (`npipe:////./pipe/dockerDesktopLinuxEngine` times out, exit status 0x40010004). **Workaround:** `wsl -d Ubuntu-24.04 -- docker ...` uses Ubuntu-24.04's Docker v29.5.3.

---

## 12. Database Models

All SQLAlchemy 2.x async models. Location: `apps/api/models/`

| Model file | Description |
|-----------|-------------|
| `user.py` | Users, OAuth accounts, email verification |
| `website.py` | Customer domains, verification status, provider profile |
| `website_group.py` | Domain groups for portfolio customers |
| `org.py` | Organizations (multi-user teams) |
| `scan_job.py` | Scan job lifecycle, status, configuration |
| `scan_result.py` | Scan output — findings, summary, WADE diff |
| `finding.py` | Individual security findings with full FrameworkAlignment |
| `grouped_finding.py` | Deduplicated / grouped findings for reporting |
| `baseline.py` | WADE PageSnapshot baseline records |
| `scan_delta.py` | WADE diff output — DriftSignal + AnomalyScore per scan |
| `subscription.py` | Stripe subscription, plan, billing period |
| `alert.py` | Finding-triggered alerts with notification state |
| `notification.py` | Alert delivery (email, in-app) |
| `provider_connection.py` | Provider OAuth token + connection state |
| `provider_profile.py` | Detected CDN/WAF/hosting per domain |
| `trusted_access.py` | Scanner allowlist confirmation per provider |
| `threat_indicator.py` | TI hits linked to scan findings |
| `incident.py` | Incident tracking for elevated findings |
| `report.py` | Generated scan reports (PDF/CSV/SARIF/Markdown) |
| `scan_schedule.py` | Monitoring schedule (daily/weekly/etc.) |
| `deployment.py` | Deployment event tracking |
| `suppression.py` | Customer-configured finding suppressions |
| `support_ticket.py` | Support escalations with provider context |
| `admin_audit_log.py` | Audit trail for admin actions |
| `log_record.py` | Structured operational log records |
| `engine.py` | Engine health + configuration |
| `engine_diagnostic.py` | Per-engine diagnostic output |
| `abuse.py` | Abuse detection + rate-limit records |
| `access_validation.py` | Domain ownership validation attempts |
| `onboarding_wizard.py` | 6-step onboarding state machine |
| `onboarding_readiness.py` | Per-provider readiness checklist |
| `infrastructure_sample.py` | Infrastructure sampling for benchmarks |
| `internal_note.py` | Internal staff notes on customers |
| `encrypted_secret.py` | Encrypted credential storage |
| `enums.py` | Shared enums (ScanStatus, FindingSeverity, etc.) |

---

## 13. External Tools & Libraries

### Detection engineering tools (knowledge corpus — not runtime)

These tools are NOT bundled or called by WebHound. Their documentation was ingested as knowledge (Phase 6B–6C) to inform WADE reasoning and scanner design.

| Tool | Use in WebHound |
|------|----------------|
| **OWASP ZAP** | ZAP detection patterns inform WebHound's JS/form engine heuristics |
| **Nuclei** (ProjectDiscovery) | Nuclei template syntax/methodology informs finding categorization |
| **Katana** (ProjectDiscovery) | Crawler design reference; WebHound's crawler follows similar safe-mode principles |
| **httpx** (ProjectDiscovery) | HTTP probing patterns reference |
| **Amass** | Subdomain enumeration concepts (knowledge only; WebHound does not enumerate subdomains) |
| **Semgrep** | Static analysis patterns for secret detection knowledge |
| **Gitleaks** | Secret pattern taxonomy reference; informs `secret_scanner.py` regex patterns |
| **libinjection** | SQL injection / XSS detection heuristics reference |
| **DalFox** | XSS detection methodology reference |
| **XSStrike** | XSS analysis patterns reference |
| **Playwright / playwright-mcp** | Browser automation knowledge; WebHound's browser runner references these patterns |
| **Firecrawl** | Web crawling methodology; WebHound's extractor informed by Firecrawl design |
| **sqlmap** | SQL injection methodology (defensive knowledge only; no payloads ingested) |

### Key Python dependencies (scanner + API)

| Library | Purpose |
|---------|---------|
| `fastapi` | API framework |
| `sqlalchemy[asyncio]` | Async ORM |
| `alembic` | Database migrations |
| `pydantic` | Request/response validation |
| `httpx` | Async HTTP client (scanner probes) |
| `beautifulsoup4` | HTML parsing (extractor) |
| `sentence-transformers` | Dense embeddings (all-MiniLM-L6-v2) |
| `numpy` | Dense vector math (no FAISS) |
| `stripe` | Stripe billing API |
| `resend` | Email API |
| `pytest` / `pytest-asyncio` | Test framework (2610 tests) |
| `graphiti-core` | Graphiti episodic memory (AI Brain) |
| `lightrag` | Graph-based RAG (AI Brain) |
| `neo4j` (driver) | Neo4j graph DB client |

### Key Node/Next.js dependencies

| Library | Purpose |
|---------|---------|
| `next` 14 | App Router framework |
| `next-auth` | Authentication (Google, GitHub, email) |
| `tailwindcss` | Styling |
| `typescript` | Type safety |
| `stripe` (JS) | Frontend billing integration |

---

## 14. Phase History — Full Build Chronology

### Early phases (scanner foundation, ~20 commits before AI work)

**Phases 1–19 (scanner build):** Complete scanner engine foundation — security headers, cookies, TLS, DNS, JavaScript analysis, forms, recon, compromise detection, secrets, API discovery, WADE baseline/diff, threat intel, orchestrator, reporting pipeline (SARIF/CSV/Markdown), performance benchmarking, real-world validation.

**Alpha hardening (mid-June 2026):** OAuth, email/phone verification, domain ownership verification, security hardening for launch. Migration to webhoundsecurity.com production domain. Railway static IPs established.

### Platform access framework (PR merged)

**Platform-access framework:** Config-driven provider-access registry detecting 10 CDN/WAF providers. Cloudflare full automation (`automation_capable=True`). `PlatformAccessWizard` frontend. Scanner egress IPs surfaced at `/scanner/identity`. Boot-time production guardrails. Onboarding completion fix (idempotent `ensure_default_schedule`). 40+ Cloudflare tests, 34 Vercel tests.

### AI Knowledge Layer (Phases 6A–6H)

**Phase 6A** (PR #1): OWASP WSTG, ASVS, CSP Cheat Sheet + MDN CSP/CORS/SRI. 6 records, 81 chunks. All pinned to exact commit SHA.

**Phase 6B** (PR #3–#4): 10 official repos — Nuclei, httpx, Katana, Amass, Gitleaks, Semgrep, MCP servers, Playwright-MCP, GitHub-MCP, LightRAG. 61 records, 552 chunks.

**Phase 6C** (PR #5): 8 detection engineering repos — ZAP, sqlmap, XSStrike, DalFox, nuclei-templates, libinjection, Firecrawl (×2). 42 records, 271 chunks. Payload directories excluded.

**Phase 6D** (PR #6): Official provider/CDN/WAF docs. 46 records.

**Phase 6E** (PR #7): Threat intelligence source docs — URLHaus, ThreatFox, AbuseIPDB, GreyNoise, MISP. 9 records.

**Phase 6F** (PR #8): Vulnerability taxonomy — CVE/NVD, CWE, CVSS 3.1, CISA KEV, OWASP Top 10. 22 records.

**Phase 6G** (PR #9): 120-question validation audit. Lexical baseline: Top-1 17%, Top-5 46%. Gap identified → Phase 7A.

**Phase 6H**: Unified chunk index. 487 records / 1161 chunks.

### Dense Retrieval (Phase 7A — PR #12)

Local all-MiniLM-L6-v2 embeddings (384-dim). 1161 embeddings, ~1.8 MB. Dense Top-1 71%, Top-5 92%. Hybrid (0.35/0.65) Top-1 76%, Top-5 90%. WADE readiness: 8.9/10. No cloud API.

### AI Brain Foundation (Phase 8A — PR #13)

Obsidian vault (45 notes, 11 folders). Brain query tests. LightRAG corpus export. Graphiti seed memories. Neo4j schema (17 node types, 14 relationship types). WADE brain interface (8 inputs, 6 functions, 6 outputs).

### WADE Advisory Retrieval (Phase 8B — PR #14)

`scripts/wade/` package. 6 retrieval functions. 22 finding types supported. `ReasoningContext` data model. 61 tests.

### AI Brain Runtime (Phase 8C — PR #15)

Brain health monitor. Infrastructure scripts (Neo4j, Graphiti, LightRAG). `OFFLINE` / `CONFIGURED_PENDING` / `LIVE` status model.

### AI Brain Infra Live (Phase 8C-INFRA + 8C-INFRA-LIVE — PRs #16, #17)

**Phase 8C-INFRA:** Infrastructure scripts, Docker configs, Graphify integration.

**Phase 8C-INFRA-LIVE:** Fully brought local runtime online:
- Ollama v0.30.6 installed — phi3:mini + nomic-embed-text LIVE at localhost:11434
- Neo4j LIVE via WSL2 Docker — 126 nodes + 191 rels loaded
- Graphiti LIVE — 13/13 episodes seeded
- LightRAG-graph LIVE — 30/30 chunks, 19 entities extracted

### Full Vault Sync (Phase 8G — PR #18)

Synchronized complete WebHound platform into the Obsidian vault. Expanded beyond the 45-note foundation to cover all scanner engines, WADE, provider framework, billing, API models.

### WADE Reasoning Engine (Phase 8D — PR #19)

Advisory reasoning layer (`scripts/wade/reasoning/`, 9 modules). 4 correlation patterns. 4 attack chains. Root cause (5 categories). 8-factor confidence model. Priority levels. Executive reasoning. Graph + memory integration (graceful degradation). Shadow mode. 49 tests passed, 2 skipped (neo4j/graphiti live).

### Scanner Audit (Phase 9A — PR #20)

Full audit of all 32 scanner engine modules. `SCANNER_ENGINE_INVENTORY.md` (finding types, CVSS, provider awareness matrix, WADE consumption matrix). `docs/ai/PHASE9A_RESULTS.md`. Identified 6 modules with STATIC-only coverage.

### Scanner Validation & Hardening (Phase 9B — PR #21, current branch)

Added 166 tests (2444 → 2610) and validation harness for the 6 previously-untested modules:

| Module | New tests |
|--------|-----------|
| `shopify.py` | 29 |
| `wix.py` | 22 |
| `source_map_probe.py` | 22 |
| `safe_input_tester.py` | 18 |
| `parameter_discovery.py` | 20 |
| `vulnerable_libs.py` | 34 |
| Validation harness | 21 |

**Validation harness** (`scanner/validation/harness.py`): `ValidationTarget/Run/Finding/Evidence/Report` data model. `SAFE_TARGET_MATRIX` (6 consented targets). `run_mock()` for CI-safe testing. Safety contract: GET/HEAD only, no forms, max 5 pages, no arbitrary third-party sites.

**Zero production code changes** — firing conditions, CVSS scores, WADE scoring all unchanged.

**PR #21** open, not merged. Branch: `feat/scanner-phase-9b-validation-hardening`. Commits: `6bd1483` (main Phase 9B), `06bcf0e` (asyncio event-loop fix).

---

## 15. Current State, Known Gaps & Roadmap

### Production status (as of 2026-06-14)

| Component | Status |
|-----------|--------|
| Scanner (32 engines) | ✅ Production |
| WADE production pipeline | ✅ Production |
| Frontend (Next.js/Vercel) | ✅ Production |
| Backend API (FastAPI/Railway) | ✅ Production |
| Auth (Google/GitHub/email) | ✅ Production |
| Billing (Stripe) | ✅ Production |
| Domain ownership verification | ✅ Production |
| Cloudflare automation | ✅ Production |
| Provider access (9 other providers) | ✅ Beta (guided manual) |
| AI Knowledge corpus (487 records) | ✅ Indexed |
| Dense embeddings (1161 chunks) | ✅ Indexed |
| WADE advisory retrieval (6 functions) | ✅ Shadow mode |
| WADE advisory reasoning (9 modules) | ✅ Shadow mode |
| Obsidian AI Brain vault | ✅ Synced |
| Ollama (phi3:mini) | ✅ Local LIVE |
| Neo4j (WSL2) | ✅ Local LIVE (ephemeral) |
| Graphiti | ✅ Local LIVE |
| LightRAG-graph | ✅ Local LIVE |
| Scanner test coverage (32/32 modules) | ✅ Complete (Phase 9B) |
| Validation harness | ✅ Built (Phase 9B) |
| Live validation against safe targets | ❌ NOT YET RUN |

### Overall production-readiness: ~80%

Per Phase 9A audit assessment. Scanner detection logic is high quality. Framework alignment is complete. Test coverage is now complete (32/32 modules post-Phase 9B).

### Known gaps

**Live scan validation not yet run:** The `SAFE_TARGET_MATRIX` defines 6 consented targets (badssl.com, testphp.vulnweb.com, demo.testfire.net, webhoundsecurity.com, cloudflare.com, expired.badssl.com). No live scan has been executed against these. Precision/recall numbers are not yet available.

**FP/FN hardening items (documented-only, not yet implemented):**
- `packer` FP reduction: tighten firing condition to require both packer pattern AND eval-of-obfuscated-string (not just pattern alone)
- `malicious_indicator` shared-hosting suppression: expand CDN suppression list to cover more managed hosting ranges
- CDN-terminated TLS documentation: `cert_expired` finding could carry a clearer "CDN certificate — origin cert not inspectable" annotation
- JS-cookie limitation: `missing_httponly` finding could carry "Note: cookies set by JavaScript after page load are not analyzed" annotation

**14 coverage gaps from Phase 9A** (all addressed at test level in 9B, none require engine code changes):
- `secret_scanner.py` — no targeted test asserting each secret pattern fires (only indirect coverage via `test_engine_health.py`)
- Evidence chain has no `evidence_id` or chain-of-custody hash
- Netlify-specific provider behavior less rich than Cloudflare/Vercel

**Docker Desktop on Windows:** Blocked by `exit status 0x40010004`. WSL2 workaround works but requires manual start of Ubuntu-24.04 Docker.

**Neo4j ephemeral:** Container has no volume committed — must re-seed after restart.

### Sensible next steps

1. **Merge PR #21** (Phase 9B) — 2610 tests, 0 failures, 0 regressions
2. **Run live validation** against `SAFE_TARGET_MATRIX` — get first real precision/recall numbers
3. **Implement packer FP hardening** — tighten `obfuscation_detector.py` firing condition + test proving before/after
4. **Expand malicious_indicator suppression** — add shared hosting ranges to CDN suppression list
5. **Secret scanner targeted tests** — assert each pattern fires against synthetic fixtures
6. **Phase 10 scanner accuracy** — the Phase 10 validation lab (`scanner/validation/ground_truth.py`, 24 targets) is already built; run `run_targets()` against live targets
7. **Per-engine readiness scorecard update** — update the 0–10 scores with Phase 9B test coverage included
8. **Advisory layer promotion** — when confidence in reasoning quality is high, consider surfacing advisory outputs in the UI (not replacing production findings, adding "AI Context" panels)
9. **Docker Desktop fix** — user action required: System Tray → Docker Desktop → wait for "running" state; or WSL Integration → Enable Ubuntu-24.04

---

*End of WebHound Complete Project Reference — 2026-06-14*
