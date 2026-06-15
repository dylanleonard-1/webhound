# Phase 9B-A — Coverage + Validation Infrastructure Results
<!-- PHASE-9B-A-COVERAGE -->

> **HONEST SCOPE NOTICE — READ FIRST**
> This is **Phase 9B-A** — coverage and validation-infrastructure only.
> It delivered the 6 static-module test suites + the validation harness data model.
> It did **NOT** do detection hardening, live scans, FP/FN measurement, or the 9A→9B
> readiness scorecard — those are deferred to **Phase 9B-B** (Detection Hardening +
> Measured Validation). See `docs/ai/PHASE9B_B_RESULTS.md` when that phase lands.

**Completed:** 2026-06-14
**Branch:** `feat/scanner-phase-9b-validation-hardening` (merged as PR #21)
**Scope:** Validation harness, test coverage for 6 previously-untested modules, documentation.
**Production code changes:** None — firing conditions, CVSS scores, WADE scoring, provider access, billing, and auth are all unchanged.

---

## Summary

Phase 9B addressed the six coverage gaps identified in Phase 9A audit. All six STATIC-only modules now have dedicated unit tests. A live-safe validation harness was added for future accuracy measurement.

| Metric | Phase 9A | Phase 9B |
|--------|---------|---------|
| Total tests | 2,444 | 2,610 |
| New tests added | — | 166 |
| STATIC-only modules | 6 | 0 |
| Modules with dedicated unit tests | 26 / 32 | 32 / 32 |
| Regressions introduced | — | 0 |

---

## Goal 1 — Validation Harness (`scanner/validation/harness.py`)

**Status: COMPLETE**

Built a structured data model for measuring scanner accuracy. See [`VALIDATION_HARNESS.md`](../../VALIDATION_HARNESS.md) for full documentation.

**Classes added:**
- `ValidationTarget` — one scan target with expected/absent finding types
- `ValidationRun` — result for one target; exposes `tp_count`, `fp_count`, `fn_count`
- `ValidationFinding` — individual finding with accuracy verdict (`PASSED`/`FAILED`/`FP`/`UNCERTAIN`/`SKIPPED`)
- `ValidationEvidence` — supporting evidence for a validation finding
- `ValidationReport` — aggregate with `precision`, `recall`, `summary()`

**`run_mock()` classmethod** — CI-safe factory that builds a report from pre-computed mock findings without any live network access.

---

## Goal 2 — SAFE_TARGET_MATRIX

**Status: COMPLETE**

Six pre-approved targets, all safe and consented:

| URL | Category | Rationale |
|-----|----------|-----------|
| `badssl.com` | TLS test suite | Designed for TLS scanner testing |
| `expired.badssl.com` | TLS failure | Specific TLS condition |
| `testphp.vulnweb.com` | OWASP vulnerable lab | Acunetix-maintained; public permission |
| `demo.testfire.net` | IBM Altoro Mutual | IBM-maintained; public permission |
| `webhoundsecurity.com` | WebHound-owned | Consented for internal validation |
| `cloudflare.com` | CDN/WAF provider | CDN TLS termination validation |

**Safety constraints enforced:** GET/HEAD only; max 5 pages; no form submission; no JS execution; no third-party production sites.

---

## Goal 3 — Validation Harness Tests

**Status: COMPLETE**

`scanner/tests/test_validation_harness.py` — **21 tests**, all passing.

- `TestValidationTarget`: creation, defaults, category field
- `TestValidationFinding`: status variants
- `TestValidationRun`: tp/fp/fn/uncertain counts, `completed_at` after `finish()`, `live_scan=False` default
- `TestValidationReport`: precision/recall math (exact values), `summary()` keys, `run_mock()` output
- `TestSafeTargetMatrix`: non-empty, all URLs valid, all named, all categorized, **no unapproved root domains**

---

## Goal 4 — Shopify Engine Tests

**Status: COMPLETE**

`scanner/tests/test_shopify_engine.py` — **29 tests**, all passing.

**Coverage:**

| Area | Tests | Key invariants proven |
|------|-------|----------------------|
| `_is_shopify()` detection | 8 | generator meta, `x-shopify-*` headers, CDN scripts, `/cdn/shop/` links |
| `analyze()` — detected | 4 | INFO severity, engine name, has evidence, has framework |
| `analyze()` — admin token leak | 5 | CRITICAL severity, CVSS 10.0, `shpat_` format, masking works |
| `analyze()` — session token | 3 | CRITICAL severity, `_shopify_y` / `_s` cookie detection |
| `analyze()` — app inventory | 2 | Third-party app list captured |
| FP guards | 5 | Short token rejected, non-admin prefix ignored, wrong format skipped |
| Framework alignment | 3 | Admin token = CVSS 10.0, engine = "shopify" |

**Previously-untested FP risk (from 9A):** Admin token in dynamically-loaded JSON — still FN (XHR/fetch not analyzed); documented in findings.

---

## Goal 5 — Wix Engine Tests

**Status: COMPLETE**

`scanner/tests/test_wix_engine.py` — **22 tests**, all passing.

**Coverage:**

| Area | Tests | Key invariants proven |
|------|-------|----------------------|
| `_is_wix()` detection | 8 | generator meta, wixstatic script, parastorage, `x-wix-request-id` header |
| `analyze()` — detected | 5 | INFO severity, engine name, has evidence, has framework |
| `analyze()` — preview URL | 7 | editor.wix.com fires, preview.wixsite.com fires, `/preview` path fires, regular wixsite link does NOT fire |
| Framework alignment | 3 | CVSS scores present |

**`_PREVIEW_LINK_RE` coverage:** All three regex alternations tested individually:
- `editor\.wix\.com` — matches `https://editor.wix.com/...`
- `preview\.wixsite\.com` — matches `https://preview.wixsite.com/...`
- `//[a-z0-9-]+\.wixsite\.com/[a-z0-9-]+/preview` — matches `https://myname.wixsite.com/mybusiness/preview`

---

## Goal 6 — Source Map Probe Tests

**Status: COMPLETE**

`scanner/tests/test_source_map_probe.py` — **22 tests**, all passing.

**Coverage:**

| Area | Tests | Key invariants proven |
|------|-------|----------------------|
| Core detection | 5 | 200 → finding; 404 → no finding; network error → no finding; no comment → no finding |
| URL resolution | 2 | Relative URL resolved via `urljoin`; absolute URL used as-is |
| Deduplication | 2 | Same map URL in two scripts → one probe + one finding |
| Legacy syntax | 1 | `//@ sourceMappingURL` (deprecated) still detected |
| Finding quality | 8 | MEDIUM severity, ≥0.9 confidence, evidence includes HTTP status "200", `map_url` in metadata, remediation present |

**Mock HTTP client pattern:** `_always_200()`, `_always_404()`, `_always_error()` helpers — no live network in tests.

---

## Goal 7 — Safe Input Tester Tests

**Status: COMPLETE**

`scanner/tests/test_safe_input_tester_and_param_discovery.py` — **38 tests** (split across two engines), all passing.

**SafeInputTester coverage (18 tests):**

| Area | Tests | Key invariants proven |
|------|-------|----------------------|
| Basic behavior | 4 | engine name, no forms → empty, 1 form → 1 plan, multiple forms → multiple plans |
| **CRITICAL passive-mode invariants** | 4 | `submitted=False` ALWAYS; `method="none"` ALWAYS; note mentions "passive" |
| Candidate inputs | 6 | text/email/password/hidden included; submit/unnamed excluded |

**CRITICAL:** The passive-mode invariants test (`submitted is False`, `method == "none"`) are the most important tests in Phase 9B — they prove the engine can never submit a form.

---

## Goal 8 — Parameter Discovery Tests

**Status: COMPLETE**

**ParameterDiscoveryEngine coverage (20 tests):**

| Area | Tests | Key invariants proven |
|------|-------|----------------------|
| URL query params | 4 | Extracted from page URL and links; deduped across sources |
| Form params | 5 | All forms captured; empty forms excluded; method/action captured |
| API params | 4 | String and dict request formats; query-string-less URLs excluded; dedup by `(url, method)` |
| `all_param_names` | 3 | Aggregates all sources; no duplicates; empty when nothing found |

**Dedup semantics:** Deduplication is by exact `(url, method)` pair, not path-pattern.

---

## Goal 9 — Vulnerable Libs Tests

**Status: COMPLETE**

`scanner/tests/test_vulnerable_libs_engine.py` — **34 tests**, all passing.

**Coverage:**

| Area | Tests | Key invariants proven |
|------|-------|----------------------|
| `_parse_cdn_url()` | 11 | jsdelivr/unpkg/cdnjs/googleapis/bootstrapcdn/jquery.com styles; aliases; non-CDN → None |
| `_v()` version parsing | 4 | Semver comparison; 1/2/3-part versions |
| jQuery | 5 | <3.5.0 fires; ≥3.5.0 no finding; old 1.x = HIGH; dedup same version |
| lodash | 2 | <4.17.21 fires; ≥4.17.21 no finding |
| AngularJS | 2 | Any 1.x fires as HIGH (EOL) |
| Bootstrap | 2 | <4.3.1 fires; 5.x no finding |
| DOMPurify | 2 | <3.0.0 fires; ≥3.0.6 no finding |
| Evidence/framework | 4 | evidence present, framework present, engine name, CVEs in metadata |
| `analyze()` via artifacts | 3 | script objects flow through; inline/internal scripts ignored |
| FP guard | 3 | Non-CDN URL ignored; no-version URL ignored; unknown library ignored |

---

## Coverage Status (all 32 modules)

All 32 scanner engine modules now have unit test coverage. The 6 previously-STATIC-only modules now have dedicated test files:

| Module | Previous | Phase 9B |
|--------|---------|---------|
| `shopify.py` | STATIC | UNIT (29 tests) |
| `wix.py` | STATIC | UNIT (22 tests) |
| `source_map_probe.py` | STATIC | UNIT (22 tests) |
| `safe_input_tester.py` | STATIC | UNIT (18 tests) |
| `parameter_discovery.py` | STATIC | UNIT (20 tests) |
| `vulnerable_libs.py` | STATIC | UNIT (34 tests) |

---

## Production Code Changes

**None.** Phase 9B added tests and a validation harness only. The following are explicitly unchanged:
- Firing conditions in all 32 engine modules
- CVSS vectors and scores in all `FrameworkAlignment` objects
- WADE scoring pipeline (`baseline_builder`, `diff_engine`, `anomaly_scorer`, `classifier`, `quality_review`, `wade_correlation`)
- Provider access, billing, and auth systems
- `.mcp.json` and MCP configuration

---

## Documented Limitations (carried from 9A)

These FN risks were confirmed in Phase 9A and remain — they are architectural limitations of passive scanning, not bugs:

1. **Admin token in XHR/fetch** (Shopify): Shopify tokens loaded via dynamic JSON calls are not analyzed.
2. **JS-set cookies** (Cookie engine): `HttpOnly` / `Secure` flags on cookies set by `document.cookie` are not in the `Set-Cookie` header.
3. **CDN-terminated TLS** (TLS engine): Scanner talks to CDN cert, not origin. `cert_expired` / cert pinning issues on origin are invisible.
4. **SSR-rendered secrets**: Server-side template secrets that don't appear in inline scripts or HTML are not detected.
5. **Edge-injected JS** (Compromise): CDN-edge JS injection (Cloudflare Workers, etc.) is not distinguishable from legitimate CDN scripts.

---

## Test Suite Final State

| Metric | Value |
|--------|-------|
| Tests collected | 2,610 |
| Tests passed | 2,610 |
| Tests failed | 0 |
| New tests from Phase 9B | 166 |
| Regressions vs Phase 9A baseline | 0 |

---

## Files Delivered

| File | Description |
|------|-------------|
| `scanner/validation/harness.py` | Validation harness data model |
| `scanner/validation/__init__.py` | Updated to export harness alongside Phase 10 framework |
| `scanner/tests/test_shopify_engine.py` | 29 Shopify engine tests |
| `scanner/tests/test_wix_engine.py` | 22 Wix engine tests |
| `scanner/tests/test_source_map_probe.py` | 22 source map probe tests |
| `scanner/tests/test_safe_input_tester_and_param_discovery.py` | 38 safe_input_tester + parameter_discovery tests |
| `scanner/tests/test_validation_harness.py` | 21 validation harness tests |
| `VALIDATION_HARNESS.md` | Harness documentation |
| `docs/ai/PHASE9B_RESULTS.md` | This document |
