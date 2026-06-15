# WebHound Scanner Validation Harness
<!-- PHASE-9B-HARNESS -->

**Location:** `scanner/validation/harness.py`  
**Added:** Phase 9B — Scanner Validation & Hardening  
**Safe-mode:** All validation runs are passive (GET/HEAD only). No form submission, no JS execution.

---

## Purpose

The validation harness provides a structured data model for measuring scanner accuracy against known-good and known-vulnerable targets. It tracks true positives, false positives, and false negatives without touching production WADE scoring.

---

## Data Model

### `ValidationTarget`
One scan target. Only safe, consented URLs are permitted:
- WebHound-owned domains (`webhoundsecurity.com`)
- Public intentionally-vulnerable test labs (`testphp.vulnweb.com`, `badssl.com`, `demo.testfire.net`)
- Safe CDN/provider endpoints for provider-detection testing (`cloudflare.com`)

```python
@dataclass
class ValidationTarget:
    url: str
    name: str
    category: TargetCategory           # cloudflare, vercel, vulnerable_lab, tls_test, etc.
    provider: str                      # cloudflare, vercel, aws, shopify, wix, etc.
    platform: str                      # wordpress, shopify, react, next.js, etc.
    expected_finding_types: list[str]  # finding types expected to fire (TP)
    expected_absent_types: list[str]   # finding types expected NOT to fire (FP guards)
    known_constraints: list[str]       # documented limitations for this target
    safe_for_live: bool = True         # False = CI-skip (needs live infrastructure)
```

### `ValidationFinding`
One scanner finding with an accuracy verdict.

| Status | Meaning |
|--------|---------|
| `PASSED` | Expected finding was detected (TP) |
| `FAILED` | Expected finding was NOT detected (FN) |
| `FP` | Finding detected but NOT expected (FP) |
| `UNCERTAIN` | Ambiguous — depends on context |
| `SKIPPED` | Target not reachable / CI skip |

### `ValidationRun`
Result of running the scanner against one target. Properties:
- `tp_count`, `fp_count`, `fn_count`, `uncertain_count`
- `live_scan: bool` — always `False` in unit test mode; `True` only for live runs

### `ValidationReport`
Aggregate across multiple runs.
- `precision = tp / (tp + fp)` — "what fraction of findings are real?"
- `recall = tp / (tp + fn)` — "what fraction of real issues did we catch?"
- `run_mock(targets, mock_results)` — CI-safe factory (no network required)

---

## SAFE_TARGET_MATRIX

Six pre-defined targets, all safe and consented:

| Target | Category | Why safe |
|--------|----------|---------|
| `badssl.com` | TLS test suite | Designed for TLS scanner testing |
| `expired.badssl.com` | TLS test | Specific TLS failure condition |
| `testphp.vulnweb.com` | Vulnerable lab | Acunetix-maintained; public scanning implied |
| `demo.testfire.net` | Vulnerable lab | IBM Altoro Mutual; public scanning permitted |
| `webhoundsecurity.com` | Marketing site | WebHound-owned; consented |
| `cloudflare.com` | CDN/WAF | Public infrastructure; CDN TLS validation |

**NEVER add arbitrary third-party production sites.** Any new entry must meet one of:
1. WebHound-owned domain
2. Intentionally-vulnerable lab with public scanning permission
3. Public infrastructure explicitly designed for security testing

---

## Usage

### Unit test (CI-safe, no network)

```python
from validation.harness import (
    ValidationTarget, ValidationReport, ValidationFinding,
    ValidationStatus, TargetCategory,
)

target = ValidationTarget(
    url="https://example.com/",
    name="test",
    category=TargetCategory.STATIC,
    provider="self",
    platform="html",
    expected_finding_types=["missing_csp"],
    expected_absent_types=[],
    known_constraints=[],
)

mock_results = {
    "https://example.com/": [
        ValidationFinding(
            target_url="https://example.com/",
            engine="security_headers",
            finding_type="missing_csp",
            title="Missing Content-Security-Policy",
            severity="medium",
            confidence=0.95,
            status=ValidationStatus.PASSED,
            expected=True,
        )
    ]
}

report = ValidationReport.run_mock([target], mock_results)
assert report.precision == 1.0
assert report.recall == 1.0
```

### Live validation (manual only, never in CI)

```python
# NEVER called from automated CI — live_scan=True requires operator approval
run = ValidationRun(target=target, live_scan=True)
# ... run the scanner against target.url ...
# ... populate run.findings with ValidationFinding objects ...
run.finish()
```

---

## Live-target safety contract

Any live scan (outside of `run_mock`) MUST follow:

1. **Targets**: Only URLs in `SAFE_TARGET_MATRIX` or WebHound-owned domains
2. **Method**: GET/HEAD only — never POST, PUT, DELETE, or PATCH
3. **Forms**: Never submitted, not even test inputs
4. **Rate limits**: ≤2 requests/second; max 5 pages per validation run
5. **No JS execution**: No headless browser, no JS rendering
6. **Credentials**: Never send authentication headers to external targets

---

## Test coverage

`scanner/tests/test_validation_harness.py` — 21 tests covering all model classes and `SAFE_TARGET_MATRIX` integrity.
