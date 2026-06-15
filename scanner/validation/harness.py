# WebHound — scanner/validation/harness.py
# Phase 9B: live validation harness for scanner quality assurance.
#
# SAFETY CONTRACT:
#   - Only WebHound-owned domains, intentionally-vulnerable public test labs,
#     or explicit safe demo endpoints (badssl.com, testphp.vulnweb.com, etc.)
#   - Safe-mode: GET/HEAD only, no POST, no JS execution, no form submission
#   - Rate limits and max-pages limits always respected
#   - Never scan third-party production sites without authorization

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class TargetCategory(str, Enum):
    CLOUDFLARE = "cloudflare"
    VERCEL = "vercel"
    RAILWAY = "railway"
    WORDPRESS = "wordpress"
    SHOPIFY = "shopify"
    WIX = "wix"
    STATIC = "static"
    REACT = "react"
    NEXTJS = "nextjs"
    API_HEAVY = "api_heavy"
    VULNERABLE_LAB = "vulnerable_lab"
    TLS_TEST = "tls_test"


class ValidationStatus(str, Enum):
    PASSED = "passed"        # finding expected and detected
    FAILED = "failed"        # finding expected but not detected (FN)
    FP = "fp"               # finding detected but expected NOT to be (FP)
    UNCERTAIN = "uncertain"  # ambiguous — could be TP or FP depending on context
    SKIPPED = "skipped"     # live target not reachable / CI-safe skip


@dataclass
class ValidationTarget:
    """One scan target for validation.

    Only safe, consented targets are permitted:
      - WebHound-owned domains
      - Public intentionally-vulnerable test labs (badssl.com, testphp.vulnweb.com, etc.)
      - Safe demo/example endpoints with explicit public scanning permission

    NEVER add arbitrary third-party production sites.
    """

    url: str
    name: str
    category: TargetCategory
    provider: str                        # cloudflare, vercel, aws, shopify, wix, etc.
    platform: str                        # wordpress, shopify, react, next.js, etc.
    expected_finding_types: list[str]    # finding types we expect to detect
    expected_absent_types: list[str]     # finding types we expect NOT to fire (FP guards)
    known_constraints: list[str]         # documented limitations for this target
    safe_for_live: bool = True           # False = CI-skip (needs live infrastructure)
    notes: str = ""


@dataclass
class ValidationEvidence:
    engine: str
    finding_type: str
    title: str
    detail: str
    raw: Any = None


@dataclass
class ValidationFinding:
    target_url: str
    engine: str
    finding_type: str
    title: str
    severity: str
    confidence: float
    status: ValidationStatus
    expected: bool
    evidence: list[ValidationEvidence] = field(default_factory=list)
    notes: str = ""


@dataclass
class ValidationRun:
    """Result of running the scanner against one ValidationTarget."""

    target: ValidationTarget
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    findings: list[ValidationFinding] = field(default_factory=list)
    engines_run: list[str] = field(default_factory=list)
    error: str | None = None
    live_scan: bool = False  # True only for live network runs

    def finish(self) -> None:
        self.completed_at = datetime.now(timezone.utc)

    @property
    def tp_count(self) -> int:
        return sum(1 for f in self.findings if f.status == ValidationStatus.PASSED)

    @property
    def fp_count(self) -> int:
        return sum(1 for f in self.findings if f.status == ValidationStatus.FP)

    @property
    def fn_count(self) -> int:
        return sum(1 for f in self.findings if f.status == ValidationStatus.FAILED)

    @property
    def uncertain_count(self) -> int:
        return sum(1 for f in self.findings if f.status == ValidationStatus.UNCERTAIN)


@dataclass
class ValidationReport:
    """Aggregate report across one or more ValidationRuns."""

    runs: list[ValidationRun] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_run(self, run: ValidationRun) -> None:
        self.runs.append(run)

    @property
    def total_tp(self) -> int:
        return sum(r.tp_count for r in self.runs)

    @property
    def total_fp(self) -> int:
        return sum(r.fp_count for r in self.runs)

    @property
    def total_fn(self) -> int:
        return sum(r.fn_count for r in self.runs)

    @property
    def total_uncertain(self) -> int:
        return sum(r.uncertain_count for r in self.runs)

    @property
    def precision(self) -> float:
        denom = self.total_tp + self.total_fp
        return self.total_tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.total_tp + self.total_fn
        return self.total_tp / denom if denom else 0.0

    def summary(self) -> dict[str, Any]:
        return {
            "runs": len(self.runs),
            "total_tp": self.total_tp,
            "total_fp": self.total_fp,
            "total_fn": self.total_fn,
            "total_uncertain": self.total_uncertain,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
        }

    @classmethod
    def run_mock(
        cls,
        targets: list[ValidationTarget],
        mock_results: dict[str, list[ValidationFinding]],
    ) -> "ValidationReport":
        """Build a ValidationReport from pre-computed mock findings.

        Used for unit tests and CI-safe validation without live network access.
        ``mock_results`` maps target URL → list of ValidationFinding.
        """
        report = cls()
        for target in targets:
            run = ValidationRun(target=target, live_scan=False)
            run.findings = mock_results.get(target.url, [])
            run.engines_run = list({f.engine for f in run.findings})
            run.finish()
            report.add_run(run)
        return report


# ---------------------------------------------------------------------------
# Pre-defined safe target matrix
# ---------------------------------------------------------------------------

SAFE_TARGET_MATRIX: list[ValidationTarget] = [
    ValidationTarget(
        url="https://badssl.com/",
        name="badssl.com — TLS test suite",
        category=TargetCategory.TLS_TEST,
        provider="self-hosted",
        platform="static",
        expected_finding_types=["cert_expired", "weak_protocol", "weak_cipher"],
        expected_absent_types=["packer", "injected_js"],
        known_constraints=[
            "Individual badssl subdomains test specific conditions; the root domain is valid",
            "Some subdomains may not resolve in restricted CI environments",
        ],
        safe_for_live=True,
        notes="Designed explicitly for TLS scanner testing. See https://badssl.com",
    ),
    ValidationTarget(
        url="https://expired.badssl.com/",
        name="badssl.com — expired cert",
        category=TargetCategory.TLS_TEST,
        provider="self-hosted",
        platform="static",
        expected_finding_types=["cert_expired"],
        expected_absent_types=[],
        known_constraints=["cert_expired is the only expected finding"],
        safe_for_live=True,
    ),
    ValidationTarget(
        url="https://testphp.vulnweb.com/",
        name="testphp.vulnweb.com — OWASP vulnerable web app",
        category=TargetCategory.VULNERABLE_LAB,
        provider="acunetix",
        platform="php",
        expected_finding_types=["api_exposure", "sensitive_paths_exposed", "robots_disclosure"],
        expected_absent_types=[],
        known_constraints=[
            "Intentionally vulnerable — all findings are expected true positives",
            "May be unreachable from restricted CI environments",
            "Rate-limit: max 5 pages, max_depth=1",
        ],
        safe_for_live=True,
        notes="Maintained by Acunetix explicitly for scanner testing. Public permission implied.",
    ),
    ValidationTarget(
        url="https://demo.testfire.net/",
        name="AltoroMutual — IBM test bank",
        category=TargetCategory.VULNERABLE_LAB,
        provider="ibm",
        platform="j2ee",
        expected_finding_types=["missing_csp", "missing_hsts"],
        expected_absent_types=["wordpress_detected", "shopify_detected"],
        known_constraints=[
            "Intentionally vulnerable — maintained by IBM for security testing",
            "Financial-themed demo site",
        ],
        safe_for_live=True,
        notes="IBM Altoro Mutual demo bank. Public scanning permitted.",
    ),
    ValidationTarget(
        url="https://webhoundsecurity.com/",
        name="WebHound marketing site",
        category=TargetCategory.VERCEL,
        provider="vercel",
        platform="nextjs",
        expected_finding_types=["technology_detected"],
        expected_absent_types=["admin_token_leak", "packer", "injected_js"],
        known_constraints=[
            "Vercel deployment-protection may be active on preview branches",
            "Next.js source maps should be disabled in production",
        ],
        safe_for_live=True,
        notes="WebHound-owned domain. Consented for internal validation.",
    ),
    # Cloudflare-protected target (synthetic — for provider edge-case validation)
    ValidationTarget(
        url="https://cloudflare.com/",
        name="Cloudflare.com — CDN/WAF provider",
        category=TargetCategory.CLOUDFLARE,
        provider="cloudflare",
        platform="static",
        expected_finding_types=["technology_detected"],
        expected_absent_types=["provider_blocked_scan"],
        known_constraints=[
            "Cloudflare itself won't trigger WAF challenge pages for most scanner IPs",
            "CDN TLS — scanner sees Cloudflare cert, not origin cert",
            "Verifying CDN-terminated TLS limitation",
        ],
        safe_for_live=True,
        notes="Public site, not a production customer. CDN TLS validation target.",
    ),
]
