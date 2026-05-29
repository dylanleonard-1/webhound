# WebHound — webhound/benchmark/harness.py
# Phase-5E: scanner quality validation harness.
#
# Each benchmark site declares:
#   * a name + category ('clean', 'spa', 'vulnerable_lab', etc.)
#   * the URL or stub that the scanner runs against
#   * expected_findings — a list of (engine, title_substring) tuples
#     that MUST appear in the scan output
#   * expected_non_findings — same shape, MUST NOT appear (false-
#     positive guards)
#   * expected_risk_range — (min, max) risk-score window
#
# The harness compares the ScanResult against these and emits a
# BenchmarkResult with precision/recall + per-expectation pass/fail.
# The harness itself is scan-mechanism agnostic — it operates on a
# ScanResult — so tests can build synthetic results to exercise the
# comparison logic without launching the full pipeline.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from webhound.models.scan_result import ScanResult


@dataclass
class FindingExpectation:
    """One expected finding signature. Matching is substring-based on
    the title and exact-match on the engine name — so ``("cookies",
    "missing Secure")`` matches any finding emitted by the cookies
    engine whose title contains 'missing Secure'."""

    engine: str
    title_substring: str
    # Optional minimum severity rank — when set, the matched finding
    # must be at least this severity for the expectation to pass.
    # Useful for "this lab MUST report a HIGH" guards.
    min_severity: str | None = None

    def matches(self, finding: Any) -> bool:
        if (finding.scanner_engine or "").lower() != self.engine.lower():
            return False
        title = (finding.title or "").lower()
        if self.title_substring.lower() not in title:
            return False
        if self.min_severity is not None:
            from webhound.models.severity import Severity
            try:
                wanted = Severity(self.min_severity.lower())
            except ValueError:
                return True
            return finding.severity.rank >= wanted.rank
        return True


@dataclass
class BenchmarkSite:
    """One declarative benchmark fixture."""

    name: str
    category: str
    url: str
    expected_findings: list[FindingExpectation] = field(
        default_factory=list,
    )
    expected_non_findings: list[FindingExpectation] = field(
        default_factory=list,
    )
    expected_risk_min: int | None = None
    expected_risk_max: int | None = None
    notes: str = ""


@dataclass
class ExpectationResult:
    expectation: FindingExpectation
    passed: bool
    matched_titles: list[str] = field(default_factory=list)


@dataclass
class BenchmarkResult:
    site: BenchmarkSite
    expected_findings_results: list[ExpectationResult] = field(
        default_factory=list,
    )
    expected_non_findings_results: list[ExpectationResult] = field(
        default_factory=list,
    )
    risk_score: int | None = None
    risk_in_range: bool = True
    # Derived overall pass/fail.
    overall_passed: bool = True

    # Derived metrics.
    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        if denom == 0:
            return 1.0
        return round(self.true_positives / denom, 4)

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        if denom == 0:
            return 1.0
        return round(self.true_positives / denom, 4)

    def to_dict(self) -> dict[str, Any]:
        return {
            "site": {
                "name": self.site.name,
                "category": self.site.category,
                "url": self.site.url,
            },
            "overall_passed": self.overall_passed,
            "risk_score": self.risk_score,
            "risk_in_range": self.risk_in_range,
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "precision": self.precision,
            "recall": self.recall,
            "expected_findings": [
                {
                    "engine": e.expectation.engine,
                    "title_substring": e.expectation.title_substring,
                    "passed": e.passed,
                    "matched_titles": e.matched_titles,
                }
                for e in self.expected_findings_results
            ],
            "expected_non_findings": [
                {
                    "engine": e.expectation.engine,
                    "title_substring": e.expectation.title_substring,
                    "passed": e.passed,
                    "matched_titles": e.matched_titles,
                }
                for e in self.expected_non_findings_results
            ],
        }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def compare(site: BenchmarkSite,
            result: ScanResult) -> BenchmarkResult:
    """Run every expectation in ``site`` against the ScanResult.

    Returns a :class:`BenchmarkResult` with per-expectation pass/fail
    + aggregate TP/FN/FP counts + precision/recall + an overall
    ``passed`` flag.

    An expected finding that doesn't appear is a false negative.
    An expected_non_finding that does appear is a false positive."""
    bm = BenchmarkResult(site=site)
    findings = list(result.active_findings)

    # Expected findings — each must appear at least once.
    for exp in site.expected_findings:
        matches = [f for f in findings if exp.matches(f)]
        passed = bool(matches)
        bm.expected_findings_results.append(ExpectationResult(
            expectation=exp, passed=passed,
            matched_titles=[m.title for m in matches[:5]],
        ))
        if passed:
            bm.true_positives += 1
        else:
            bm.false_negatives += 1
            bm.overall_passed = False

    # Expected non-findings — each must NOT appear.
    for exp in site.expected_non_findings:
        matches = [f for f in findings if exp.matches(f)]
        passed = (len(matches) == 0)
        bm.expected_non_findings_results.append(ExpectationResult(
            expectation=exp, passed=passed,
            matched_titles=[m.title for m in matches[:5]],
        ))
        if not passed:
            bm.false_positives += 1
            bm.overall_passed = False

    # Risk score window.
    bm.risk_score = result.metadata.get("risk_score")
    if (bm.risk_score is not None
            and site.expected_risk_min is not None
            and bm.risk_score < site.expected_risk_min):
        bm.risk_in_range = False
        bm.overall_passed = False
    if (bm.risk_score is not None
            and site.expected_risk_max is not None
            and bm.risk_score > site.expected_risk_max):
        bm.risk_in_range = False
        bm.overall_passed = False
    return bm


# ---------------------------------------------------------------------------
# Curated default suite
# ---------------------------------------------------------------------------


CURATED_SITES: tuple[BenchmarkSite, ...] = (
    BenchmarkSite(
        name="example_clean_static",
        category="clean",
        url="https://example.com/",
        expected_findings=[],
        expected_non_findings=[
            FindingExpectation(
                engine="threat_intel",
                title_substring="likely malicious",
            ),
            FindingExpectation(
                engine="injected_js",
                title_substring="injected javascript",
            ),
        ],
        expected_risk_min=0,
        expected_risk_max=70,
        notes="Static clean site; no compromise indicators expected.",
    ),
    BenchmarkSite(
        name="nextjs_spa",
        category="spa",
        url="https://nextjs-demo.example/",
        expected_findings=[
            # SPA sites typically lack a strong CSP. We expect the
            # CSP engine to flag it.
            FindingExpectation(
                engine="security_headers",
                title_substring="content-security-policy",
            ),
        ],
        expected_non_findings=[
            FindingExpectation(
                engine="injected_js",
                title_substring="seo spam",
            ),
        ],
        notes="Modern SPA — expect CSP gap, no compromise indicators.",
    ),
    BenchmarkSite(
        name="vulnerable_lab",
        category="vulnerable_lab",
        url="https://lab.invalid.example/",
        expected_findings=[
            FindingExpectation(
                engine="cookies",
                title_substring="secure",
                min_severity="medium",
            ),
        ],
        expected_non_findings=[],
        expected_risk_min=60,
        notes="Mock vulnerable lab — high-severity baseline.",
    ),
    BenchmarkSite(
        name="api_heavy_app",
        category="api_app",
        url="https://api-app.example/",
        expected_findings=[],
        expected_non_findings=[
            FindingExpectation(
                engine="threat_intel",
                title_substring="likely malicious",
            ),
        ],
        notes="API-heavy app — many fetch endpoints but clean.",
    ),
)


def run_suite(
    runners: Sequence[tuple[BenchmarkSite, ScanResult]],
) -> list[BenchmarkResult]:
    """Run the harness across a list of (site, scan_result) pairs and
    return one BenchmarkResult per site. Caller is responsible for
    producing each ScanResult — the harness itself does no scanning,
    so a live integration test, a synthetic test, or a recorded scan
    all work."""
    return [compare(site, result) for site, result in runners]
