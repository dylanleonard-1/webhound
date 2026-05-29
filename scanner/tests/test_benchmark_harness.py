# WebHound — scanner/tests/test_benchmark_harness.py
# Phase-5E benchmark harness tests.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.benchmark.harness import (
    BenchmarkSite,
    CURATED_SITES,
    FindingExpectation,
    compare,
    run_suite,
)
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory
from webhound.models.scan_result import ScanResult, ScanStatus
from webhound.models.severity import Severity
from webhound.models.target import Target


def _f(*, title, engine="security_headers", severity=Severity.MEDIUM) -> Finding:
    return Finding(
        title=title, description="long enough description for audit " * 3,
        severity=severity, category=FindingCategory.SECURITY_HEADER,
        scanner_engine=engine,
        confidence=0.9,
        severity_rationale="r",
        confidence_rationale="r",
        evidence=[Evidence(
            evidence_type=EvidenceType.HEADER, content="x",
            location="https://target/", source_engine=engine,
        )],
    )


def _result(findings, risk_score=50) -> ScanResult:
    r = ScanResult(
        target=Target.from_url("https://target/"),
        status=ScanStatus.COMPLETED,
        findings=findings,
        engines_run=["security_headers"],
        urls_crawled=1,
        pages_analyzed=1,
        started_at=datetime(2026, 5, 29, tzinfo=timezone.utc),
        completed_at=datetime(2026, 5, 29, tzinfo=timezone.utc),
    )
    r.recompute_aggregates()
    r.metadata["risk_score"] = risk_score
    return r


# ---------------------------------------------------------------------------
# Expectation matching
# ---------------------------------------------------------------------------


def test_expectation_substring_match() -> None:
    exp = FindingExpectation(
        engine="security_headers",
        title_substring="content-security",
    )
    assert exp.matches(_f(title="Missing Content-Security-Policy"))
    assert not exp.matches(_f(title="Missing X-Frame-Options"))


def test_expectation_engine_match_is_required() -> None:
    exp = FindingExpectation(
        engine="cookies", title_substring="missing secure",
    )
    assert not exp.matches(
        _f(engine="security_headers", title="missing Secure"),
    )


def test_expectation_min_severity_enforced() -> None:
    exp = FindingExpectation(
        engine="security_headers", title_substring="x",
        min_severity="high",
    )
    assert exp.matches(_f(title="x-frame", severity=Severity.HIGH))
    assert not exp.matches(_f(title="x-frame", severity=Severity.LOW))


# ---------------------------------------------------------------------------
# compare() — TP / FN / FP accounting
# ---------------------------------------------------------------------------


def test_expected_finding_present_counts_tp() -> None:
    site = BenchmarkSite(
        name="x", category="x", url="x",
        expected_findings=[FindingExpectation(
            engine="security_headers",
            title_substring="content-security",
        )],
    )
    bm = compare(site, _result([
        _f(title="Missing Content-Security-Policy"),
    ]))
    assert bm.true_positives == 1
    assert bm.false_negatives == 0
    assert bm.overall_passed is True


def test_expected_finding_missing_counts_fn() -> None:
    site = BenchmarkSite(
        name="x", category="x", url="x",
        expected_findings=[FindingExpectation(
            engine="security_headers",
            title_substring="content-security",
        )],
    )
    bm = compare(site, _result([]))
    assert bm.true_positives == 0
    assert bm.false_negatives == 1
    assert bm.overall_passed is False


def test_expected_non_finding_appearing_counts_fp() -> None:
    """A non-finding expectation that actually appears in the scan
    output is a false positive — and the suite fails."""
    site = BenchmarkSite(
        name="x", category="x", url="x",
        expected_non_findings=[FindingExpectation(
            engine="injected_js",
            title_substring="injected javascript",
        )],
    )
    bm = compare(site, _result([
        _f(engine="injected_js",
           title="Injected JavaScript detected"),
    ]))
    assert bm.false_positives == 1
    assert bm.overall_passed is False


def test_risk_score_under_min_fails() -> None:
    site = BenchmarkSite(
        name="x", category="x", url="x",
        expected_risk_min=60,
    )
    bm = compare(site, _result([], risk_score=40))
    assert bm.risk_in_range is False
    assert bm.overall_passed is False


def test_risk_score_over_max_fails() -> None:
    site = BenchmarkSite(
        name="x", category="x", url="x",
        expected_risk_max=70,
    )
    bm = compare(site, _result([], risk_score=85))
    assert bm.risk_in_range is False
    assert bm.overall_passed is False


# ---------------------------------------------------------------------------
# Precision + recall
# ---------------------------------------------------------------------------


def test_precision_and_recall_clean_run() -> None:
    site = BenchmarkSite(
        name="x", category="x", url="x",
        expected_findings=[FindingExpectation(
            engine="security_headers",
            title_substring="content-security",
        )],
    )
    bm = compare(site, _result([
        _f(title="Missing Content-Security-Policy"),
    ]))
    assert bm.precision == 1.0
    assert bm.recall == 1.0


def test_recall_drops_on_false_negative() -> None:
    site = BenchmarkSite(
        name="x", category="x", url="x",
        expected_findings=[
            FindingExpectation(
                engine="security_headers",
                title_substring="content-security",
            ),
            FindingExpectation(
                engine="security_headers",
                title_substring="x-frame",
            ),
        ],
    )
    bm = compare(site, _result([
        _f(title="Missing Content-Security-Policy"),
    ]))
    # 1 of 2 expected findings present.
    assert bm.recall == 0.5


# ---------------------------------------------------------------------------
# Curated suite registry
# ---------------------------------------------------------------------------


def test_curated_sites_categories_diverse() -> None:
    categories = {s.category for s in CURATED_SITES}
    assert "clean" in categories
    assert "spa" in categories
    assert "vulnerable_lab" in categories
    assert "api_app" in categories


def test_run_suite_pairs_each_site_with_result() -> None:
    sites = [CURATED_SITES[0]]
    results = [_result([])]
    bms = run_suite(list(zip(sites, results)))
    assert len(bms) == 1
    assert bms[0].site.name == "example_clean_static"


def test_to_dict_round_trip_shape() -> None:
    site = BenchmarkSite(
        name="x", category="clean", url="x",
        expected_findings=[FindingExpectation(
            engine="security_headers", title_substring="csp",
        )],
        expected_non_findings=[FindingExpectation(
            engine="threat_intel", title_substring="evil",
        )],
        expected_risk_min=0, expected_risk_max=70,
    )
    bm = compare(site, _result([
        _f(title="Missing CSP — Content-Security-Policy"),
    ]))
    d = bm.to_dict()
    for k in ("site", "overall_passed", "risk_score", "risk_in_range",
               "true_positives", "false_negatives", "false_positives",
               "precision", "recall", "expected_findings",
               "expected_non_findings"):
        assert k in d
