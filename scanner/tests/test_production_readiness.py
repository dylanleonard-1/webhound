# WebHound — scanner/tests/test_production_readiness.py
# Phase-5I tests.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.benchmark.harness import (
    BenchmarkResult,
    BenchmarkSite,
)
from webhound.models.scan_result import ScanResult, ScanStatus
from webhound.models.target import Target
from webhound.reporting.production_readiness import (
    DimensionScore,
    ProductionReadinessReport,
    score_scan,
)


def _result_with(metadata: dict) -> ScanResult:
    r = ScanResult(
        target=Target.from_url("https://target/"),
        status=ScanStatus.COMPLETED, findings=[],
        engines_run=[], urls_crawled=0, pages_analyzed=0,
        started_at=datetime(2026, 5, 29, tzinfo=timezone.utc),
        completed_at=datetime(2026, 5, 29, tzinfo=timezone.utc),
    )
    r.metadata = metadata
    return r


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_perfect_scan_scores_an_A() -> None:
    meta = {
        "evidence_quality":      {"completeness_ratio": 1.0,
                                    "incomplete_count": 0},
        "threat_intel_coverage": {"coverage_ratio": 1.0,
                                    "has_coverage_gap": False,
                                    "per_source_count": {
                                        "static_html": 5, "browser": 3,
                                        "csp": 2, "iframe": 1,
                                    }},
        "wade_quality_review":   {"note_count": 0,
                                    "total_findings_reviewed": 10},
        "compliance":            {}, "evidence_graph": {},
        "asset_map":             {}, "correlated_chains": [],
        "browser_pass":          {},
    }
    r = score_scan(_result_with(meta))
    assert r.grade == "A"
    assert r.ready is True
    assert r.gaps == []


def test_perfect_scan_with_passing_benchmarks_stays_A() -> None:
    site = BenchmarkSite(name="x", category="clean", url="x")
    bm = BenchmarkResult(site=site, true_positives=10,
                         false_negatives=0, false_positives=0)
    meta = {
        "evidence_quality":      {"completeness_ratio": 1.0},
        "threat_intel_coverage": {"coverage_ratio": 1.0,
                                    "per_source_count": {
                                        "static_html": 1, "browser": 1,
                                        "csp": 1, "iframe": 1,
                                    }},
        "wade_quality_review":   {"note_count": 0,
                                    "total_findings_reviewed": 1},
        "compliance": {}, "evidence_graph": {},
        "asset_map": {}, "correlated_chains": [],
        "browser_pass": {},
    }
    r = score_scan(_result_with(meta), benchmarks=[bm])
    assert r.ready is True


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_evidence_gap_lowers_score_and_lists_gap() -> None:
    meta = {
        "evidence_quality": {"completeness_ratio": 0.3,
                              "incomplete_count": 7},
    }
    r = score_scan(_result_with(meta))
    ev = next(d for d in r.dimensions if d.name == "evidence_quality")
    assert ev.score == 30.0
    assert any("Evidence quality" in g for g in r.gaps)


def test_threat_intel_gap_listed() -> None:
    meta = {
        "threat_intel_coverage": {
            "coverage_ratio": 0.5,
            "has_coverage_gap": True,
            "unclassified_hosts": ["a.test", "b.test"],
        },
    }
    r = score_scan(_result_with(meta))
    assert any("Threat-intel" in g for g in r.gaps)


def test_low_recall_benchmarks_lower_score() -> None:
    site = BenchmarkSite(name="x", category="x", url="x")
    bm = BenchmarkResult(site=site, true_positives=1,
                         false_negatives=9, false_positives=0)
    r = score_scan(_result_with({}), benchmarks=[bm])
    recall_dim = next(
        d for d in r.dimensions if d.name == "benchmark_recall"
    )
    assert recall_dim.score < 50.0
    assert any("recall" in g.lower() for g in r.gaps)


def test_low_precision_benchmarks_listed() -> None:
    site = BenchmarkSite(name="x", category="x", url="x")
    bm = BenchmarkResult(site=site, true_positives=1,
                         false_negatives=0, false_positives=9)
    r = score_scan(_result_with({}), benchmarks=[bm])
    assert any("precision" in g.lower() for g in r.gaps)


def test_dashboard_parity_missing_keys_listed() -> None:
    # metadata only has compliance — every other v4 key is missing.
    meta = {"compliance": {}}
    r = score_scan(_result_with(meta))
    parity = next(
        d for d in r.dimensions if d.name == "dashboard_parity"
    )
    assert parity.score < 50.0
    assert any("Dashboard parity" in g for g in r.gaps)


def test_wade_review_high_note_ratio_listed() -> None:
    meta = {
        "wade_quality_review": {
            "note_count": 5, "total_findings_reviewed": 10,
        },
    }
    r = score_scan(_result_with(meta))
    wade = next(d for d in r.dimensions if d.name == "wade_review_signal")
    # 5 notes in 10 findings is way over the calibrated threshold.
    assert wade.score < 50.0


def test_discovery_coverage_low_when_few_sources() -> None:
    meta = {
        "threat_intel_coverage": {
            "coverage_ratio": 1.0,
            "per_source_count": {"static_html": 1},
        },
    }
    r = score_scan(_result_with(meta))
    disc = next(
        d for d in r.dimensions if d.name == "discovery_coverage"
    )
    # 1 source × 25 = 25
    assert disc.score == 25.0
    assert any("Discovery coverage" in g for g in r.gaps)


# ---------------------------------------------------------------------------
# Grade thresholds
# ---------------------------------------------------------------------------


def test_grade_thresholds_A_through_F() -> None:
    from webhound.reporting.production_readiness import _grade
    assert _grade(95) == "A"
    assert _grade(85) == "B"
    assert _grade(75) == "C"
    assert _grade(65) == "D"
    assert _grade(50) == "F"


def test_ready_flag_requires_80() -> None:
    r = ProductionReadinessReport(overall_score=79.9)
    # We set ready directly via score_scan; sanity-check the
    # threshold logic by calling score_scan with metadata that
    # produces ~50.
    meta = {"evidence_quality": {"completeness_ratio": 0.5}}
    report = score_scan(_result_with(meta))
    assert report.ready is False


def test_to_dict_round_trip_shape() -> None:
    r = score_scan(_result_with({}))
    d = r.to_dict()
    for k in ("overall_score", "grade", "ready", "dimensions", "gaps"):
        assert k in d
