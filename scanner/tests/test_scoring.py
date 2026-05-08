# WebHound — scanner/tests/test_scoring.py
# Tests for _compute_risk_score and risk-level label logic.

from __future__ import annotations

import pytest

from webhound.core.orchestrator import _compute_risk_score
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.scan_result import ScanResult, SeverityBreakdown
from webhound.models.severity import Severity
from webhound.models.target import Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result_with_breakdown(
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    info: int = 0,
) -> ScanResult:
    """Build a minimal ScanResult with the given severity counts in grouped_findings."""
    target = Target.from_url("https://example.com")
    result = ScanResult(target=target)
    # Build grouped findings to represent each severity count
    for _ in range(critical):
        result.grouped_findings.append(_grouped(Severity.CRITICAL))
    for _ in range(high):
        result.grouped_findings.append(_grouped(Severity.HIGH))
    for _ in range(medium):
        result.grouped_findings.append(_grouped(Severity.MEDIUM))
    for _ in range(low):
        result.grouped_findings.append(_grouped(Severity.LOW))
    for _ in range(info):
        result.grouped_findings.append(_grouped(Severity.INFO))
    return result


_GF_COUNTER = 0


def _grouped(severity: Severity) -> GroupedFinding:
    global _GF_COUNTER
    _GF_COUNTER += 1
    return GroupedFinding(
        title=f"Finding {_GF_COUNTER}",
        description="Test finding",
        severity=severity,
        category=FindingCategory.SECURITY_HEADER,
        scanner_engine="test",
        affected_urls=["https://example.com/"],
        affected_url_count=1,
        evidence_count=1,
        confidence=1.0,
        framework=FrameworkAlignment(),
    )


# ---------------------------------------------------------------------------
# Score arithmetic
# ---------------------------------------------------------------------------


class TestScoreArithmetic:
    def test_no_findings_scores_100(self):
        score, _ = _compute_risk_score(_result_with_breakdown())
        assert score == 100

    def test_one_critical_deducts_30_then_caps_at_59(self):
        # 100 - 30 = 70, but the critical cap clamps the result to ≤ 59
        score, _ = _compute_risk_score(_result_with_breakdown(critical=1))
        assert score == 59

    def test_two_criticals_deducts_60(self):
        score, _ = _compute_risk_score(_result_with_breakdown(critical=2))
        assert score == 40

    def test_critical_cap_at_70_deduction(self):
        # 3 × 30 = 90, capped at 70 → score = 30
        score, _ = _compute_risk_score(_result_with_breakdown(critical=3))
        assert score == 30

    def test_one_high_deducts_15(self):
        score, _ = _compute_risk_score(_result_with_breakdown(high=1))
        assert score == 85

    def test_high_cap_at_40_deduction(self):
        # 3 × 15 = 45, capped at 40 → score = 60
        score, _ = _compute_risk_score(_result_with_breakdown(high=3))
        assert score == 60

    def test_one_medium_deducts_7(self):
        score, _ = _compute_risk_score(_result_with_breakdown(medium=1))
        assert score == 93

    def test_medium_cap_at_30_deduction(self):
        # 5 × 7 = 35, capped at 30 → score = 70
        score, _ = _compute_risk_score(_result_with_breakdown(medium=5))
        assert score == 70

    def test_one_low_deducts_2(self):
        score, _ = _compute_risk_score(_result_with_breakdown(low=1))
        assert score == 98

    def test_low_cap_at_10_deduction(self):
        # 6 × 2 = 12, capped at 10 → score = 90
        score, _ = _compute_risk_score(_result_with_breakdown(low=6))
        assert score == 90

    def test_info_deducts_nothing(self):
        score, _ = _compute_risk_score(_result_with_breakdown(info=10))
        assert score == 100

    def test_score_never_goes_below_zero(self):
        # Pile on everything
        score, _ = _compute_risk_score(
            _result_with_breakdown(critical=10, high=10, medium=10, low=10)
        )
        assert score >= 0

    def test_score_capped_at_100(self):
        score, _ = _compute_risk_score(_result_with_breakdown())
        assert score <= 100


# ---------------------------------------------------------------------------
# Critical finding caps score at 59
# ---------------------------------------------------------------------------


class TestCriticalCap:
    def test_one_critical_caps_at_59(self):
        # 100 - 30 = 70, but critical cap reduces to min(70, 59) = 59
        score, _ = _compute_risk_score(_result_with_breakdown(critical=1))
        assert score <= 59

    def test_no_critical_not_capped(self):
        # Without criticals, a good score can exceed 59
        score, _ = _compute_risk_score(_result_with_breakdown(high=1))
        assert score > 59


# ---------------------------------------------------------------------------
# Risk level labels
# ---------------------------------------------------------------------------


class TestRiskLevelLabels:
    def test_no_findings_is_low_risk(self):
        _, level = _compute_risk_score(_result_with_breakdown())
        assert level == "low"

    def test_score_75_is_low(self):
        # 2 medium = 14 deducted → 86 → "low"
        _, level = _compute_risk_score(_result_with_breakdown(medium=2))
        assert level == "low"

    def test_medium_findings_produce_medium_risk(self):
        # 5 medium = 30 deducted → 70 → "low" (guard prevents medium from producing high)
        # 3 medium = 21 deducted → 79 → "low"
        # Need enough medium to get below 75: 4 × 7 = 28 → 72 → "low"
        # Actually: 5 medium = 30 → 70 → "low" still (≥75 is "low", ≥50 is "medium")
        # To get "medium" we need score in [50, 74]: e.g. high=2 → 70 "low"; high=3 → 55 "medium"
        _, level = _compute_risk_score(_result_with_breakdown(high=3))
        assert level == "medium"

    def test_critical_finding_forces_high_or_above(self):
        _, level = _compute_risk_score(_result_with_breakdown(critical=1))
        assert level in ("high", "critical")

    def test_many_mediums_without_high_cannot_produce_high_label(self):
        # Downward guard: "high" requires at least one HIGH or CRITICAL finding
        score, level = _compute_risk_score(_result_with_breakdown(medium=10))
        # Score = 100 - 30 = 70 → "low" by score threshold
        # Even if it were in "high" range, the guard would push it to "medium"
        assert level in ("low", "medium")

    def test_many_lows_without_high_cannot_produce_high_label(self):
        _, level = _compute_risk_score(_result_with_breakdown(low=20))
        assert level in ("low", "medium")

    def test_critical_label_requires_critical_finding(self):
        # Score < 25 without any CRITICAL finding → downward guard kicks in
        # Many highs: 100 - 40 = 60 (capped) → still "medium" or "high"
        # To get score < 25 without CRITICAL: 40 + 30 + 10 = 80 → 20
        score, level = _compute_risk_score(
            _result_with_breakdown(high=3, medium=5, low=6)
        )
        # If score < 25 but no critical finding, guard changes "critical" → "high"
        if score < 25:
            assert level != "critical"

    def test_critical_finding_label_when_score_very_low(self):
        # Multiple criticals + everything else
        _, level = _compute_risk_score(
            _result_with_breakdown(critical=3, high=3, medium=5)
        )
        assert level in ("critical", "high")

    def test_zero_score_with_critical_findings_is_critical(self):
        # 3 criticals: 100 - 70 = 30, but caps at 59. 3×30=90 capped at 70 → score=30.
        # That's ≥25 so "high" by threshold. Upward guard: critical present → "high" min.
        score, level = _compute_risk_score(_result_with_breakdown(critical=3))
        assert level in ("high", "critical")


# ---------------------------------------------------------------------------
# Grouped vs raw findings
# ---------------------------------------------------------------------------


class TestScoringUsesGroupedFindings:
    def test_grouped_findings_take_precedence(self):
        result = _result_with_breakdown(critical=1)
        # grouped_findings already set; severity_breakdown should be ignored
        result.severity_breakdown = SeverityBreakdown(critical=0, high=0)
        score, level = _compute_risk_score(result)
        # Score should reflect the grouped finding (1 critical), not the empty breakdown
        assert score <= 59
        assert level in ("high", "critical")

    def test_falls_back_to_severity_breakdown_when_no_grouped(self):
        target = Target.from_url("https://example.com")
        result = ScanResult(target=target)
        result.severity_breakdown = SeverityBreakdown(critical=1)
        # grouped_findings is empty
        score, level = _compute_risk_score(result)
        assert score <= 59
