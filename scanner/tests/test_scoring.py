# WebHound — scanner/tests/test_scoring.py
# Tests for _compute_risk_score and risk-level label logic.
#
# Score direction: 0 = safe, 100 = critical.
# Tier caps: critical +85, high +40, medium +30, low +10.
# Thresholds: ≤19 safe | ≤39 low | ≤59 medium | ≤79 high | >79 critical.

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
    engine: str = "test",
) -> ScanResult:
    """Build a minimal ScanResult with the given severity counts in grouped_findings."""
    target = Target.from_url("https://example.com")
    result = ScanResult(target=target)
    for _ in range(critical):
        result.grouped_findings.append(_grouped(Severity.CRITICAL, engine))
    for _ in range(high):
        result.grouped_findings.append(_grouped(Severity.HIGH, engine))
    for _ in range(medium):
        result.grouped_findings.append(_grouped(Severity.MEDIUM, engine))
    for _ in range(low):
        result.grouped_findings.append(_grouped(Severity.LOW, engine))
    for _ in range(info):
        result.grouped_findings.append(_grouped(Severity.INFO, engine))
    return result


_GF_COUNTER = 0


def _grouped(severity: Severity, engine: str = "test") -> GroupedFinding:
    global _GF_COUNTER
    _GF_COUNTER += 1
    return GroupedFinding(
        title=f"Finding {_GF_COUNTER}",
        description="Test finding",
        severity=severity,
        category=FindingCategory.SECURITY_HEADER,
        scanner_engine=engine,
        affected_urls=["https://example.com/"],
        affected_url_count=1,
        evidence_count=1,
        confidence=1.0,
        framework=FrameworkAlignment(),
    )


# ---------------------------------------------------------------------------
# Score arithmetic (0 = safe, 100 = critical)
# ---------------------------------------------------------------------------


class TestScoreArithmetic:
    def test_no_findings_scores_0(self):
        risk, _ = _compute_risk_score(_result_with_breakdown())
        assert risk == 0

    def test_one_critical_adds_30(self):
        risk, _ = _compute_risk_score(_result_with_breakdown(critical=1))
        assert risk == 30

    def test_two_criticals_adds_60(self):
        risk, _ = _compute_risk_score(_result_with_breakdown(critical=2))
        assert risk == 60

    def test_three_criticals_adds_85_capped(self):
        # 3 × 30 = 90, capped at 85
        risk, _ = _compute_risk_score(_result_with_breakdown(critical=3))
        assert risk == 85

    def test_critical_cap_at_85(self):
        # Many criticals: always capped at 85
        risk, _ = _compute_risk_score(_result_with_breakdown(critical=10))
        assert risk == 85

    def test_one_high_adds_15(self):
        risk, _ = _compute_risk_score(_result_with_breakdown(high=1))
        assert risk == 15

    def test_high_cap_at_40(self):
        # 3 × 15 = 45, capped at 40
        risk, _ = _compute_risk_score(_result_with_breakdown(high=3))
        assert risk == 40

    def test_one_medium_adds_7(self):
        risk, _ = _compute_risk_score(_result_with_breakdown(medium=1))
        assert risk == 7

    def test_medium_cap_at_30(self):
        # 5 × 7 = 35, capped at 30
        risk, _ = _compute_risk_score(_result_with_breakdown(medium=5))
        assert risk == 30

    def test_one_low_adds_2(self):
        risk, _ = _compute_risk_score(_result_with_breakdown(low=1))
        assert risk == 2

    def test_low_cap_at_10(self):
        # 6 × 2 = 12, capped at 10
        risk, _ = _compute_risk_score(_result_with_breakdown(low=6))
        assert risk == 10

    def test_info_adds_nothing(self):
        risk, _ = _compute_risk_score(_result_with_breakdown(info=10))
        assert risk == 0

    def test_score_never_exceeds_100(self):
        risk, _ = _compute_risk_score(
            _result_with_breakdown(critical=10, high=10, medium=10, low=10)
        )
        assert risk <= 100

    def test_score_never_below_zero(self):
        risk, _ = _compute_risk_score(_result_with_breakdown())
        assert risk >= 0

    def test_combined_tiers_sum_correctly(self):
        # 1 critical (30) + 1 high (15) + 1 medium (7) + 1 low (2) = 54
        risk, _ = _compute_risk_score(
            _result_with_breakdown(critical=1, high=1, medium=1, low=1)
        )
        assert risk == 54


# ---------------------------------------------------------------------------
# Risk level labels
# ---------------------------------------------------------------------------


class TestRiskLevelLabels:
    def test_no_findings_is_safe(self):
        _, level = _compute_risk_score(_result_with_breakdown())
        assert level == "safe"

    def test_info_only_is_safe(self):
        _, level = _compute_risk_score(_result_with_breakdown(info=20))
        assert level == "safe"

    def test_one_medium_is_safe(self):
        # risk = 7 → safe (≤ 19)
        _, level = _compute_risk_score(_result_with_breakdown(medium=1))
        assert level == "safe"

    def test_three_medium_is_low(self):
        # risk = 21 → low (20–39)
        _, level = _compute_risk_score(_result_with_breakdown(medium=3))
        assert level == "low"

    def test_three_high_is_medium(self):
        # risk = 40 → medium (40–59)
        _, level = _compute_risk_score(_result_with_breakdown(high=3))
        assert level == "medium"

    def test_three_high_three_medium_is_high(self):
        # risk = 40 + 21 = 61 → high (60–79)
        _, level = _compute_risk_score(_result_with_breakdown(high=3, medium=3))
        assert level == "high"

    def test_three_critical_three_high_is_critical(self):
        # risk = 85 + 40 = 125 → 100 (clamped) → critical (> 79)
        _, level = _compute_risk_score(_result_with_breakdown(critical=3, high=3))
        assert level == "critical"

    def test_one_critical_forces_high_label_via_upward_guard(self):
        # risk = 30 → "low" by threshold, but upward guard forces "high"
        _, level = _compute_risk_score(_result_with_breakdown(critical=1))
        assert level == "high"

    def test_one_high_forces_low_label_via_upward_guard(self):
        # risk = 15 → "safe" by threshold, but upward guard forces "low"
        _, level = _compute_risk_score(_result_with_breakdown(high=1))
        assert level == "low"

    def test_critical_label_requires_critical_finding(self):
        # Even with max high + medium + low (40+30+10=80 > 79), no critical → downward guard
        risk, level = _compute_risk_score(
            _result_with_breakdown(high=3, medium=5, low=6)
        )
        assert level != "critical"

    def test_high_label_requires_high_or_critical(self):
        # medium+low only: max = 30+10=40 → medium (not in high range)
        # Guard would apply if somehow in high range
        _, level = _compute_risk_score(_result_with_breakdown(medium=5, low=6))
        assert level in ("safe", "low", "medium")

    def test_many_mediums_cannot_produce_high_or_above(self):
        # medium cap = 30 → max risk from medium alone = 30 → "low"
        _, level = _compute_risk_score(_result_with_breakdown(medium=20))
        assert level in ("safe", "low")

    def test_many_lows_alone_are_safe_or_low(self):
        _, level = _compute_risk_score(_result_with_breakdown(low=20))
        assert level in ("safe", "low")


# ---------------------------------------------------------------------------
# Grouped vs raw findings fallback
# ---------------------------------------------------------------------------


class TestScoringUsesGroupedFindings:
    def test_grouped_findings_take_precedence(self):
        result = _result_with_breakdown(critical=1)
        # Even if severity_breakdown says 0 criticals, grouped findings win
        result.severity_breakdown = SeverityBreakdown(critical=0, high=0)
        risk, level = _compute_risk_score(result)
        assert risk == 30  # 1 critical
        assert level == "high"  # upward guard

    def test_falls_back_to_severity_breakdown_when_no_grouped(self):
        target = Target.from_url("https://example.com")
        result = ScanResult(target=target)
        result.severity_breakdown = SeverityBreakdown(critical=1)
        # grouped_findings is empty — falls back to severity_breakdown
        risk, level = _compute_risk_score(result)
        assert risk == 30
        assert level == "high"  # upward guard


# ---------------------------------------------------------------------------
# WADE engine exclusion from security score
# ---------------------------------------------------------------------------


class TestWadeExclusion:
    def test_wade_critical_does_not_inflate_score_above_security_findings(self):
        # Security: 1 medium → risk = 7 (safe)
        # WADE: 1 "critical" (behavioural) — must NOT raise the score
        target = Target.from_url("https://example.com")
        result = ScanResult(target=target)
        result.grouped_findings.append(_grouped(Severity.MEDIUM, engine="test"))
        result.grouped_findings.append(_grouped(Severity.CRITICAL, engine="wade"))
        risk, level = _compute_risk_score(result)
        # Only security finding (medium) should count: risk = 7
        assert risk == 7
        assert level == "safe"

    def test_wade_only_falls_back_to_wade_findings(self):
        # When ALL findings are WADE (no security engine findings), WADE
        # findings are used as the fallback — they contribute to the score.
        target = Target.from_url("https://example.com")
        result = ScanResult(target=target)
        result.grouped_findings.append(_grouped(Severity.HIGH, engine="wade"))
        risk, level = _compute_risk_score(result)
        # security_grouped = [] → falls back to all grouped (wade HIGH = 15)
        # upward guard (bd.high > 0) → at least "low"
        assert risk == 15
        assert level == "low"

    def test_security_findings_plus_wade_use_security_only(self):
        # Security: 1 critical. WADE: 1 critical. Score should only reflect security.
        target = Target.from_url("https://example.com")
        result = ScanResult(target=target)
        result.grouped_findings.append(_grouped(Severity.CRITICAL, engine="security_headers"))
        result.grouped_findings.append(_grouped(Severity.CRITICAL, engine="wade"))
        risk, level = _compute_risk_score(result)
        # Only 1 security critical: risk = 30, upward guard → high
        assert risk == 30
        assert level == "high"

    def test_all_wade_findings_fall_back_to_breakdown(self):
        # If ALL grouped findings are wade, security_grouped is empty → fall back
        # to result.grouped_findings (all-wade) rather than empty
        target = Target.from_url("https://example.com")
        result = ScanResult(target=target)
        result.grouped_findings.append(_grouped(Severity.HIGH, engine="wade"))
        result.grouped_findings.append(_grouped(Severity.MEDIUM, engine="wade"))
        # security_grouped = [] (empty) → falls back to all grouped (wade)
        risk, level = _compute_risk_score(result)
        # Falls back to wade grouped: high(15) + medium(7) = 22 → low
        # upward guard: bd.high > 0 → at least "low"
        assert risk == 22
        assert level == "low"
