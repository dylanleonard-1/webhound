# WebHound — tests/test_risk_scoring.py
# Phase-7 centralized trust-weighted risk scoring (Task 9 battery).
# The contract: inventory never scores, hardening and heuristics are
# capped, volume cannot fake severity, and one confirmed CRITICAL
# moves the needle hard.

from __future__ import annotations

from webhound.core.risk_scoring import compute_risk_score
from webhound.models.finding import FindingCategory
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.scan_result import ScanResult
from webhound.models.severity import Severity
from webhound.models.target import Target


def _grouped(title="Issue", severity=Severity.MEDIUM, engine="engine_a",
             category=FindingCategory.JAVASCRIPT, confidence=1.0,
             finding_type="confirmed_risk", confidence_label="confirmed",
             ) -> GroupedFinding:
    return GroupedFinding(
        title=title, severity=severity, category=category,
        scanner_engine=engine, description="d", confidence=confidence,
        metadata={"finding_type": finding_type,
                  "confidence_label": confidence_label},
    )


def _result(groups) -> ScanResult:
    r = ScanResult(target=Target.from_url("https://t.test/"))
    r.grouped_findings = list(groups)
    return r


# ---------------------------------------------------------------------------
# Task 9 scenarios
# ---------------------------------------------------------------------------


def test_inventory_findings_do_not_change_risk_score() -> None:
    """#1 + #8: any amount of inventory (APIs observed, third-party
    services, technology) scores exactly zero."""
    groups = [
        _grouped(title=f"Observed thing {i}", severity=Severity.INFO,
                 finding_type="inventory", confidence_label="confirmed")
        for i in range(40)
    ] + [
        # Even inventory that kept a LOW severity contributes 0.
        _grouped(title="Third-party service observed",
                 severity=Severity.LOW, finding_type="inventory"),
    ]
    score, level, bd = compute_risk_score(_result(groups))
    assert score == 0
    assert level == "safe"
    assert bd.type_totals["inventory"] == 0.0


def test_missing_headers_grouped_and_capped() -> None:
    """#2: a pile of MEDIUM header-hardening findings caps at 12."""
    headers = [
        # Same engine: repetition damping kicks in first.
        _grouped(title=f"Missing header {i}", severity=Severity.MEDIUM,
                 engine="security_headers",
                 category=FindingCategory.SECURITY_HEADER,
                 finding_type="hardening", confidence_label="confirmed")
        for i in range(12)
    ] + [
        # Other header engines (csp_engine, cors...) — enough volume
        # that the explicit header cap must fire.
        _grouped(title=f"CSP issue {i}", severity=Severity.MEDIUM,
                 engine=f"csp_engine_{i}",
                 category=FindingCategory.SECURITY_HEADER,
                 finding_type="hardening", confidence_label="confirmed")
        for i in range(10)
    ]
    score, level, bd = compute_risk_score(_result(headers))
    assert score <= 12
    assert level == "safe"
    assert any("security-header" in c for c in bd.caps_applied)


def test_many_low_findings_cannot_fake_high_risk() -> None:
    """#3: 50 LOW likely-risks across engines stay far below 'high'."""
    groups = [
        _grouped(title=f"Low issue {i}", severity=Severity.LOW,
                 engine=f"engine_{i % 5}", finding_type="likely_risk",
                 confidence_label="medium")
        for i in range(50)
    ]
    score, level, _ = compute_risk_score(_result(groups))
    assert score < 40
    assert level in ("safe", "low")


def test_heuristic_findings_capped_at_10() -> None:
    """#4: heuristic signals saturate at +10 total."""
    groups = [
        _grouped(title=f"Suspicious pattern {i}", severity=Severity.HIGH,
                 engine=f"eng{i}", finding_type="heuristic_signal",
                 confidence_label="heuristic")
        for i in range(20)
    ]
    score, level, bd = compute_risk_score(_result(groups))
    assert bd.type_totals["heuristic_signal"] == 10.0
    assert score == 10
    assert level == "safe"


def test_confirmed_critical_strongly_affects_risk() -> None:
    """#5 + #10: one confirmed CRITICAL (exposed secret) scores 35 and
    the level guard forces at least 'high'."""
    groups = [_grouped(title="Exposed .env file with credentials",
                       severity=Severity.CRITICAL,
                       engine="sensitive_paths",
                       category=FindingCategory.RECON,
                       finding_type="confirmed_risk",
                       confidence_label="confirmed")]
    score, level, _ = compute_risk_score(_result(groups))
    assert score == 35
    assert level == "high"  # upward guard: real CRITICAL can't read calm


def test_two_confirmed_criticals_reach_critical_level() -> None:
    groups = [
        _grouped(title="Exposed .env", severity=Severity.CRITICAL,
                 engine="sensitive_paths"),
        _grouped(title="Secret key in JS", severity=Severity.CRITICAL,
                 engine="secret_scanner"),
        _grouped(title="Password form over HTTP", severity=Severity.HIGH,
                 engine="form_risk", category=FindingCategory.FORM),
    ]
    score, level, _ = compute_risk_score(_result(groups))
    assert score >= 80
    assert level == "critical"


def test_likely_risk_multiplier_applied() -> None:
    groups = [_grouped(title="Admin portal", severity=Severity.HIGH,
                       finding_type="likely_risk",
                       confidence_label="high")]
    score, _, _ = compute_risk_score(_result(groups))
    assert score == 15  # 20 × 0.75


def test_medium_and_low_confidence_multipliers() -> None:
    med = [_grouped(severity=Severity.HIGH, finding_type="confirmed_risk",
                    confidence_label="medium")]
    low = [_grouped(severity=Severity.HIGH, finding_type="confirmed_risk",
                    confidence_label="low")]
    assert compute_risk_score(_result(med))[0] == 10   # 20 × 0.5
    assert compute_risk_score(_result(low))[0] == 5    # 20 × 0.25


def test_repeated_engine_type_pairs_damped() -> None:
    """Repeated finding classes from one engine count once at full
    weight, then ×0.5."""
    groups = [
        _grouped(title=f"Variant {i}", severity=Severity.MEDIUM,
                 engine="same_engine")
        for i in range(3)
    ]
    score, _, _ = compute_risk_score(_result(groups))
    assert score == 16  # 8 + 4 + 4


def test_hardening_total_capped_at_15() -> None:
    groups = [
        _grouped(title=f"Hardening {i}", severity=Severity.MEDIUM,
                 engine=f"eng{i}", category=FindingCategory.DNS,
                 finding_type="hardening", confidence_label="confirmed")
        for i in range(30)
    ]
    score, level, bd = compute_risk_score(_result(groups))
    assert bd.type_totals["hardening"] == 15.0
    assert score == 15
    assert level == "safe"


def test_hardening_plus_inventory_never_high() -> None:
    """#13-adjacent: a site with ONLY hardening + inventory output can
    never read worse than 'low'."""
    groups = (
        [_grouped(title=f"H{i}", severity=Severity.MEDIUM,
                  engine=f"e{i}", finding_type="hardening")
         for i in range(20)]
        + [_grouped(title=f"I{i}", severity=Severity.INFO,
                    finding_type="inventory") for i in range(20)]
        + [_grouped(title=f"S{i}", severity=Severity.HIGH,
                    engine=f"h{i}", finding_type="heuristic_signal",
                    confidence_label="heuristic") for i in range(10)]
    )
    score, level, _ = compute_risk_score(_result(groups))
    assert score <= 25  # 15 hardening + 10 heuristic
    assert level in ("safe", "low")


def test_wade_findings_excluded_from_score() -> None:
    groups = [
        GroupedFinding(
            title="WADE anomaly", severity=Severity.CRITICAL,
            category=FindingCategory.COMPROMISE, scanner_engine="wade",
            description="d",
            metadata={"finding_type": "confirmed_risk",
                      "confidence_label": "confirmed"},
        ),
        _grouped(title="Real low", severity=Severity.LOW),
    ]
    score, level, _ = compute_risk_score(_result(groups))
    assert score == 2
    assert level == "safe"


def test_unannotated_results_use_legacy_algorithm() -> None:
    """Old persisted results without trust annotations score through
    the byte-compatible legacy path — breakdown is None."""
    r = _result([GroupedFinding(
        title="Old finding", severity=Severity.CRITICAL,
        category=FindingCategory.RECON, scanner_engine="old",
        description="d", confidence=1.0,
    )])
    score, level, bd = compute_risk_score(r)
    assert bd is None
    assert score == 30  # legacy CRITICAL weight
    assert level == "high"
