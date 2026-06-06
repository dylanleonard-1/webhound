# WebHound — tests/test_finding_presenter.py
# Phase-7 Tasks 7-8: calm customer-facing wording + report sections.

from __future__ import annotations

from webhound.core.finding_presenter import (
    SEVERITY_ACTIONS,
    build_report_sections,
    present,
    section_of,
)
from webhound.models.finding import FindingCategory
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.severity import Severity


def _gf(title="Issue", severity=Severity.MEDIUM, engine="e",
        finding_type="likely_risk", confidence_label="high",
        category=FindingCategory.JAVASCRIPT) -> GroupedFinding:
    return GroupedFinding(
        title=title, severity=severity, category=category,
        scanner_engine=engine, description="d",
        metadata={"finding_type": finding_type,
                  "confidence_label": confidence_label},
    )


def test_severity_action_wording() -> None:
    assert SEVERITY_ACTIONS["critical"] == "Fix immediately"
    assert SEVERITY_ACTIONS["high"] == "Fix soon"
    assert SEVERITY_ACTIONS["medium"] == "Review and schedule"
    assert SEVERITY_ACTIONS["low"] == "Hardening improvement"
    assert SEVERITY_ACTIONS["info"] == "Discovered asset"


def test_present_uses_calm_language() -> None:
    p = present(_gf(finding_type="heuristic_signal",
                    confidence_label="heuristic"))
    assert "not a confirmed issue" in p["headline"]
    banned = ("compromised", "easily hack", "hacked")
    assert not any(b in p["headline"].lower() for b in banned)


def test_inventory_headline_is_not_scary() -> None:
    p = present(_gf(severity=Severity.INFO, finding_type="inventory",
                    confidence_label="confirmed"))
    assert "not a security problem" in p["headline"]
    assert p["action"] == "Discovered asset"


def test_sections_route_by_type_and_engine() -> None:
    assert section_of(_gf(finding_type="confirmed_risk")) == \
        "security_risks"
    assert section_of(_gf(finding_type="heuristic_signal")) == \
        "security_risks"
    assert section_of(_gf(finding_type="hardening")) == \
        "hardening_recommendations"
    assert section_of(_gf(finding_type="inventory")) == "inventory"
    assert section_of(_gf(engine="wade", finding_type="likely_risk")) == \
        "wade_changes"


def test_build_report_sections_separates_and_counts() -> None:
    """Task-9 #13: the customer-facing summary separates risk /
    hardening / inventory."""
    grouped = [
        _gf(title="Exposed secret", severity=Severity.CRITICAL,
            finding_type="confirmed_risk", confidence_label="confirmed"),
        _gf(title="Missing CSP", severity=Severity.MEDIUM,
            finding_type="hardening",
            category=FindingCategory.SECURITY_HEADER),
        _gf(title="API surface mapped", severity=Severity.INFO,
            finding_type="inventory"),
        _gf(title="New script", severity=Severity.MEDIUM, engine="wade",
            finding_type="likely_risk"),
    ]
    sections = build_report_sections(grouped)
    assert sections["counts"] == {
        "security_risks": 1,
        "hardening_recommendations": 1,
        "inventory": 1,
        "wade_changes": 1,
    }
    assert sections["security_risks"][0]["title"] == "Exposed secret"
    assert sections["security_risks"][0]["action"] == "Fix immediately"
    assert sections["hardening_recommendations"][0]["title"] == \
        "Missing CSP"
    assert sections["inventory"][0]["title"] == "API surface mapped"
    assert sections["wade_changes"][0]["title"] == "New script"


def test_sections_sorted_by_severity() -> None:
    grouped = [
        _gf(title="low", severity=Severity.LOW),
        _gf(title="crit", severity=Severity.CRITICAL),
        _gf(title="med", severity=Severity.MEDIUM),
    ]
    sections = build_report_sections(grouped)
    titles = [e["title"] for e in sections["security_risks"]]
    assert titles == ["crit", "med", "low"]
