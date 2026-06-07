# WebHound — tests/test_advisor_priority.py
# Phase-15 Task 2/3/5/7: priority, action plan, change + trend explainers.

from __future__ import annotations

from webhound.advisor.action_plan import (
    ActionBucket,
    Effort,
    build_action_plan,
)
from webhound.advisor.change_explainer import (
    explain_change,
    explain_recurring,
    explain_trend,
)
from webhound.advisor.priority_explainer import explain_priorities
from webhound.models.finding import FindingCategory
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.severity import Severity


def _gf(title, *, engine="e", category=FindingCategory.UNKNOWN,
        severity=Severity.MEDIUM, finding_type="likely_risk",
        confidence_label="high") -> GroupedFinding:
    return GroupedFinding(
        title=title, severity=severity, category=category,
        scanner_engine=engine, description="d",
        metadata={"finding_type": finding_type,
                  "confidence_label": confidence_label})


# ---------------------------------------------------------------------------
# Priority (Task 3)
# ---------------------------------------------------------------------------


def test_priority_ranks_by_contribution() -> None:
    findings = [
        _gf("Missing CSP", engine="security_headers",
            category=FindingCategory.SECURITY_HEADER, severity=Severity.MEDIUM,
            finding_type="hardening"),
        _gf("Exposed .env", engine="sensitive_paths",
            category=FindingCategory.RECON, severity=Severity.CRITICAL,
            finding_type="confirmed_risk", confidence_label="confirmed"),
    ]
    prio = explain_priorities(findings)
    assert prio[0].rank == 1
    assert "Exposed .env" not in prio[0].explanation  # title not required
    assert prio[0].risk_share_pct > prio[1].risk_share_pct
    assert "top priority" in prio[0].explanation.lower()
    assert "%" in prio[0].explanation


def test_priority_explains_affected_surface() -> None:
    findings = [_gf("Password form posts credentials to a different domain",
                    engine="form_risk", category=FindingCategory.FORM,
                    severity=Severity.CRITICAL)]
    prio = explain_priorities(findings)
    assert "payment" in prio[0].affected_surface.lower() \
        or "authentication" in prio[0].affected_surface.lower() \
        or "site" in prio[0].affected_surface.lower()


def test_priority_excludes_inventory() -> None:
    findings = [
        _gf("API surface mapped", engine="endpoint_discovery",
            category=FindingCategory.API, severity=Severity.INFO,
            finding_type="inventory"),
        _gf("Exposed admin", engine="sensitive_paths",
            category=FindingCategory.RECON, severity=Severity.MEDIUM),
    ]
    prio = explain_priorities(findings)
    assert len(prio) == 1                  # inventory excluded


# ---------------------------------------------------------------------------
# Action plan (Task 5)
# ---------------------------------------------------------------------------


def test_critical_is_fix_now() -> None:
    plan = build_action_plan([
        _gf("Exposed .env", engine="sensitive_paths",
            category=FindingCategory.RECON, severity=Severity.CRITICAL,
            finding_type="confirmed_risk")])
    assert plan.items[0].bucket == ActionBucket.FIX_NOW
    assert plan.items[0].risk_reduction == "high"


def test_header_is_low_effort_fix_soon_or_monitor() -> None:
    plan = build_action_plan([
        _gf("Missing CSP", engine="security_headers",
            category=FindingCategory.SECURITY_HEADER, severity=Severity.MEDIUM,
            finding_type="hardening")])
    assert plan.items[0].effort == Effort.LOW


def test_inventory_is_informational() -> None:
    plan = build_action_plan([
        _gf("Technology detected", engine="technology",
            category=FindingCategory.TECHNOLOGY, severity=Severity.INFO,
            finding_type="inventory")])
    assert plan.items[0].bucket == ActionBucket.INFORMATIONAL


def test_action_plan_buckets_and_counts() -> None:
    plan = build_action_plan([
        _gf("Exposed .env", engine="sensitive_paths",
            category=FindingCategory.RECON, severity=Severity.CRITICAL,
            finding_type="confirmed_risk"),
        _gf("Missing CSP", engine="security_headers",
            category=FindingCategory.SECURITY_HEADER, severity=Severity.LOW,
            finding_type="hardening"),
        _gf("API mapped", engine="endpoint_discovery",
            category=FindingCategory.API, severity=Severity.INFO,
            finding_type="inventory"),
    ])
    d = plan.to_dict()
    assert d["counts"]["fix_now"] == 1
    assert d["counts"]["informational"] == 1
    # Fix Now ordered first.
    assert plan.items[0].bucket == ActionBucket.FIX_NOW


# ---------------------------------------------------------------------------
# Change + trend explanations (Task 2/7)
# ---------------------------------------------------------------------------


def test_new_script_on_checkout_explained() -> None:
    e = explain_change({
        "asset": "script", "category": "vendor_change",
        "direction": "increased", "url": "https://t.test/checkout",
        "confidence": "high", "tier": "review"})
    assert "checkout" in e.headline.lower()
    assert "third-party script" in e.headline.lower()
    assert e.confidence == "high"


def test_suspicious_change_is_alarming() -> None:
    e = explain_change({
        "asset": "iframe", "category": "possible_compromise",
        "direction": "increased", "tier": "warning", "confidence": "high"})
    assert e.is_alarming is True
    assert "tampering" in e.detail.lower()


def test_trend_increase_explained() -> None:
    e = explain_trend({
        "direction": "increased", "score_change": 30,
        "reasons": ["+2 confirmed risks"], "previous_level": "low",
        "current_level": "medium"})
    assert "increased" in e.headline.lower()
    assert "confirmed risks" in e.detail.lower()
    assert e.is_alarming is True


def test_trend_stable_is_calm() -> None:
    e = explain_trend({"direction": "unchanged", "score_change": 0,
                       "reasons": [], "previous_level": "low",
                       "current_level": "low"})
    assert "stable" in e.headline.lower()
    assert e.is_alarming is False


def test_recurring_note() -> None:
    note = explain_recurring({"occurrences": 3, "title": "GA added"})
    assert "3 scans" in note
    assert explain_recurring({"occurrences": 1, "title": "x"}) == ""
