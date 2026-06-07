# WebHound — tests/test_advisor_explain.py
# Phase-15 Task 1/4: risk explanations + business impact.

from __future__ import annotations

from webhound.advisor.business_impact import (
    ImpactLevel,
    assess_impact,
)
from webhound.advisor.risk_explainer import explain_finding
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
# Risk explanations (Task 1)
# ---------------------------------------------------------------------------


def test_admin_portal_explanation_matches_spec() -> None:
    f = _gf("Exposed Admin panel detected", engine="sensitive_paths",
            category=FindingCategory.RECON)
    e = explain_finding(f)
    assert "administrative" in e.what_happened.lower() \
        or "login" in e.what_happened.lower()
    assert "targeted" in e.why_it_matters.lower()
    assert ("vpn" in e.what_should_be_done.lower()
            or "ip" in e.what_should_be_done.lower()
            or "multi-factor" in e.what_should_be_done.lower())
    # All four parts populated.
    d = e.to_dict()
    for k in ("what_happened", "why_it_matters", "what_could_happen",
              "what_should_be_done"):
        assert d[k]


def test_exposed_secret_explanation_says_rotate() -> None:
    f = _gf("Exposed Environment variable file detected",
            engine="sensitive_paths", category=FindingCategory.RECON,
            severity=Severity.CRITICAL, confidence_label="confirmed")
    e = explain_finding(f)
    assert "rotate" in e.what_should_be_done.lower()


def test_cookie_explanation_distinguishes_session() -> None:
    sess = explain_finding(_gf("Cookie `sessionid` is missing HttpOnly",
                               engine="cookie_scanner",
                               category=FindingCategory.COOKIE))
    assert "hijack" in sess.what_could_happen.lower() \
        or "session" in sess.why_it_matters.lower()


def test_hardening_explanation_is_calm() -> None:
    e = explain_finding(_gf("Missing Content-Security-Policy",
                            engine="security_headers",
                            category=FindingCategory.SECURITY_HEADER,
                            finding_type="hardening"))
    assert "hardening" in e.why_it_matters.lower()
    assert "not an active vulnerability" in e.why_it_matters.lower()


def test_inventory_explanation_no_risk_language() -> None:
    e = explain_finding(_gf("API surface mapped", engine="endpoint_discovery",
                           category=FindingCategory.API,
                           severity=Severity.INFO, finding_type="inventory"))
    assert "not a security problem" in e.why_it_matters.lower()


def test_compromise_explanation_urges_investigation() -> None:
    e = explain_finding(_gf("Hidden iframe detected", engine="hidden_iframes",
                           category=FindingCategory.COMPROMISE,
                           severity=Severity.HIGH))
    assert "tampering" in e.why_it_matters.lower() \
        or "compromise" in e.what_could_happen.lower()
    assert "investigate" in e.what_should_be_done.lower()


# ---------------------------------------------------------------------------
# Business impact (Task 4)
# ---------------------------------------------------------------------------


def test_payment_form_impacts_payment_and_revenue() -> None:
    f = _gf("Payment form posts to a different domain", engine="form_risk",
            category=FindingCategory.FORM, severity=Severity.CRITICAL)
    imp = assess_impact(f)
    assert imp.dimensions["payment_risk"] == ImpactLevel.HIGH
    assert imp.dimensions["revenue"].rank >= ImpactLevel.MEDIUM.rank
    assert imp.primary == "payment_risk"


def test_exposed_secret_impacts_data_exposure() -> None:
    f = _gf("Exposed Environment variable file detected",
            engine="sensitive_paths", category=FindingCategory.RECON,
            severity=Severity.CRITICAL)
    imp = assess_impact(f)
    assert imp.dimensions["data_exposure_risk"] == ImpactLevel.HIGH


def test_admin_impacts_authentication() -> None:
    f = _gf("Exposed Admin panel detected", engine="sensitive_paths",
            category=FindingCategory.RECON)
    imp = assess_impact(f)
    assert imp.dimensions["authentication_risk"].rank >= ImpactLevel.HIGH.rank


def test_inventory_no_business_impact() -> None:
    f = _gf("API surface mapped", engine="endpoint_discovery",
            category=FindingCategory.API, severity=Severity.INFO,
            finding_type="inventory")
    imp = assess_impact(f)
    assert imp.max_level == ImpactLevel.NONE
    assert "no direct business impact" in imp.summary.lower()


def test_impact_summary_human_readable() -> None:
    f = _gf("Checkout payment form over HTTP", engine="form_risk",
            category=FindingCategory.FORM, severity=Severity.CRITICAL)
    imp = assess_impact(f)
    assert "payment security" in imp.summary.lower()
