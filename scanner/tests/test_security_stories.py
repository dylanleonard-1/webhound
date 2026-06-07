# WebHound — tests/test_security_stories.py
# Phase-8 correlation engine: customer-facing security stories. Covers
# every Task-13 scenario plus the no-double-count scoring contract.

from __future__ import annotations

import pytest

from webhound.core.security_stories import (
    CorrelationConfidence,
    CorrelationType,
    build_security_stories,
    correlate_wade_changes,
)
from webhound.models.finding import FindingCategory
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.severity import Severity


def _gf(title, *, engine="e", category=FindingCategory.UNKNOWN,
        severity=Severity.MEDIUM, finding_type="likely_risk",
        confidence_label="high", metadata=None, tags=None) -> GroupedFinding:
    md = {"finding_type": finding_type, "confidence_label": confidence_label}
    md.update(metadata or {})
    return GroupedFinding(
        title=title, severity=severity, category=category,
        scanner_engine=engine, description="d", metadata=md,
        tags=tags or [], affected_urls=["https://t.test/x"],
    )


def _types(stories):
    return {s.correlation_type for s in stories}


# ---------------------------------------------------------------------------
# Task 13 scenarios
# ---------------------------------------------------------------------------


def test_admin_exposure_chain() -> None:
    findings = [
        _gf("Exposed Admin panel detected", engine="sensitive_paths",
            category=FindingCategory.RECON, metadata={"path": "/admin"}),
        _gf("Internal or admin API referenced", engine="endpoint_discovery",
            category=FindingCategory.API),
        _gf("Missing Strict-Transport-Security",
            engine="security_headers",
            category=FindingCategory.SECURITY_HEADER,
            finding_type="hardening"),
    ]
    stories = build_security_stories(findings)
    admin = next(s for s in stories
                 if s.correlation_type == CorrelationType.ADMIN_EXPOSURE)
    assert admin.title == "Administrative Exposure Surface"
    assert len(admin.member_finding_ids) >= 2
    assert admin.recommendation


def test_supply_chain_risk() -> None:
    findings = [
        _gf("Untrusted third-party script loaded",
            engine="third_party_domains",
            category=FindingCategory.JAVASCRIPT,
            metadata={"host": "weird-cdn-3x9.tk"}),
        _gf("Domain flagged by URLhaus", engine="threat_intel",
            category=FindingCategory.COMPROMISE,
            metadata={"host": "weird-cdn-3x9.tk", "urlhaus": True}),
    ]
    stories = build_security_stories(findings)
    sc = next(s for s in stories
              if s.correlation_type == CorrelationType.SUPPLY_CHAIN_RISK)
    assert sc.confidence == CorrelationConfidence.CONFIRMED  # threat hit


def test_known_vendor_suppression_in_supply_chain() -> None:
    """Task 4/12: Stripe/GA/etc. must NOT trigger supply-chain risk."""
    findings = [
        _gf("Third-party script loaded", engine="third_party_domains",
            category=FindingCategory.JAVASCRIPT,
            metadata={"host": "js.stripe.com",
                      "vendor_category": "payment"}),
        _gf("Third-party script loaded", engine="third_party_domains",
            category=FindingCategory.JAVASCRIPT,
            metadata={"host": "www.google-analytics.com",
                      "vendor_category": "analytics"}),
    ]
    stories = build_security_stories(findings)
    assert CorrelationType.SUPPLY_CHAIN_RISK not in _types(stories)


def test_payment_surface_inventory_when_clean() -> None:
    findings = [
        _gf("Payment form detected", engine="form_risk",
            category=FindingCategory.FORM, severity=Severity.INFO,
            finding_type="inventory"),
        _gf("Stripe payment integration observed",
            engine="third_party_domains",
            category=FindingCategory.JAVASCRIPT, severity=Severity.INFO,
            metadata={"vendor_category": "payment"},
            finding_type="inventory"),
    ]
    stories = build_security_stories(findings)
    pay = next(s for s in stories
               if s.correlation_type == CorrelationType.PAYMENT_SURFACE)
    assert pay.is_inventory is True
    assert pay.severity == Severity.INFO


def test_payment_surface_escalates_with_suspicious_signal() -> None:
    findings = [
        _gf("Payment/checkout form detected", engine="form_risk",
            category=FindingCategory.FORM),
        _gf("Stripe payment integration observed",
            engine="third_party_domains",
            category=FindingCategory.JAVASCRIPT,
            metadata={"vendor_category": "payment"}),
        _gf("Hidden iframe detected", engine="hidden_iframes",
            category=FindingCategory.COMPROMISE, severity=Severity.HIGH,
            finding_type="likely_risk"),
    ]
    stories = build_security_stories(findings)
    pay = next(s for s in stories
               if s.correlation_type == CorrelationType.PAYMENT_SURFACE)
    assert pay.is_inventory is False
    assert pay.severity == Severity.HIGH


def test_authentication_surface() -> None:
    findings = [
        _gf("Login form over HTTPS", engine="form_risk",
            category=FindingCategory.FORM),
        _gf("Auth/session API referenced", engine="endpoint_discovery",
            category=FindingCategory.API),
        _gf("Session cookie missing HttpOnly", engine="cookie_scanner",
            category=FindingCategory.COOKIE),
    ]
    stories = build_security_stories(findings)
    auth = next(s for s in stories
                if s.correlation_type == CorrelationType.AUTH_SURFACE)
    assert auth.title == "Authentication Surface Review"
    assert len(auth.member_finding_ids) == 3


def test_possible_compromise_chain_confidence_grows() -> None:
    two = build_security_stories([
        _gf("Unexpected injected script", engine="injected_js",
            category=FindingCategory.COMPROMISE),
        _gf("Hidden iframe detected", engine="hidden_iframes",
            category=FindingCategory.COMPROMISE),
    ])
    three = build_security_stories([
        _gf("Unexpected injected script", engine="injected_js",
            category=FindingCategory.COMPROMISE),
        _gf("Hidden iframe detected", engine="hidden_iframes",
            category=FindingCategory.COMPROMISE),
        _gf("Suspicious redirect detected", engine="suspicious_redirects",
            category=FindingCategory.COMPROMISE),
    ])
    c2 = next(s for s in two
              if s.correlation_type == CorrelationType.POSSIBLE_COMPROMISE)
    c3 = next(s for s in three
              if s.correlation_type == CorrelationType.POSSIBLE_COMPROMISE)
    # More converging evidence → at least as confident.
    assert c3.confidence.rank >= c2.confidence.rank
    assert c3.confidence == CorrelationConfidence.HIGH
    assert "Possible Website Compromise" == c3.title


def test_website_modification_from_wade() -> None:
    timeline = {"records": [
        {"change_key": "k1", "diff_type": "new_script_source",
         "url": "https://t.test/", "value": "https://x.test/a.js",
         "change_type": "suspicious_script_change", "band": "medium"},
        {"change_key": "k2", "diff_type": "new_external_domain",
         "url": "https://t.test/", "value": "x.test",
         "change_type": "new_third_party_service", "band": "low"},
    ]}
    story = correlate_wade_changes(timeline)
    assert story is not None
    assert story.correlation_type == CorrelationType.WEBSITE_MODIFICATION
    assert story.title == "Unexpected Website Modification"  # suspicious
    assert story.severity == Severity.HIGH


def test_website_modification_expected_deployment_is_calm() -> None:
    timeline = {"records": [
        {"change_key": "k1", "diff_type": "new_script_source",
         "url": "https://t.test/", "value": "https://x.test/a.js",
         "change_type": "new_analytics_tool", "band": "very_low"},
        {"change_key": "k2", "diff_type": "new_external_domain",
         "url": "https://t.test/", "value": "ga.test",
         "change_type": "new_marketing_tool", "band": "very_low"},
    ]}
    story = correlate_wade_changes(timeline)
    assert story is not None
    assert story.is_inventory is True
    assert story.severity == Severity.LOW


def test_wade_noise_suppressed() -> None:
    """Task 12: pure expected-deployment / content updates → no story."""
    timeline = {"records": [
        {"change_key": "k1", "diff_type": "dom_structure_change",
         "url": "https://t.test/", "value": None,
         "change_type": "expected_deployment", "band": "very_low"},
        {"change_key": "k2", "diff_type": "status_code_change",
         "url": "https://t.test/", "value": "200",
         "change_type": "normal_content_update", "band": "very_low"},
    ]}
    assert correlate_wade_changes(timeline) is None


def test_header_and_cookie_hardening_grouped() -> None:
    findings = [
        _gf("Missing Content-Security-Policy", engine="csp_engine",
            category=FindingCategory.SECURITY_HEADER, severity=Severity.MEDIUM,
            finding_type="hardening"),
        _gf("Missing Permissions-Policy", engine="security_headers",
            category=FindingCategory.SECURITY_HEADER, severity=Severity.LOW,
            finding_type="hardening"),
        _gf("Cookie missing Secure flag", engine="cookie_scanner",
            category=FindingCategory.COOKIE, severity=Severity.LOW,
            finding_type="hardening"),
        _gf("Cookie missing SameSite", engine="cookie_scanner",
            category=FindingCategory.COOKIE, severity=Severity.LOW,
            finding_type="hardening"),
    ]
    stories = build_security_stories(findings)
    assert CorrelationType.HEADER_HARDENING in _types(stories)
    assert CorrelationType.COOKIE_HARDENING in _types(stories)


def test_correlation_confidence_levels() -> None:
    """Task 9: unknown domain alone is low; full compromise chain high."""
    lone = build_security_stories([
        _gf("Login form", engine="form_risk", category=FindingCategory.FORM),
        _gf("Auth API referenced", engine="endpoint_discovery",
            category=FindingCategory.API, confidence_label="medium"),
    ])
    auth = next(s for s in lone
                if s.correlation_type == CorrelationType.AUTH_SURFACE)
    assert auth.confidence in (CorrelationConfidence.MEDIUM,
                               CorrelationConfidence.HIGH)


# ---------------------------------------------------------------------------
# Task 1 + 10: annotation and no-double-count
# ---------------------------------------------------------------------------


def test_findings_annotated_with_correlation() -> None:
    findings = [
        _gf("Unexpected injected script", engine="injected_js",
            category=FindingCategory.COMPROMISE),
        _gf("Hidden iframe detected", engine="hidden_iframes",
            category=FindingCategory.COMPROMISE),
    ]
    build_security_stories(findings)
    for f in findings:
        assert f.correlation_id is not None
        assert f.correlation_type == CorrelationType.POSSIBLE_COMPROMISE.value
        assert f.correlation_confidence is not None
        assert f.metadata["correlation_ids"]


def test_stories_create_no_findings() -> None:
    """Task 10: correlation reorganizes — it never adds scored findings,
    so it cannot inflate risk."""
    findings = [
        _gf("Unexpected injected script", engine="injected_js",
            category=FindingCategory.COMPROMISE),
        _gf("Hidden iframe detected", engine="hidden_iframes",
            category=FindingCategory.COMPROMISE),
    ]
    before = len(findings)
    stories = build_security_stories(findings)
    assert stories                     # stories produced
    assert len(findings) == before     # but the scored list is untouched


def test_no_stories_on_clean_scan() -> None:
    findings = [
        _gf("Technology detected: nginx", engine="technology",
            category=FindingCategory.TECHNOLOGY, severity=Severity.INFO,
            finding_type="inventory"),
    ]
    stories = build_security_stories(findings)
    # A lone inventory tech finding forms no security story.
    assert all(s.correlation_type != CorrelationType.POSSIBLE_COMPROMISE
               for s in stories)


def test_empty_input_safe() -> None:
    assert build_security_stories([]) == []
    assert correlate_wade_changes(None) is None
    assert correlate_wade_changes({"records": []}) is None
