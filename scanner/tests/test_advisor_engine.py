# WebHound — tests/test_advisor_engine.py
# Phase-15 Task 6/8: remediation roadmap + top-level advisory + Q&A.

from __future__ import annotations

from webhound.advisor import (
    build_advisory,
    build_remediation_roadmap,
)
from webhound.models.finding import FindingCategory
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.scan_result import ScanResult
from webhound.models.severity import Severity
from webhound.models.target import Target


def _gf(title, *, engine="e", category=FindingCategory.UNKNOWN,
        severity=Severity.MEDIUM, finding_type="likely_risk",
        confidence_label="high") -> GroupedFinding:
    return GroupedFinding(
        title=title, severity=severity, category=category,
        scanner_engine=engine, description="d",
        metadata={"finding_type": finding_type,
                  "confidence_label": confidence_label})


def _result(groups, **meta) -> ScanResult:
    r = ScanResult(target=Target.from_url("https://t.test/"))
    r.grouped_findings = list(groups)
    r.metadata.update(meta)
    return r


# ---------------------------------------------------------------------------
# Remediation roadmap (Task 8)
# ---------------------------------------------------------------------------


def test_roadmap_consolidates_and_orders() -> None:
    findings = [
        _gf("Missing CSP", engine="security_headers",
            category=FindingCategory.SECURITY_HEADER, severity=Severity.MEDIUM,
            finding_type="hardening"),
        _gf("Missing Permissions-Policy", engine="security_headers",
            category=FindingCategory.SECURITY_HEADER, severity=Severity.LOW,
            finding_type="hardening"),
        _gf("Exposed Admin panel detected", engine="sensitive_paths",
            category=FindingCategory.RECON, severity=Severity.MEDIUM),
        _gf("Untrusted third-party script", engine="third_party_domains",
            category=FindingCategory.JAVASCRIPT, severity=Severity.MEDIUM),
    ]
    roadmap = build_remediation_roadmap(findings)
    titles = [s.title for s in roadmap]
    # Two header findings collapse into ONE step.
    header_steps = [s for s in roadmap if "header" in s.title.lower()]
    assert len(header_steps) == 1
    assert header_steps[0].finding_count == 2
    # Admin access ordered before headers + third-party.
    assert titles.index("Restrict administrative access") < \
        titles.index("Improve browser security headers")
    # Steps are numbered 1..n.
    assert [s.step for s in roadmap] == list(range(1, len(roadmap) + 1))


def test_roadmap_secrets_first() -> None:
    findings = [
        _gf("Missing CSP", engine="security_headers",
            category=FindingCategory.SECURITY_HEADER, finding_type="hardening"),
        _gf("Exposed Environment variable file detected",
            engine="sensitive_paths", category=FindingCategory.RECON,
            severity=Severity.CRITICAL, finding_type="confirmed_risk"),
    ]
    roadmap = build_remediation_roadmap(findings)
    assert roadmap[0].title.startswith("Remove exposed secrets")


# ---------------------------------------------------------------------------
# Top-level advisory + Q&A (Task 6)
# ---------------------------------------------------------------------------


def test_advisory_full_shape() -> None:
    result = _result([
        _gf("Exposed Environment variable file detected",
            engine="sensitive_paths", category=FindingCategory.RECON,
            severity=Severity.CRITICAL, finding_type="confirmed_risk",
            confidence_label="confirmed"),
        _gf("Missing CSP", engine="security_headers",
            category=FindingCategory.SECURITY_HEADER, severity=Severity.MEDIUM,
            finding_type="hardening"),
    ], risk_level="high")
    adv = build_advisory(result).to_dict()
    assert adv["findings"]
    assert adv["priorities"]
    assert adv["action_plan"]["counts"]["fix_now"] == 1
    assert adv["remediation_roadmap"]
    # Every finding has the four-part explanation + impact + action.
    for fa in adv["findings"]:
        assert fa["explanation"]["what_should_be_done"]
        assert "dimensions" in fa["business_impact"]


def test_qa_what_to_fix_first() -> None:
    result = _result([
        _gf("Exposed Admin panel detected", engine="sensitive_paths",
            category=FindingCategory.RECON, severity=Severity.CRITICAL,
            finding_type="confirmed_risk")], risk_level="high")
    adv = build_advisory(result).to_dict()
    assert "Admin" in adv["qa"]["what_should_i_fix_first"]


def test_qa_hacked_no_indicators() -> None:
    result = _result([
        _gf("Missing CSP", engine="security_headers",
            category=FindingCategory.SECURITY_HEADER, finding_type="hardening")],
        risk_level="low")
    adv = build_advisory(result).to_dict()
    assert "no compromise indicators" in \
        adv["qa"]["did_my_website_get_hacked"].lower()


def test_qa_hacked_with_compromise_story() -> None:
    result = _result(
        [_gf("Hidden iframe detected", engine="hidden_iframes",
             category=FindingCategory.COMPROMISE, severity=Severity.HIGH)],
        risk_level="high",
        security_stories=[{"correlation_type": "possible_compromise"}])
    adv = build_advisory(result).to_dict()
    assert "investigation" in adv["qa"]["did_my_website_get_hacked"].lower()


def test_advisory_trend_from_risk_delta() -> None:
    result = _result([_gf("x", severity=Severity.MEDIUM)], risk_level="medium")
    adv = build_advisory(result, risk_delta={
        "direction": "increased", "score_change": 20,
        "reasons": ["+1 confirmed risks"], "previous_level": "low",
        "current_level": "medium"}).to_dict()
    assert adv["trend"]["is_alarming"] is True
    assert "increased" in adv["qa"]["why_did_my_score_change"].lower()


def test_advisory_empty_scan_safe() -> None:
    adv = build_advisory(_result([], risk_level="safe")).to_dict()
    assert adv["findings"] == []
    assert "good shape" in adv["qa"]["is_this_serious"].lower()
