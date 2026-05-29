# WebHound — scanner/tests/test_evidence_quality.py
# Phase-5D evidence quality audit tests.

from __future__ import annotations

import pytest

from webhound.core.evidence_quality import (
    EvidenceQualityReport,
    audit_findings,
)
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import (
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.severity import Severity


def _good(**kw) -> Finding:
    base = dict(
        title="Missing Content-Security-Policy header",
        description=(
            "The page does not set a Content-Security-Policy header. "
            "Browsers will execute any inline or third-party script "
            "without restriction."
        ),
        severity=Severity.HIGH,
        category=FindingCategory.SECURITY_HEADER,
        confidence=0.9,
        scanner_engine="security_headers",
        severity_rationale=(
            "Missing CSP allows arbitrary inline + third-party scripts."
        ),
        confidence_rationale=(
            "Direct header inspection — no header found."
        ),
        evidence=[Evidence(
            evidence_type=EvidenceType.HEADER, content="missing",
            location="https://target.test/",
            source_engine="security_headers",
        )],
    )
    base.update(kw)
    return Finding(**base)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_clean_finding_is_complete() -> None:
    r = audit_findings([_good()])
    assert r.completeness_ratio == 1.0
    assert r.has_gaps is False


# ---------------------------------------------------------------------------
# Each violation kind flagged
# ---------------------------------------------------------------------------


def test_missing_evidence_flagged() -> None:
    f = _good(evidence=[])
    issue = audit_findings([f]).incomplete_findings[0]
    assert "evidence" in issue.missing_fields


def test_empty_evidence_location_flagged() -> None:
    f = _good(evidence=[Evidence(
        evidence_type=EvidenceType.HEADER, content="x",
        location="", source_engine="security_headers",
    )])
    issue = audit_findings([f]).incomplete_findings[0]
    assert "evidence_location" in issue.missing_fields


def test_short_description_flagged() -> None:
    f = _good(description="Missing CSP")
    issue = audit_findings([f]).incomplete_findings[0]
    assert "description" in issue.missing_fields


def test_missing_severity_rationale_flagged() -> None:
    f = _good(severity_rationale=None)
    issue = audit_findings([f]).incomplete_findings[0]
    assert "severity_rationale" in issue.missing_fields


def test_missing_confidence_rationale_flagged() -> None:
    f = _good(confidence_rationale=None)
    issue = audit_findings([f]).incomplete_findings[0]
    assert "confidence_rationale" in issue.missing_fields


def test_info_findings_dont_require_rationales() -> None:
    """INFO findings are informational — they don't need to justify
    severity or confidence."""
    f = _good(
        severity=Severity.INFO,
        severity_rationale=None,
        confidence_rationale=None,
    )
    r = audit_findings([f])
    assert r.has_gaps is False


# ---------------------------------------------------------------------------
# Suppression / false-positive skip
# ---------------------------------------------------------------------------


def test_suppressed_finding_excluded_from_audit() -> None:
    f = _good(severity_rationale=None, suppressed=True)
    r = audit_findings([f])
    assert r.total_findings == 0
    assert r.has_gaps is False


def test_false_positive_finding_excluded() -> None:
    f = _good(severity_rationale=None, false_positive=True)
    r = audit_findings([f])
    assert r.total_findings == 0


# ---------------------------------------------------------------------------
# Per-engine histogram
# ---------------------------------------------------------------------------


def test_per_engine_incomplete_histogram() -> None:
    good = _good()
    bad1 = _good(severity_rationale=None, scanner_engine="cookies")
    bad2 = _good(severity_rationale=None, scanner_engine="cookies")
    bad3 = _good(severity_rationale=None, scanner_engine="cors")
    r = audit_findings([good, bad1, bad2, bad3])
    assert r.per_engine_incomplete_count["cookies"] == 2
    assert r.per_engine_incomplete_count["cors"] == 1
    assert "security_headers" not in r.per_engine_incomplete_count


def test_to_dict_keys() -> None:
    r = audit_findings([_good()])
    d = r.to_dict()
    for k in ("total_findings", "complete_findings",
               "completeness_ratio", "has_gaps", "incomplete_count",
               "incomplete_findings", "per_engine_incomplete_count"):
        assert k in d
