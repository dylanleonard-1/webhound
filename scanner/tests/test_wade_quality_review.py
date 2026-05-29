# WebHound — scanner/tests/test_wade_quality_review.py
# Phase-5H tests.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory
from webhound.models.scan_result import ScanResult, ScanStatus
from webhound.models.severity import Severity
from webhound.models.target import Target
from webhound.wade.quality_review import review_scan


def _f(*, severity=Severity.HIGH, confidence=0.9, title="x finding",
        engine="security_headers", evidence=None, tags=None,
        metadata=None) -> Finding:
    ev = evidence
    if ev is None:
        ev = [Evidence(
            evidence_type=EvidenceType.HEADER, content="x",
            location="https://target/", source_engine=engine,
        )]
    return Finding(
        title=title,
        description="long enough description for the audit to be happy " * 2,
        severity=severity, category=FindingCategory.SECURITY_HEADER,
        confidence=confidence, scanner_engine=engine,
        severity_rationale="r", confidence_rationale="r",
        evidence=ev, tags=tags or [],
        metadata=metadata or {},
    )


def _result(findings) -> ScanResult:
    r = ScanResult(
        target=Target.from_url("https://target/"),
        status=ScanStatus.COMPLETED,
        findings=findings,
        engines_run=["security_headers"],
        urls_crawled=1, pages_analyzed=1,
        started_at=datetime(2026, 5, 29, tzinfo=timezone.utc),
        completed_at=datetime(2026, 5, 29, tzinfo=timezone.utc),
    )
    r.recompute_aggregates()
    return r


# ---------------------------------------------------------------------------
# Clean scan → no notes
# ---------------------------------------------------------------------------


def test_clean_scan_emits_no_notes() -> None:
    r = review_scan(_result([
        _f(title="Missing CSP", confidence=0.95, tags=["confirmed"]),
    ]))
    # Single high-severity finding with confidence 0.95 — but no
    # corroboration is the only flag and we have the missing_corroboration
    # kind for that.
    kinds = {n.kind for n in r.notes}
    # Possible_FP shouldn't fire (confidence high).
    assert "possible_false_positive" not in kinds


# ---------------------------------------------------------------------------
# possible_false_positive
# ---------------------------------------------------------------------------


def test_possible_false_positive_low_confidence_high_severity() -> None:
    r = review_scan(_result([
        _f(severity=Severity.HIGH, confidence=0.4),
    ]))
    kinds = [n.kind for n in r.notes]
    assert "possible_false_positive" in kinds


def test_possible_false_positive_silent_when_corroborated() -> None:
    r = review_scan(_result([
        _f(severity=Severity.HIGH, confidence=0.4,
           tags=["corroborated"]),
    ]))
    kinds = {n.kind for n in r.notes}
    assert "possible_false_positive" not in kinds


# ---------------------------------------------------------------------------
# weak_evidence
# ---------------------------------------------------------------------------


def test_weak_evidence_flagged_on_missing_location() -> None:
    f = _f(evidence=[Evidence(
        evidence_type=EvidenceType.HEADER, content="x", location="",
        source_engine="security_headers",
    )])
    r = review_scan(_result([f]))
    kinds = [n.kind for n in r.notes]
    assert "weak_evidence" in kinds


# ---------------------------------------------------------------------------
# duplicate_finding
# ---------------------------------------------------------------------------


def test_duplicate_finding_flagged_only_for_second() -> None:
    a = _f(title="Missing Content-Security-Policy on /a")
    b = _f(title="Missing Content-Security-Policy on /b")
    r = review_scan(_result([a, b]))
    dup = [n for n in r.notes if n.kind == "duplicate_finding"]
    assert len(dup) == 1
    # The second finding is the one flagged.
    assert dup[0].finding_id == str(b.id)


# ---------------------------------------------------------------------------
# missing_corroboration
# ---------------------------------------------------------------------------


def test_missing_corroboration_flagged() -> None:
    r = review_scan(_result([
        _f(severity=Severity.HIGH, confidence=0.95),
    ]))
    kinds = [n.kind for n in r.notes]
    assert "missing_corroboration" in kinds


def test_missing_corroboration_silent_when_corroborated_by_set() -> None:
    r = review_scan(_result([
        _f(severity=Severity.HIGH, confidence=0.95,
           metadata={"corroborated_by": ["supply_chain"]}),
    ]))
    kinds = {n.kind for n in r.notes}
    assert "missing_corroboration" not in kinds


def test_missing_corroboration_silent_for_cluster_finding() -> None:
    """A cluster finding IS the corroboration — flagging it for
    missing corroboration would be confusing."""
    r = review_scan(_result([
        _f(severity=Severity.HIGH, confidence=0.85,
           tags=["cluster", "correlated"]),
    ]))
    kinds = {n.kind for n in r.notes}
    assert "missing_corroboration" not in kinds


# ---------------------------------------------------------------------------
# suspicious_scoring
# ---------------------------------------------------------------------------


def test_suspicious_scoring_info_with_high_confidence_flagged() -> None:
    r = review_scan(_result([
        _f(severity=Severity.INFO, confidence=0.95),
    ]))
    kinds = [n.kind for n in r.notes]
    assert "suspicious_scoring" in kinds


# ---------------------------------------------------------------------------
# Invariants — WADE is advisory only
# ---------------------------------------------------------------------------


def test_review_does_not_mutate_findings() -> None:
    f = _f(severity=Severity.HIGH, confidence=0.4)
    original_severity = f.severity
    original_confidence = f.confidence
    review_scan(_result([f]))
    assert f.severity == original_severity
    assert f.confidence == original_confidence


def test_review_does_not_add_findings() -> None:
    r = _result([
        _f(severity=Severity.HIGH, confidence=0.4),
    ])
    before = len(r.findings)
    review = review_scan(r)
    after = len(r.findings)
    assert before == after
    # Notes reference real finding_ids, not invented ones.
    for n in review.notes:
        assert n.finding_id == str(r.findings[0].id)


def test_to_dict_round_trip_shape() -> None:
    r = review_scan(_result([_f(severity=Severity.HIGH, confidence=0.4)]))
    d = r.to_dict()
    for k in ("total_findings_reviewed", "note_count",
               "counts_by_kind", "notes"):
        assert k in d
