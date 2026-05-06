# WebHound — scanner/tests/test_models.py
# Pytest tests for all Phase 1 data models.

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from webhound.models import (
    Baseline,
    BaselineEntry,
    BaselineStatus,
    Evidence,
    EvidenceType,
    Finding,
    FindingCategory,
    FrameworkAlignment,
    ResponseProfile,
    ScanError,
    ScanOptions,
    ScanResult,
    ScanStatus,
    Severity,
    SeverityBreakdown,
    Target,
    TargetScope,
    TLSInfo,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def target() -> Target:
    return Target.from_url(
        "https://example.com",
        scan_options=ScanOptions(max_depth=2, max_pages=50, rate_limit_rps=1.0),
    )


@pytest.fixture()
def evidence() -> Evidence:
    return Evidence(
        evidence_type=EvidenceType.HEADER,
        content="X-Frame-Options: DENY",
        location="https://example.com/",
        confidence=0.95,
        source_engine="headers_engine",
    )


@pytest.fixture()
def finding(evidence: Evidence) -> Finding:
    return Finding(
        title="Missing Content-Security-Policy header",
        description="The response does not set a Content-Security-Policy header.",
        severity=Severity.MEDIUM,
        category=FindingCategory.SECURITY_HEADER,
        evidence=[evidence],
        confidence=0.9,
        scanner_engine="headers_engine",
        framework=FrameworkAlignment(
            owasp_top10=["A05:2021"],
            cwe_ids=["CWE-693"],
        ),
        remediation="Add a strict Content-Security-Policy header.",
    )


@pytest.fixture()
def scan_result(target: Target, finding: Finding) -> ScanResult:
    result = ScanResult(target=target)
    result.add_finding(finding)
    result.engines_run = ["headers_engine", "tls_engine"]
    result.urls_crawled = 10
    result.pages_analyzed = 8
    result.mark_complete()
    return result


@pytest.fixture()
def baseline(target: Target) -> Baseline:
    b = Baseline(target_id=target.id)
    entry = BaselineEntry(
        url="https://example.com/",
        status_code=200,
        content_length=4096,
        response_time_ms=150.0,
        headers={"server": "nginx"},
        content_hash="abc123def456" * 4,
    )
    b.add_entry(entry)
    b.mark_ready()
    return b


# ---------------------------------------------------------------------------
# Severity tests
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_unknown_is_lowest(self):
        assert Severity.UNKNOWN < Severity.INFO

    def test_numeric_scores(self):
        assert Severity.CRITICAL.numeric_score >= 9.0
        assert Severity.INFO.numeric_score == 0.0

    def test_from_cvss(self):
        assert Severity.from_cvss(9.8) == Severity.CRITICAL
        assert Severity.from_cvss(7.5) == Severity.HIGH
        assert Severity.from_cvss(5.0) == Severity.MEDIUM
        assert Severity.from_cvss(2.0) == Severity.LOW
        assert Severity.from_cvss(0.0) == Severity.INFO

    def test_from_label_case_insensitive(self):
        assert Severity.from_label("CRITICAL") == Severity.CRITICAL
        assert Severity.from_label("High") == Severity.HIGH

    def test_from_label_unknown_fallback(self):
        assert Severity.from_label("bogus") == Severity.UNKNOWN

    def test_is_actionable(self):
        assert Severity.CRITICAL.is_actionable()
        assert Severity.HIGH.is_actionable()
        assert Severity.MEDIUM.is_actionable()
        assert not Severity.LOW.is_actionable()
        assert not Severity.INFO.is_actionable()

    def test_color_codes_are_strings(self):
        for s in Severity:
            assert isinstance(s.color_code(), str)

    def test_hashable_usable_in_set(self):
        s = {Severity.HIGH, Severity.MEDIUM, Severity.HIGH}
        assert len(s) == 2

    def test_string_value(self):
        assert Severity.CRITICAL.value == "critical"
        assert str(Severity.HIGH) == "high"


# ---------------------------------------------------------------------------
# Evidence tests
# ---------------------------------------------------------------------------


class TestEvidence:
    def test_defaults(self, evidence: Evidence):
        assert isinstance(evidence.id, UUID)
        assert isinstance(evidence.captured_at, datetime)
        assert evidence.confidence == 0.95

    def test_confidence_rounded(self):
        e = Evidence(
            evidence_type=EvidenceType.RAW,
            content="test",
            location="https://x.com",
            confidence=0.123456789,
            source_engine="eng",
        )
        assert len(str(e.confidence).split(".")[-1]) <= 4

    def test_confidence_bounds(self):
        with pytest.raises(Exception):
            Evidence(
                evidence_type=EvidenceType.RAW,
                content="x",
                location="u",
                confidence=1.5,
                source_engine="e",
            )

    def test_status_code_bounds(self):
        with pytest.raises(Exception):
            Evidence(
                evidence_type=EvidenceType.HTTP_RESPONSE,
                content="x",
                location="u",
                confidence=1.0,
                source_engine="e",
                status_code=999,
            )

    def test_round_trip_json(self, evidence: Evidence):
        raw = evidence.to_json()
        restored = Evidence.from_json(raw)
        assert restored.id == evidence.id
        assert restored.evidence_type == evidence.evidence_type
        assert restored.confidence == evidence.confidence

    def test_round_trip_dict(self, evidence: Evidence):
        d = evidence.to_dict()
        restored = Evidence.from_dict(d)
        assert restored.content == evidence.content

    def test_http_header_constructor(self):
        e = Evidence.http_header(
            "X-Content-Type-Options", "nosniff", "https://a.com", "eng"
        )
        assert e.evidence_type == EvidenceType.HEADER
        assert "nosniff" in e.content
        assert e.extra["header_name"] == "X-Content-Type-Options"

    def test_pattern_match_constructor(self):
        e = Evidence.pattern_match(
            pattern=r"eval\(",
            matched_text="eval(atob('...'))",
            location="https://a.com/app.js",
            source_engine="js_engine",
        )
        assert e.evidence_type == EvidenceType.PATTERN_MATCH
        assert e.confidence == 0.8

    def test_extra_field_is_flexible(self, evidence: Evidence):
        evidence.extra["custom_key"] = {"nested": True}
        assert evidence.extra["custom_key"]["nested"] is True


# ---------------------------------------------------------------------------
# FrameworkAlignment tests
# ---------------------------------------------------------------------------


class TestFrameworkAlignment:
    def test_defaults_empty(self):
        fa = FrameworkAlignment()
        assert fa.owasp_top10 == []
        assert fa.cwe_ids == []
        assert fa.nist_controls == []
        assert fa.cvss_score is None

    def test_populated(self):
        fa = FrameworkAlignment(
            owasp_top10=["A03:2021"],
            cwe_ids=["CWE-79"],
            nist_controls=["SI-10"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            cvss_score=6.1,
        )
        assert "CWE-79" in fa.cwe_ids
        assert fa.cvss_score == 6.1

    def test_cvss_score_bounds(self):
        with pytest.raises(Exception):
            FrameworkAlignment(cvss_score=11.0)


# ---------------------------------------------------------------------------
# Finding tests
# ---------------------------------------------------------------------------


class TestFinding:
    def test_defaults(self, finding: Finding):
        assert isinstance(finding.id, UUID)
        assert finding.false_positive is False
        assert finding.reviewed is False
        assert finding.suppressed is False
        assert finding.evidence_count == 1

    def test_is_active(self, finding: Finding):
        assert finding.is_active
        finding.false_positive = True
        assert not finding.is_active

    def test_effective_severity_high_confidence(self, finding: Finding):
        finding.severity = Severity.HIGH
        finding.confidence = 0.9
        assert finding.effective_severity == Severity.HIGH

    def test_effective_severity_low_confidence_demotion(self, finding: Finding):
        finding.severity = Severity.HIGH
        finding.confidence = 0.3
        assert finding.effective_severity == Severity.MEDIUM

    def test_effective_severity_critical_demotion(self, finding: Finding):
        finding.severity = Severity.CRITICAL
        finding.confidence = 0.3
        assert finding.effective_severity == Severity.HIGH

    def test_confidence_rounded(self, finding: Finding):
        finding.confidence = 0.12345678
        # validator fires on construction — here we check it was rounded at build
        f2 = Finding(
            title="t",
            description="d",
            severity=Severity.LOW,
            confidence=0.12345678,
            scanner_engine="e",
        )
        assert len(str(f2.confidence).split(".")[-1]) <= 4

    def test_round_trip_json(self, finding: Finding):
        raw = finding.to_json()
        restored = Finding.from_json(raw)
        assert restored.id == finding.id
        assert restored.severity == finding.severity
        assert len(restored.evidence) == 1

    def test_round_trip_dict(self, finding: Finding):
        d = finding.to_dict()
        restored = Finding.from_dict(d)
        assert restored.title == finding.title

    def test_framework_alignment_serialised(self, finding: Finding):
        d = finding.to_dict()
        assert "A05:2021" in d["framework"]["owasp_top10"]
        assert "CWE-693" in d["framework"]["cwe_ids"]

    def test_suppressed_not_active(self, finding: Finding):
        finding.suppressed = True
        assert not finding.is_active


# ---------------------------------------------------------------------------
# Target tests
# ---------------------------------------------------------------------------


class TestTarget:
    def test_from_url_derives_fields(self, target: Target):
        assert target.hostname == "example.com"
        assert target.scheme == "https"
        assert target.is_https is True

    def test_base_url_no_port(self, target: Target):
        assert target.base_url == "https://example.com"

    def test_base_url_non_standard_port(self):
        t = Target.from_url("https://example.com:8443")
        assert ":8443" in t.base_url

    def test_base_url_standard_port_omitted(self):
        t = Target.from_url("https://example.com:443")
        assert ":443" not in t.base_url

    def test_scheme_normalised(self):
        t = Target(url="http://a.com", hostname="a.com", scheme="HTTP")
        assert t.scheme == "http"

    def test_invalid_scheme_raises(self):
        with pytest.raises(Exception):
            Target(url="ftp://a.com", hostname="a.com", scheme="ftp")

    def test_scan_options_defaults(self):
        t = Target.from_url("https://a.com")
        assert t.scan_options.max_depth == 3
        assert t.scan_options.rate_limit_rps == 2.0
        assert t.scan_options.respect_robots_txt is True

    def test_rate_limit_upper_bound(self):
        with pytest.raises(Exception):
            ScanOptions(rate_limit_rps=99.0)

    def test_round_trip_json(self, target: Target):
        raw = target.to_json()
        restored = Target.from_json(raw)
        assert restored.id == target.id
        assert restored.hostname == target.hostname

    def test_round_trip_dict(self, target: Target):
        d = target.to_dict()
        restored = Target.from_dict(d)
        assert restored.url == target.url

    def test_tls_info_expiry(self):
        future = datetime.now(timezone.utc) + timedelta(days=90)
        past = datetime.now(timezone.utc) - timedelta(days=1)
        tls_valid = TLSInfo(hostname="a.com", not_after=future)
        tls_expired = TLSInfo(hostname="a.com", not_after=past)
        assert not tls_valid.is_expired
        assert tls_expired.is_expired
        assert tls_valid.days_until_expiry > 0

    def test_tls_info_no_expiry_returns_none(self):
        tls = TLSInfo(hostname="a.com")
        assert tls.days_until_expiry is None
        assert not tls.is_expired


# ---------------------------------------------------------------------------
# ScanResult tests
# ---------------------------------------------------------------------------


class TestScanResult:
    def test_initial_state(self, target: Target):
        result = ScanResult(target=target)
        assert result.status == ScanStatus.PENDING
        assert result.findings == []
        assert result.overall_risk_score == 0.0

    def test_add_finding(self, target: Target, finding: Finding):
        result = ScanResult(target=target)
        result.add_finding(finding)
        assert len(result.findings) == 1

    def test_mark_complete(self, scan_result: ScanResult):
        assert scan_result.status == ScanStatus.COMPLETED
        assert scan_result.completed_at is not None
        assert scan_result.duration_seconds is not None
        assert scan_result.duration_seconds >= 0.0

    def test_severity_breakdown_after_complete(self, scan_result: ScanResult):
        assert scan_result.severity_breakdown.medium == 1
        assert scan_result.severity_breakdown.total == 1

    def test_overall_risk_score_nonzero(self, scan_result: ScanResult):
        assert scan_result.overall_risk_score > 0.0

    def test_active_findings_excludes_fp(self, scan_result: ScanResult):
        scan_result.findings[0].false_positive = True
        assert scan_result.active_findings == []

    def test_recompute_resets_when_all_fp(self, scan_result: ScanResult):
        scan_result.findings[0].false_positive = True
        scan_result.recompute_aggregates()
        assert scan_result.overall_risk_score == 0.0
        assert scan_result.severity_breakdown.total == 0

    def test_add_error(self, scan_result: ScanResult):
        err = ScanError(engine="tls_engine", message="Connection refused", url="https://a.com")
        scan_result.add_error(err)
        assert len(scan_result.errors) == 1

    def test_mark_failed(self, target: Target):
        result = ScanResult(target=target)
        result.mark_failed("timeout")
        assert result.status == ScanStatus.FAILED
        assert result.metadata["failure_reason"] == "timeout"

    def test_summary_structure(self, scan_result: ScanResult):
        s = scan_result.summary()
        assert "id" in s
        assert "target" in s
        assert "findings" in s
        assert "duration_seconds" in s
        assert s["findings"]["total"] == 1

    def test_round_trip_json(self, scan_result: ScanResult):
        raw = scan_result.to_json()
        restored = ScanResult.from_json(raw)
        assert restored.id == scan_result.id
        assert restored.status == scan_result.status
        assert len(restored.findings) == 1

    def test_round_trip_dict(self, scan_result: ScanResult):
        d = scan_result.to_dict()
        restored = ScanResult.from_dict(d)
        assert restored.overall_risk_score == scan_result.overall_risk_score

    def test_multiple_severity_levels(self, target: Target):
        result = ScanResult(target=target)
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.LOW, Severity.INFO):
            result.add_finding(
                Finding(
                    title=f"{sev.value} finding",
                    description="test",
                    severity=sev,
                    confidence=1.0,
                    scanner_engine="test",
                )
            )
        result.mark_complete()
        bd = result.severity_breakdown
        assert bd.critical == 1
        assert bd.high == 1
        assert bd.low == 1
        assert bd.info == 1


# ---------------------------------------------------------------------------
# SeverityBreakdown tests
# ---------------------------------------------------------------------------


class TestSeverityBreakdown:
    def test_total(self):
        bd = SeverityBreakdown(critical=1, high=2, medium=3, low=4, info=5)
        assert bd.total == 15

    def test_actionable(self):
        bd = SeverityBreakdown(critical=1, high=2, medium=3, low=4, info=5)
        assert bd.actionable == 6


# ---------------------------------------------------------------------------
# Baseline tests
# ---------------------------------------------------------------------------


class TestBaseline:
    def test_initial_status(self, target: Target):
        b = Baseline(target_id=target.id)
        assert b.status == BaselineStatus.BUILDING
        assert not b.is_ready
        assert not b.is_usable

    def test_mark_ready(self, baseline: Baseline):
        assert baseline.status == BaselineStatus.READY
        assert baseline.is_ready

    def test_sample_count(self, baseline: Baseline):
        assert baseline.sample_count == 1

    def test_add_entry_increments_count(self, baseline: Baseline):
        entry = BaselineEntry(
            url="https://example.com/page",
            status_code=200,
            content_length=1024,
            response_time_ms=80.0,
            headers={},
            content_hash="a" * 64,
        )
        baseline.add_entry(entry)
        assert baseline.sample_count == 2

    def test_usable_when_ready_not_expired(self, baseline: Baseline):
        assert baseline.is_usable

    def test_expired_not_usable(self, baseline: Baseline):
        baseline.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        assert not baseline.is_usable

    def test_mark_stale(self, baseline: Baseline):
        baseline.mark_stale()
        assert baseline.status == BaselineStatus.STALE
        assert not baseline.is_ready

    def test_extend_expiry(self, baseline: Baseline):
        old_expiry = baseline.expires_at
        baseline.extend_expiry(60)
        assert baseline.expires_at > old_expiry

    def test_anomaly_threshold_rounded(self):
        b = Baseline(target_id=uuid4(), anomaly_threshold=0.123456)
        assert len(str(b.anomaly_threshold).split(".")[-1]) <= 4

    def test_anomaly_threshold_bounds(self):
        with pytest.raises(Exception):
            Baseline(target_id=uuid4(), anomaly_threshold=1.5)

    def test_round_trip_json(self, baseline: Baseline):
        raw = baseline.to_json()
        restored = Baseline.from_json(raw)
        assert restored.id == baseline.id
        assert restored.status == baseline.status
        assert restored.sample_count == baseline.sample_count

    def test_round_trip_dict(self, baseline: Baseline):
        d = baseline.to_dict()
        restored = Baseline.from_dict(d)
        assert restored.target_id == baseline.target_id

    def test_response_profile_structure(self):
        profile = ResponseProfile(
            url_pattern="https://example.com/*",
            status_codes={"200": 40, "404": 2},
            content_length_mean=4096.0,
            content_length_stddev=512.0,
            response_time_p50_ms=120.0,
            response_time_p90_ms=300.0,
            response_time_p99_ms=800.0,
            sample_count=42,
        )
        assert profile.sample_count == 42
        assert profile.status_codes["200"] == 40
