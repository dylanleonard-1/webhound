# WebHound — scanner/tests/test_wade_integration.py
# Tests for Phase 12: WADE v1 integration into the scanner pipeline.
#
# Covers: scan without baseline → WADE skipped cleanly; scan with baseline →
# detects script/domain/form/header regression; WADE findings in ScanResult;
# JSON/summary reports include WADE section; engine diagnostics includes WADE status.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx
import pytest

from webhound.core.orchestrator import Scanner
from webhound.engines.tls_dns.dns_checker import DnsRecords
from webhound.engines.tls_dns.tls_checker import TlsCertInfo
from webhound.models.engine_status import EngineRunStatus
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory
from webhound.models.scan_result import ScanResult, ScanStatus, SeverityBreakdown
from webhound.models.severity import Severity
from webhound.models.target import ScanOptions, Target
from webhound.reporting.json_report import JsonReport, _wade_section
from webhound.reporting.summary_builder import SummaryBuilder
from webhound.wade.baseline_builder import BaselineBuilder, PageSnapshot, SiteBaseline
from webhound.wade.diff_engine import DiffType


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_MINIMAL_HTML = (
    "<!DOCTYPE html><html><head><title>T</title></head><body>ok</body></html>"
)

_HTML_WITH_SCRIPT = (
    "<!DOCTYPE html><html><head><title>T</title></head><body>"
    '<script src="https://cdn.example.com/lib.js"></script>'
    "</body></html>"
)

_HTML_WITH_NEW_SCRIPT = (
    "<!DOCTYPE html><html><head><title>T</title></head><body>"
    '<script src="https://cdn.example.com/lib.js"></script>'
    '<script src="https://evil.example.net/track.js"></script>'
    "</body></html>"
)

_HTML_WITH_FORM = (
    "<!DOCTYPE html><html><head><title>Login</title></head><body>"
    '<form method="POST" action="/login">'
    '<input type="text" name="username" />'
    '<input type="password" name="password" />'
    "</form></body></html>"
)

_HTML_WITH_NEW_FORM = (
    "<!DOCTYPE html><html><head><title>Login</title></head><body>"
    '<form method="POST" action="/login">'
    '<input type="text" name="username" />'
    '<input type="password" name="password" />'
    "</form>"
    '<form method="POST" action="/subscribe">'
    '<input type="email" name="email" />'
    "</form>"
    "</body></html>"
)


def _target(url: str = "https://example.com") -> Target:
    opts = ScanOptions(max_pages=3, max_depth=1, rate_limit_rps=10.0, verify_tls=False)
    return Target.from_url(url, scan_options=opts)


def _mock_transport(body: str = _MINIMAL_HTML) -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/", ""):
            return httpx.Response(
                status_code=200,
                text=body,
                headers={"content-type": "text/html; charset=utf-8"},
            )
        return httpx.Response(status_code=404, text="Not Found")

    return httpx.MockTransport(handler)


def _mock_transport_with_headers(
    body: str = _MINIMAL_HTML, extra_headers: dict[str, str] | None = None
) -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        hdrs = {"content-type": "text/html; charset=utf-8"}
        if extra_headers:
            hdrs.update(extra_headers)
        if request.url.path in ("/", ""):
            return httpx.Response(status_code=200, text=body, headers=hdrs)
        return httpx.Response(status_code=404, text="Not Found")

    return httpx.MockTransport(handler)


def _patch_tls_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    from webhound.engines.tls_dns import dns_checker as _dns, tls_checker as _tls

    monkeypatch.setattr(
        _tls, "probe_tls",
        lambda *a, **k: TlsCertInfo(domain="example.com", connection_failed=True),
    )
    monkeypatch.setattr(
        _dns, "resolve_dns",
        lambda *a, **k: DnsRecords(domain="example.com", a=["93.184.216.34"]),
    )


def _completed_result_no_wade() -> ScanResult:
    """A completed ScanResult without any WADE metadata."""
    target = _target()
    result = ScanResult(
        target=target,
        status=ScanStatus.COMPLETED,
        findings=[],
        engines_run=["security_headers"],
        urls_crawled=1,
        pages_analyzed=1,
        started_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2025, 1, 1, 12, 0, 5, tzinfo=timezone.utc),
    )
    result.recompute_aggregates()
    result.metadata["risk_score"] = 90
    result.metadata["risk_level"] = "low"
    result.metadata["external_domains"] = []
    result.metadata["external_domain_count"] = 0
    return result


def _completed_result_with_wade(
    baseline_generated: bool = True,
    compared: bool = True,
    anomaly_count: int = 2,
    wade_findings: list[Finding] | None = None,
) -> ScanResult:
    """A completed ScanResult with WADE metadata and optional findings."""
    target = _target()
    findings = wade_findings or []
    result = ScanResult(
        target=target,
        status=ScanStatus.COMPLETED,
        findings=findings,
        engines_run=["security_headers", "wade"],
        urls_crawled=1,
        pages_analyzed=1,
        started_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2025, 1, 1, 12, 0, 5, tzinfo=timezone.utc),
    )
    result.recompute_aggregates()
    result.metadata["risk_score"] = 70
    result.metadata["risk_level"] = "medium"
    result.metadata["external_domains"] = []
    result.metadata["external_domain_count"] = 0
    result.metadata["wade_baseline_generated"] = baseline_generated
    result.metadata["wade_baseline_version"] = "abc123" if baseline_generated else None
    result.metadata["wade_compared_to_previous"] = compared
    result.metadata["wade_anomaly_count"] = anomaly_count
    return result


def _wade_finding(
    title: str = "New External Script Detected",
    severity: Severity = Severity.HIGH,
    anomaly_score: float = 0.75,
    location: str = "https://example.com/",
) -> Finding:
    return Finding(
        title=title,
        description=f"Script change detected. Anomaly score: {anomaly_score:.2f}.",
        severity=severity,
        category=FindingCategory.JAVASCRIPT,
        scanner_engine="wade",
        anomaly_score=anomaly_score,
        evidence=[
            Evidence(
                evidence_type=EvidenceType.PATTERN_MATCH,
                content="new script",
                location=location,
                source_engine="wade",
                extra={"diff_type": DiffType.NEW_SCRIPT_SOURCE.value},
            )
        ],
    )


def _build_baseline_from_snapshot(
    url: str = "https://example.com/",
    script_sources: list[str] | None = None,
    external_domains: list[str] | None = None,
    form_signatures: list[str] | None = None,
    headers: dict[str, str] | None = None,
    cookie_signatures: dict[str, str] | None = None,
    scan_id: str = "baseline-scan-001",
    target_url: str = "https://example.com",
) -> SiteBaseline:
    snap = PageSnapshot(
        url=url,
        status_code=200,
        content_hash="abc123",
        headers=headers or {"x-content-type-options": "nosniff"},
        script_sources=script_sources or [],
        inline_hashes=[],
        external_domains=external_domains or [],
        form_signatures=form_signatures or [],
        cookie_signatures=cookie_signatures or {},
    )
    return SiteBaseline(
        target_url=target_url,
        scan_id=scan_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        pages={url: snap},
        all_script_sources=script_sources or [],
        all_external_domains=external_domains or [],
        page_count=1,
    )


# ---------------------------------------------------------------------------
# Scanner integration tests — WADE skipped when no baseline
# ---------------------------------------------------------------------------


class TestWadeNoBaseline:
    @pytest.mark.anyio
    async def test_scan_without_baseline_completes_successfully(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        assert result.status == ScanStatus.COMPLETED

    @pytest.mark.anyio
    async def test_wade_skipped_in_diagnostics_without_baseline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        wade_diag = next((d for d in result.engine_diagnostics if d.name == "wade"), None)
        assert wade_diag is not None
        assert wade_diag.status == EngineRunStatus.SKIPPED
        assert wade_diag.skipped_reason == "no previous baseline supplied"

    @pytest.mark.anyio
    async def test_no_wade_findings_without_baseline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        wade_findings = [f for f in result.findings if f.scanner_engine == "wade"]
        assert wade_findings == []

    @pytest.mark.anyio
    async def test_baseline_generated_metadata_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        assert result.metadata.get("wade_baseline_generated") is True
        assert result.metadata.get("wade_baseline_version") is not None

    @pytest.mark.anyio
    async def test_compared_to_previous_is_false_without_baseline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        assert result.metadata.get("wade_compared_to_previous") is False
        assert result.metadata.get("wade_anomaly_count") == 0

    @pytest.mark.anyio
    async def test_current_baseline_property_populated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        await scanner.scan()
        assert scanner.current_baseline is not None
        assert scanner.current_baseline.target_url == "https://example.com"

    @pytest.mark.anyio
    async def test_current_baseline_is_none_before_scan(self) -> None:
        scanner = Scanner(_target())
        assert scanner.current_baseline is None


# ---------------------------------------------------------------------------
# Scanner integration tests — WADE active with previous baseline
# ---------------------------------------------------------------------------


class TestWadeWithBaseline:
    @pytest.mark.anyio
    async def test_new_script_source_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        previous = _build_baseline_from_snapshot(script_sources=[])
        scanner = Scanner(
            _target(),
            _transport=_mock_transport(_HTML_WITH_SCRIPT),
            previous_baseline=previous,
        )
        result = await scanner.scan()
        wade_findings = [f for f in result.findings if f.scanner_engine == "wade"]
        titles = [f.title for f in wade_findings]
        assert any("Script" in t for t in titles), f"Expected script finding, got: {titles}"

    @pytest.mark.anyio
    async def test_new_external_domain_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        previous = _build_baseline_from_snapshot(external_domains=[])
        scanner = Scanner(
            _target(),
            _transport=_mock_transport(_HTML_WITH_SCRIPT),
            previous_baseline=previous,
        )
        result = await scanner.scan()
        wade_findings = [f for f in result.findings if f.scanner_engine == "wade"]
        assert len(wade_findings) >= 1

    @pytest.mark.anyio
    async def test_new_form_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        previous = _build_baseline_from_snapshot(form_signatures=[])
        scanner = Scanner(
            _target(),
            _transport=_mock_transport(_HTML_WITH_FORM),
            previous_baseline=previous,
        )
        result = await scanner.scan()
        wade_findings = [f for f in result.findings if f.scanner_engine == "wade"]
        titles = [f.title for f in wade_findings]
        assert any("Form" in t for t in titles), f"Expected form finding, got: {titles}"

    @pytest.mark.anyio
    async def test_header_regression_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        previous = _build_baseline_from_snapshot(
            headers={
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "content-security-policy": "default-src 'self'",
            }
        )
        scanner = Scanner(
            _target(),
            _transport=_mock_transport_with_headers(
                extra_headers={"x-content-type-options": "nosniff"}
            ),
            previous_baseline=previous,
        )
        result = await scanner.scan()
        wade_findings = [f for f in result.findings if f.scanner_engine == "wade"]
        titles = [f.title for f in wade_findings]
        assert any("Header" in t for t in titles), f"Expected header finding, got: {titles}"

    @pytest.mark.anyio
    async def test_wade_findings_in_scan_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        previous = _build_baseline_from_snapshot(script_sources=[])
        scanner = Scanner(
            _target(),
            _transport=_mock_transport(_HTML_WITH_SCRIPT),
            previous_baseline=previous,
        )
        result = await scanner.scan()
        assert any(f.scanner_engine == "wade" for f in result.findings)

    @pytest.mark.anyio
    async def test_wade_findings_status_in_diagnostics(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        previous = _build_baseline_from_snapshot(script_sources=[])
        scanner = Scanner(
            _target(),
            _transport=_mock_transport(_HTML_WITH_SCRIPT),
            previous_baseline=previous,
        )
        result = await scanner.scan()
        wade_diag = next((d for d in result.engine_diagnostics if d.name == "wade"), None)
        assert wade_diag is not None
        assert wade_diag.status in (EngineRunStatus.FINDINGS, EngineRunStatus.PASSED)
        assert wade_diag.skipped_reason is None

    @pytest.mark.anyio
    async def test_compared_to_previous_true_with_baseline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        previous = _build_baseline_from_snapshot()
        scanner = Scanner(
            _target(),
            _transport=_mock_transport(),
            previous_baseline=previous,
        )
        result = await scanner.scan()
        assert result.metadata.get("wade_compared_to_previous") is True

    @pytest.mark.anyio
    async def test_anomaly_count_metadata_matches_findings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        previous = _build_baseline_from_snapshot(script_sources=[])
        scanner = Scanner(
            _target(),
            _transport=_mock_transport(_HTML_WITH_SCRIPT),
            previous_baseline=previous,
        )
        result = await scanner.scan()
        wade_findings = [f for f in result.findings if f.scanner_engine == "wade"]
        assert result.metadata.get("wade_anomaly_count") == len(wade_findings)

    @pytest.mark.anyio
    async def test_wade_findings_have_anomaly_score(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        previous = _build_baseline_from_snapshot(script_sources=[])
        scanner = Scanner(
            _target(),
            _transport=_mock_transport(_HTML_WITH_SCRIPT),
            previous_baseline=previous,
        )
        result = await scanner.scan()
        wade_findings = [f for f in result.findings if f.scanner_engine == "wade"]
        for f in wade_findings:
            assert f.anomaly_score is not None
            assert 0.0 <= f.anomaly_score <= 1.0

    @pytest.mark.anyio
    async def test_wade_findings_have_evidence_with_extra(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        previous = _build_baseline_from_snapshot(script_sources=[])
        scanner = Scanner(
            _target(),
            _transport=_mock_transport(_HTML_WITH_SCRIPT),
            previous_baseline=previous,
        )
        result = await scanner.scan()
        wade_findings = [f for f in result.findings if f.scanner_engine == "wade"]
        for f in wade_findings:
            assert f.evidence, "WADE finding should have evidence"
            assert "diff_type" in f.evidence[0].extra

    @pytest.mark.anyio
    async def test_no_change_between_identical_baselines(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        # First scan to build a baseline
        scanner1 = Scanner(_target(), _transport=_mock_transport())
        await scanner1.scan()
        first_baseline = scanner1.current_baseline

        # Second scan using first baseline — same content, no changes
        scanner2 = Scanner(
            _target(),
            _transport=_mock_transport(),
            previous_baseline=first_baseline,
        )
        result2 = await scanner2.scan()
        wade_findings = [f for f in result2.findings if f.scanner_engine == "wade"]
        assert len(wade_findings) == 0
        assert result2.metadata.get("wade_anomaly_count") == 0


# ---------------------------------------------------------------------------
# JSON report — WADE section
# ---------------------------------------------------------------------------


class TestJsonReportWadeSection:
    def test_wade_section_present_in_report(self) -> None:
        result = _completed_result_no_wade()
        report = JsonReport().build(result)
        assert "wade" in report

    def test_wade_section_keys(self) -> None:
        result = _completed_result_no_wade()
        report = JsonReport().build(result)
        wade = report["wade"]
        assert "baseline_generated" in wade
        assert "baseline_version" in wade
        assert "compared_to_previous_baseline" in wade
        assert "anomaly_count" in wade
        assert "top_anomalies" in wade

    def test_wade_section_defaults_no_metadata(self) -> None:
        result = _completed_result_no_wade()
        report = JsonReport().build(result)
        wade = report["wade"]
        assert wade["baseline_generated"] is False
        assert wade["baseline_version"] is None
        assert wade["compared_to_previous_baseline"] is False
        assert wade["anomaly_count"] == 0
        assert wade["top_anomalies"] == []

    def test_wade_section_reflects_metadata(self) -> None:
        result = _completed_result_with_wade(anomaly_count=3, compared=True)
        report = JsonReport().build(result)
        wade = report["wade"]
        assert wade["baseline_generated"] is True
        assert wade["baseline_version"] == "abc123"
        assert wade["compared_to_previous_baseline"] is True
        assert wade["anomaly_count"] == 3

    def test_wade_top_anomalies_populated(self) -> None:
        f1 = _wade_finding(anomaly_score=0.90)
        f2 = _wade_finding(title="Cookie Regression", anomaly_score=0.60, severity=Severity.MEDIUM)
        result = _completed_result_with_wade(wade_findings=[f1, f2], anomaly_count=2)
        report = JsonReport().build(result)
        wade = report["wade"]
        assert len(wade["top_anomalies"]) == 2

    def test_wade_top_anomalies_capped_at_five(self) -> None:
        findings = [_wade_finding(title=f"Finding {i}", anomaly_score=0.8) for i in range(8)]
        result = _completed_result_with_wade(wade_findings=findings, anomaly_count=8)
        report = JsonReport().build(result)
        assert len(report["wade"]["top_anomalies"]) == 5

    def test_wade_top_anomalies_sorted_by_score_desc(self) -> None:
        f_low = _wade_finding(title="Low Score", anomaly_score=0.3)
        f_high = _wade_finding(title="High Score", anomaly_score=0.9)
        f_mid = _wade_finding(title="Mid Score", anomaly_score=0.6)
        result = _completed_result_with_wade(
            wade_findings=[f_low, f_high, f_mid], anomaly_count=3
        )
        report = JsonReport().build(result)
        scores = [a["anomaly_score"] for a in report["wade"]["top_anomalies"]]
        assert scores == sorted(scores, reverse=True)

    def test_wade_anomaly_item_keys(self) -> None:
        f = _wade_finding()
        result = _completed_result_with_wade(wade_findings=[f], anomaly_count=1)
        report = JsonReport().build(result)
        item = report["wade"]["top_anomalies"][0]
        assert "title" in item
        assert "severity" in item
        assert "confidence" in item
        assert "anomaly_score" in item
        assert "evidence_location" in item
        assert "description" in item

    def test_wade_section_helper_function_directly(self) -> None:
        result = _completed_result_with_wade()
        section = _wade_section(result)
        assert isinstance(section, dict)
        assert "top_anomalies" in section

    def test_wade_section_not_included_for_non_wade_findings(self) -> None:
        f = Finding(
            title="Other Finding",
            description="desc",
            severity=Severity.HIGH,
            category=FindingCategory.SECURITY_HEADER,
            scanner_engine="security_headers",
            evidence=[],
        )
        result = _completed_result_no_wade()
        result.findings = [f]
        result.recompute_aggregates()
        report = JsonReport().build(result)
        assert report["wade"]["top_anomalies"] == []


# ---------------------------------------------------------------------------
# Summary report — WADE section
# ---------------------------------------------------------------------------


class TestSummaryBuilderWadeSection:
    def test_wade_section_absent_when_no_metadata(self) -> None:
        result = _completed_result_no_wade()
        summary = SummaryBuilder().build(result)
        assert "WADE" not in summary

    def test_wade_section_present_when_baseline_generated(self) -> None:
        result = _completed_result_with_wade(baseline_generated=True, compared=False)
        summary = SummaryBuilder().build(result)
        assert "WADE" in summary

    def test_wade_summary_shows_baseline_generated_yes(self) -> None:
        result = _completed_result_with_wade(baseline_generated=True)
        summary = SummaryBuilder().build(result)
        assert "Baseline generated:   yes" in summary

    def test_wade_summary_shows_compared_yes(self) -> None:
        result = _completed_result_with_wade(compared=True)
        summary = SummaryBuilder().build(result)
        assert "Compared to baseline: yes" in summary

    def test_wade_summary_shows_anomaly_count(self) -> None:
        result = _completed_result_with_wade(anomaly_count=4)
        summary = SummaryBuilder().build(result)
        assert "Anomalies detected:   4" in summary

    def test_wade_summary_shows_skip_note_when_not_compared(self) -> None:
        result = _completed_result_with_wade(compared=False, anomaly_count=0)
        summary = SummaryBuilder().build(result)
        assert "no previous baseline" in summary

    def test_wade_summary_lists_top_findings(self) -> None:
        f = _wade_finding(title="New External Script Detected", anomaly_score=0.75)
        result = _completed_result_with_wade(wade_findings=[f], anomaly_count=1)
        summary = SummaryBuilder().build(result)
        assert "New External Script Detected" in summary
        assert "score 0.75" in summary

    def test_wade_findings_severity_label_in_summary(self) -> None:
        f = _wade_finding(severity=Severity.HIGH)
        result = _completed_result_with_wade(wade_findings=[f], anomaly_count=1)
        summary = SummaryBuilder().build(result)
        assert "[HIGH]" in summary


# ---------------------------------------------------------------------------
# Engine diagnostics — WADE entry
# ---------------------------------------------------------------------------


class TestEngineDiagnosticsWade:
    @pytest.mark.anyio
    async def test_wade_appears_in_engine_diagnostics(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        names = [d.name for d in result.engine_diagnostics]
        assert "wade" in names

    @pytest.mark.anyio
    async def test_wade_category_is_anomaly_detection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        wade_diag = next(d for d in result.engine_diagnostics if d.name == "wade")
        assert wade_diag.category == "anomaly_detection"

    @pytest.mark.anyio
    async def test_wade_skipped_reason_in_json_report(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        report = JsonReport().build(result)
        wade_diag = next(
            d for d in report["engine_diagnostics"] if d["name"] == "wade"
        )
        assert wade_diag["status"] == "skipped"
        assert wade_diag["skipped_reason"] == "no previous baseline supplied"

    @pytest.mark.anyio
    async def test_wade_findings_status_in_json_diagnostics(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        previous = _build_baseline_from_snapshot(script_sources=[])
        scanner = Scanner(
            _target(),
            _transport=_mock_transport(_HTML_WITH_SCRIPT),
            previous_baseline=previous,
        )
        result = await scanner.scan()
        report = JsonReport().build(result)
        wade_diag = next(
            d for d in report["engine_diagnostics"] if d["name"] == "wade"
        )
        assert wade_diag["status"] in ("findings", "passed")
        assert wade_diag["skipped_reason"] is None

    @pytest.mark.anyio
    async def test_wade_findings_count_in_diagnostics(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        previous = _build_baseline_from_snapshot(script_sources=[])
        scanner = Scanner(
            _target(),
            _transport=_mock_transport(_HTML_WITH_SCRIPT),
            previous_baseline=previous,
        )
        result = await scanner.scan()
        wade_diag = next(d for d in result.engine_diagnostics if d.name == "wade")
        wade_findings = [f for f in result.findings if f.scanner_engine == "wade"]
        assert wade_diag.findings_count == len(wade_findings)
