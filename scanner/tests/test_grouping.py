# WebHound — scanner/tests/test_grouping.py
# Tests for Phase 13: finding deduplication, grouping, and noise reduction.
#
# Covers: FindingGrouper unit tests, grouped JSON output, summary using grouped
# findings, risk scoring from grouped findings, raw findings preserved, affected
# URL counts, per-URL engine isolation, compromise/WADE findings not hidden.

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest

from webhound.core.finding_grouper import FindingGrouper, _PER_URL_ENGINES
from webhound.core.orchestrator import Scanner, _breakdown_from_grouped, _compute_risk_score
from webhound.engines.tls_dns.dns_checker import DnsRecords
from webhound.engines.tls_dns.tls_checker import TlsCertInfo
from webhound.models.engine_status import EngineRunStatus
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.scan_result import ScanResult, ScanStatus, SeverityBreakdown
from webhound.models.severity import Severity
from webhound.models.target import ScanOptions, Target
from webhound.reporting.json_report import JsonReport
from webhound.reporting.summary_builder import SummaryBuilder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MINIMAL_HTML = (
    "<!DOCTYPE html><html><head><title>T</title></head><body>ok</body></html>"
)


def _target(url: str = "https://example.com") -> Target:
    opts = ScanOptions(max_pages=3, max_depth=1, rate_limit_rps=10.0, verify_tls=False)
    return Target.from_url(url, scan_options=opts)


def _finding(
    title: str = "Missing CSP",
    severity: Severity = Severity.MEDIUM,
    engine: str = "security_headers",
    category: FindingCategory = FindingCategory.SECURITY_HEADER,
    location: str = "https://example.com/",
    remediation: str | None = "Add Content-Security-Policy header.",
    owasp: list[str] | None = None,
    confidence: float = 1.0,
    anomaly_score: float | None = None,
) -> Finding:
    return Finding(
        title=title,
        description=f"{title} detected.",
        severity=severity,
        category=category,
        scanner_engine=engine,
        remediation=remediation,
        confidence=confidence,
        anomaly_score=anomaly_score,
        framework=FrameworkAlignment(owasp_top10=owasp or []),
        evidence=[
            Evidence(
                evidence_type=EvidenceType.HEADER,
                content="missing",
                location=location,
                source_engine=engine,
            )
        ],
    )


def _mock_transport(body: str = _MINIMAL_HTML) -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/", ""):
            return httpx.Response(
                200, text=body,
                headers={"content-type": "text/html; charset=utf-8"},
            )
        return httpx.Response(404, text="Not Found")
    return httpx.MockTransport(handler)


def _patch_tls_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    from webhound.engines.tls_dns import dns_checker as _dns, tls_checker as _tls
    monkeypatch.setattr(_tls, "probe_tls",
        lambda *a, **k: TlsCertInfo(domain="example.com", connection_failed=True))
    monkeypatch.setattr(_dns, "resolve_dns",
        lambda *a, **k: DnsRecords(domain="example.com", a=["93.184.216.34"]))


def _completed_result(findings: list[Finding]) -> ScanResult:
    result = ScanResult(
        target=_target(),
        status=ScanStatus.COMPLETED,
        findings=findings,
        engines_run=["security_headers"],
        urls_crawled=len({f.evidence[0].location for f in findings if f.evidence}),
        pages_analyzed=len({f.evidence[0].location for f in findings if f.evidence}),
        started_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2025, 1, 1, 12, 0, 5, tzinfo=timezone.utc),
    )
    result.recompute_aggregates()
    result.metadata["risk_score"] = 80
    result.metadata["risk_level"] = "low"
    result.metadata["external_domains"] = []
    result.metadata["external_domain_count"] = 0
    return result


# ---------------------------------------------------------------------------
# FindingGrouper — unit tests
# ---------------------------------------------------------------------------


class TestFindingGrouperBasic:
    def test_single_finding_becomes_one_group(self) -> None:
        f = _finding()
        groups = FindingGrouper().group([f])
        assert len(groups) == 1

    def test_two_same_title_engine_different_urls_collapse(self) -> None:
        f1 = _finding(location="https://example.com/")
        f2 = _finding(location="https://example.com/about")
        groups = FindingGrouper().group([f1, f2])
        assert len(groups) == 1

    def test_different_titles_stay_separate(self) -> None:
        f1 = _finding(title="Missing CSP")
        f2 = _finding(title="Missing X-Frame-Options")
        groups = FindingGrouper().group([f1, f2])
        assert len(groups) == 2

    def test_different_remediation_stays_separate(self) -> None:
        f1 = _finding(remediation="Fix A")
        f2 = _finding(remediation="Fix B")
        groups = FindingGrouper().group([f1, f2])
        assert len(groups) == 2

    def test_different_engines_stay_separate(self) -> None:
        f1 = _finding(engine="security_headers")
        f2 = _finding(engine="cors", category=FindingCategory.CORS)
        groups = FindingGrouper().group([f1, f2])
        assert len(groups) == 2

    def test_empty_list_returns_empty(self) -> None:
        assert FindingGrouper().group([]) == []

    def test_groups_sorted_by_severity_descending(self) -> None:
        f_low = _finding(title="Low Issue", severity=Severity.LOW)
        f_critical = _finding(title="Critical Issue", severity=Severity.CRITICAL,
                              remediation="Fix critical")
        f_medium = _finding(title="Medium Issue", severity=Severity.MEDIUM,
                            remediation="Fix medium")
        groups = FindingGrouper().group([f_low, f_critical, f_medium])
        assert groups[0].severity == Severity.CRITICAL
        assert groups[-1].severity == Severity.LOW


class TestFindingGrouperAffectedUrls:
    def test_affected_url_count_correct(self) -> None:
        findings = [
            _finding(location=f"https://example.com/page{i}") for i in range(5)
        ]
        groups = FindingGrouper().group(findings)
        assert len(groups) == 1
        assert groups[0].affected_url_count == 5

    def test_affected_urls_contains_sample_urls(self) -> None:
        urls = [f"https://example.com/p{i}" for i in range(5)]
        findings = [_finding(location=u) for u in urls]
        groups = FindingGrouper().group(findings)
        assert len(groups[0].affected_urls) == 5
        assert set(groups[0].affected_urls) == set(urls)

    def test_affected_urls_capped_at_ten(self) -> None:
        findings = [_finding(location=f"https://example.com/p{i}") for i in range(15)]
        groups = FindingGrouper().group(findings)
        assert groups[0].affected_url_count == 15
        assert len(groups[0].affected_urls) == 10

    def test_evidence_count_equals_total_raw_findings(self) -> None:
        findings = [_finding(location=f"https://example.com/p{i}") for i in range(8)]
        groups = FindingGrouper().group(findings)
        assert groups[0].evidence_count == 8

    def test_duplicate_url_counted_once(self) -> None:
        f1 = _finding(location="https://example.com/")
        f2 = _finding(location="https://example.com/")
        groups = FindingGrouper().group([f1, f2])
        assert groups[0].affected_url_count == 1
        assert groups[0].evidence_count == 2


class TestFindingGrouperQuality:
    def test_confidence_is_max_of_group(self) -> None:
        f1 = _finding(confidence=0.6)
        f2 = _finding(confidence=0.9, location="https://example.com/about")
        f3 = _finding(confidence=0.7, location="https://example.com/contact")
        groups = FindingGrouper().group([f1, f2, f3])
        assert groups[0].confidence == pytest.approx(0.9)

    def test_anomaly_score_is_max_of_group(self) -> None:
        f1 = _finding(anomaly_score=0.3, location="https://example.com/")
        f2 = _finding(anomaly_score=0.8, location="https://example.com/about")
        groups = FindingGrouper().group([f1, f2])
        assert groups[0].anomaly_score == pytest.approx(0.8)

    def test_anomaly_score_none_when_no_scores(self) -> None:
        f = _finding()
        groups = FindingGrouper().group([f])
        assert groups[0].anomaly_score is None

    def test_finding_ids_preserved(self) -> None:
        f1 = _finding(location="https://example.com/")
        f2 = _finding(location="https://example.com/about")
        groups = FindingGrouper().group([f1, f2])
        assert str(f1.id) in groups[0].finding_ids
        assert str(f2.id) in groups[0].finding_ids

    def test_framework_alignment_from_first_finding(self) -> None:
        f1 = _finding(owasp=["A05:2021"], location="https://example.com/")
        f2 = _finding(owasp=["A05:2021"], location="https://example.com/about")
        groups = FindingGrouper().group([f1, f2])
        assert groups[0].framework.owasp_top10 == ["A05:2021"]

    def test_severity_preserved(self) -> None:
        f1 = _finding(severity=Severity.HIGH, location="https://example.com/")
        f2 = _finding(severity=Severity.HIGH, location="https://example.com/about")
        groups = FindingGrouper().group([f1, f2])
        assert groups[0].severity == Severity.HIGH

    def test_remediation_preserved(self) -> None:
        f = _finding(remediation="Use a strict CSP policy.")
        groups = FindingGrouper().group([f])
        assert groups[0].remediation == "Use a strict CSP policy."


# ---------------------------------------------------------------------------
# Per-URL engine isolation — sensitive paths + compromise + WADE
# ---------------------------------------------------------------------------


class TestPerUrlEngineIsolation:
    def test_sensitive_paths_stays_separate_per_url(self) -> None:
        f1 = _finding(title="Sensitive Path", engine="sensitive_paths",
                      category=FindingCategory.RECON,
                      location="https://example.com/.env")
        f2 = _finding(title="Sensitive Path", engine="sensitive_paths",
                      category=FindingCategory.RECON,
                      location="https://example.com/wp-admin")
        groups = FindingGrouper().group([f1, f2])
        assert len(groups) == 2

    def test_injected_js_stays_separate_per_url(self) -> None:
        f1 = _finding(title="Injected JS", engine="injected_js",
                      category=FindingCategory.COMPROMISE,
                      location="https://example.com/")
        f2 = _finding(title="Injected JS", engine="injected_js",
                      category=FindingCategory.COMPROMISE,
                      location="https://example.com/about")
        groups = FindingGrouper().group([f1, f2])
        assert len(groups) == 2

    def test_hidden_iframes_stays_separate_per_url(self) -> None:
        f1 = _finding(title="Hidden iFrame", engine="hidden_iframes",
                      location="https://example.com/page1")
        f2 = _finding(title="Hidden iFrame", engine="hidden_iframes",
                      location="https://example.com/page2")
        groups = FindingGrouper().group([f1, f2])
        assert len(groups) == 2

    def test_seo_spam_stays_separate_per_url(self) -> None:
        f1 = _finding(title="SEO Spam", engine="seo_spam",
                      location="https://example.com/p1")
        f2 = _finding(title="SEO Spam", engine="seo_spam",
                      location="https://example.com/p2")
        groups = FindingGrouper().group([f1, f2])
        assert len(groups) == 2

    def test_suspicious_redirects_stays_separate_per_url(self) -> None:
        f1 = _finding(title="Suspicious Redirect", engine="suspicious_redirects",
                      location="https://example.com/r1")
        f2 = _finding(title="Suspicious Redirect", engine="suspicious_redirects",
                      location="https://example.com/r2")
        groups = FindingGrouper().group([f1, f2])
        assert len(groups) == 2

    def test_wade_findings_stay_separate_per_url(self) -> None:
        f1 = _finding(title="New External Script Detected", engine="wade",
                      category=FindingCategory.JAVASCRIPT,
                      location="https://example.com/")
        f2 = _finding(title="New External Script Detected", engine="wade",
                      category=FindingCategory.JAVASCRIPT,
                      location="https://example.com/checkout")
        groups = FindingGrouper().group([f1, f2])
        assert len(groups) == 2

    def test_per_url_exact_duplicate_collapses(self) -> None:
        f1 = _finding(title="Injected JS", engine="injected_js",
                      location="https://example.com/")
        f2 = _finding(title="Injected JS", engine="injected_js",
                      location="https://example.com/")
        groups = FindingGrouper().group([f1, f2])
        assert len(groups) == 1
        assert groups[0].evidence_count == 2

    def test_per_url_engines_set_contains_expected_engines(self) -> None:
        expected = {"sensitive_paths", "injected_js", "hidden_iframes",
                    "seo_spam", "suspicious_redirects", "wade"}
        assert expected <= _PER_URL_ENGINES


# ---------------------------------------------------------------------------
# Risk scoring from grouped findings
# ---------------------------------------------------------------------------


class TestRiskScoringGrouped:
    def _result_with_grouped(self, groups: list[GroupedFinding]) -> ScanResult:
        r = ScanResult(target=_target())
        r.grouped_findings = groups
        r.severity_breakdown = SeverityBreakdown()
        return r

    def _grouped(self, severity: Severity, title: str = "Issue") -> GroupedFinding:
        return GroupedFinding(
            title=title,
            severity=severity,
            category=FindingCategory.SECURITY_HEADER,
            scanner_engine="security_headers",
            description="desc",
            affected_url_count=50,
            evidence_count=50,
        )

    def test_many_raw_medium_findings_score_fairly_when_grouped(self) -> None:
        # 24 raw medium findings → 1 grouped medium → much better score than raw
        raw_findings = [
            _finding(title="Missing CSP", location=f"https://example.com/p{i}")
            for i in range(24)
        ]
        result = _completed_result(raw_findings)
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        score, level = _compute_risk_score(result)
        # 1 grouped medium = -7 → score 93 → "low"
        assert score >= 90
        assert level == "low"

    def test_raw_severity_breakdown_used_when_no_groups(self) -> None:
        result = ScanResult(target=_target())
        result.severity_breakdown = SeverityBreakdown(medium=24)
        result.grouped_findings = []
        score, level = _compute_risk_score(result)
        # 24 mediums: min(24*7, 30) = 30 → score 70 → "medium"
        assert score == 70
        assert level == "medium"

    def test_grouped_score_uses_grouped_count(self) -> None:
        # 1 grouped MEDIUM
        g = self._grouped(Severity.MEDIUM)
        result = self._result_with_grouped([g])
        score, level = _compute_risk_score(result)
        assert score == 93
        assert level == "low"

    def test_many_grouped_mediums_still_capped(self) -> None:
        # Even 10 grouped MEDIUMs can't exceed the 30-point cap
        groups = [self._grouped(Severity.MEDIUM, f"Issue{i}") for i in range(10)]
        result = self._result_with_grouped(groups)
        score, level = _compute_risk_score(result)
        assert score == 70  # 100 - 30 (cap)
        assert level == "medium"

    def test_single_critical_grouped_forces_high_label(self) -> None:
        groups = [self._grouped(Severity.CRITICAL)]
        result = self._result_with_grouped(groups)
        score, level = _compute_risk_score(result)
        assert level in ("high", "critical")

    def test_breakdown_from_grouped_counts_per_severity(self) -> None:
        groups = [
            self._grouped(Severity.CRITICAL, "C1"),
            self._grouped(Severity.HIGH, "H1"),
            self._grouped(Severity.HIGH, "H2"),
            self._grouped(Severity.MEDIUM, "M1"),
        ]
        bd = _breakdown_from_grouped(groups)
        assert bd.critical == 1
        assert bd.high == 2
        assert bd.medium == 1
        assert bd.low == 0

    def test_info_findings_dont_affect_score(self) -> None:
        groups = [self._grouped(Severity.INFO, "Info Issue")]
        result = self._result_with_grouped(groups)
        score, level = _compute_risk_score(result)
        assert score == 100
        assert level == "low"

    def test_sensitive_path_findings_remain_in_grouped(self) -> None:
        f1 = _finding(title="Exposed .env", engine="sensitive_paths",
                      category=FindingCategory.RECON,
                      severity=Severity.HIGH,
                      location="https://example.com/.env")
        f2 = _finding(title="Exposed .env", engine="sensitive_paths",
                      category=FindingCategory.RECON,
                      severity=Severity.HIGH,
                      location="https://example.com/config/.env")
        groups = FindingGrouper().group([f1, f2])
        # Sensitive paths stay separate — 2 groups
        assert len(groups) == 2
        # Both are HIGH — risk scoring gets 2 HIGH findings
        bd = _breakdown_from_grouped(groups)
        assert bd.high == 2


# ---------------------------------------------------------------------------
# Raw findings still preserved
# ---------------------------------------------------------------------------


class TestRawFindingsPreserved:
    def test_raw_findings_still_in_result(self) -> None:
        f1 = _finding(location="https://example.com/")
        f2 = _finding(location="https://example.com/about")
        result = _completed_result([f1, f2])
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        assert len(result.findings) == 2
        assert len(result.grouped_findings) == 1

    def test_finding_ids_in_grouped_reference_raw(self) -> None:
        f1 = _finding(location="https://example.com/")
        f2 = _finding(location="https://example.com/about")
        result = _completed_result([f1, f2])
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        gf = result.grouped_findings[0]
        raw_ids = {str(f.id) for f in result.findings}
        assert set(gf.finding_ids) == raw_ids

    def test_engine_diagnostics_count_raw_findings(self) -> None:
        # Engine diagnostics use raw counts — grouping doesn't change them
        from webhound.core.engine_tracker import EngineTracker
        from datetime import datetime, timezone
        t = datetime(2025, 1, 1, tzinfo=timezone.utc)
        tracker = EngineTracker()
        findings = [_finding(location=f"https://example.com/p{i}") for i in range(5)]
        tracker.record_run("security_headers", findings, 10.0, t, t)
        statuses = tracker.build_statuses()
        assert statuses[0].findings_count == 5


# ---------------------------------------------------------------------------
# JSON report — grouped_findings section
# ---------------------------------------------------------------------------


class TestJsonReportGroupedFindings:
    def test_grouped_findings_key_present(self) -> None:
        result = _completed_result([])
        report = JsonReport().build(result)
        assert "grouped_findings" in report

    def test_grouped_findings_empty_when_no_findings(self) -> None:
        result = _completed_result([])
        report = JsonReport().build(result)
        assert report["grouped_findings"] == []

    def test_grouped_findings_populated(self) -> None:
        findings = [
            _finding(location=f"https://example.com/p{i}") for i in range(3)
        ]
        result = _completed_result(findings)
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        report = JsonReport().build(result)
        assert len(report["grouped_findings"]) == 1

    def test_grouped_finding_has_required_keys(self) -> None:
        f = _finding()
        result = _completed_result([f])
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        report = JsonReport().build(result)
        gf = report["grouped_findings"][0]
        for key in ("title", "severity", "category", "scanner_engine", "description",
                    "remediation", "affected_url_count", "affected_urls",
                    "evidence_count", "confidence", "anomaly_score",
                    "framework", "finding_ids"):
            assert key in gf, f"Missing key: {key}"

    def test_grouped_finding_affected_url_count(self) -> None:
        findings = [
            _finding(location=f"https://example.com/p{i}") for i in range(7)
        ]
        result = _completed_result(findings)
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        report = JsonReport().build(result)
        assert report["grouped_findings"][0]["affected_url_count"] == 7

    def test_grouped_finding_evidence_count(self) -> None:
        findings = [
            _finding(location=f"https://example.com/p{i}") for i in range(4)
        ]
        result = _completed_result(findings)
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        report = JsonReport().build(result)
        assert report["grouped_findings"][0]["evidence_count"] == 4

    def test_raw_findings_still_in_json(self) -> None:
        f1 = _finding(location="https://example.com/")
        f2 = _finding(location="https://example.com/about")
        result = _completed_result([f1, f2])
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        report = JsonReport().build(result)
        assert len(report["findings"]) == 2
        assert len(report["grouped_findings"]) == 1

    def test_multiple_groups_in_json(self) -> None:
        f_header = _finding(title="Missing CSP", engine="security_headers",
                            location="https://example.com/")
        f_cookie = _finding(title="Missing Secure Flag", engine="cookie_scanner",
                            category=FindingCategory.COOKIE, remediation="Add Secure flag.",
                            location="https://example.com/")
        f_cors = _finding(title="Permissive CORS", engine="cors",
                          category=FindingCategory.CORS, remediation="Restrict origins.",
                          location="https://example.com/")
        result = _completed_result([f_header, f_cookie, f_cors])
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        report = JsonReport().build(result)
        assert len(report["grouped_findings"]) == 3

    def test_framework_in_grouped_json(self) -> None:
        f = _finding(owasp=["A05:2021"])
        result = _completed_result([f])
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        report = JsonReport().build(result)
        fw = report["grouped_findings"][0]["framework"]
        assert "owasp_top10" in fw
        assert fw["owasp_top10"] == ["A05:2021"]


# ---------------------------------------------------------------------------
# Summary report — grouped findings
# ---------------------------------------------------------------------------


class TestSummaryBuilderGrouped:
    def test_top_findings_section_present(self) -> None:
        f = _finding()
        result = _completed_result([f])
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        summary = SummaryBuilder().build(result)
        assert "Top Findings:" in summary

    def test_grouped_title_in_summary(self) -> None:
        f = _finding(title="Missing Content-Security-Policy")
        result = _completed_result([f])
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        summary = SummaryBuilder().build(result)
        assert "Missing Content-Security-Policy" in summary

    def test_multi_page_issue_shows_page_count(self) -> None:
        findings = [
            _finding(title="Missing CSP", location=f"https://example.com/p{i}")
            for i in range(5)
        ]
        result = _completed_result(findings)
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        summary = SummaryBuilder().build(result)
        assert "5 pages" in summary

    def test_single_page_issue_no_page_count(self) -> None:
        f = _finding()
        result = _completed_result([f])
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        summary = SummaryBuilder().build(result)
        assert "1 pages" not in summary

    def test_fallback_to_active_findings_when_no_groups(self) -> None:
        f = _finding(title="Fallback Finding")
        result = _completed_result([f])
        # Don't populate grouped_findings
        summary = SummaryBuilder().build(result)
        assert "Fallback Finding" in summary
        assert "Top Findings:" in summary

    def test_compromise_findings_visible_in_summary(self) -> None:
        f1 = _finding(title="Injected JS Detected", engine="injected_js",
                      severity=Severity.HIGH, category=FindingCategory.COMPROMISE,
                      location="https://example.com/page1")
        f2 = _finding(title="Injected JS Detected", engine="injected_js",
                      severity=Severity.HIGH, category=FindingCategory.COMPROMISE,
                      location="https://example.com/page2")
        result = _completed_result([f1, f2])
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        summary = SummaryBuilder().build(result)
        # Two separate per-URL groups — both should appear (top 10)
        assert summary.count("Injected JS Detected") == 2

    def test_severity_label_in_summary(self) -> None:
        f = _finding(severity=Severity.HIGH)
        result = _completed_result([f])
        result.grouped_findings = FindingGrouper().group(result.active_findings)
        summary = SummaryBuilder().build(result)
        assert "[HIGH]" in summary


# ---------------------------------------------------------------------------
# Scanner integration — grouped findings populated after full scan
# ---------------------------------------------------------------------------


class TestScannerGroupingIntegration:
    @pytest.mark.anyio
    async def test_grouped_findings_populated_after_scan(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        assert isinstance(result.grouped_findings, list)

    @pytest.mark.anyio
    async def test_raw_findings_still_present_after_scan(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        raw_count = len(result.findings)
        grouped_count = sum(g.evidence_count for g in result.grouped_findings)
        # Every raw finding should be referenced by a group
        assert grouped_count == len(result.active_findings)
        assert raw_count >= 0  # raw preserved

    @pytest.mark.anyio
    async def test_grouped_count_lte_raw_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        assert len(result.grouped_findings) <= len(result.active_findings)

    @pytest.mark.anyio
    async def test_risk_score_uses_grouped_not_raw(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        # Verify the stored risk_score used grouped findings
        stored_score = result.metadata.get("risk_score", 100)
        # Recompute manually with grouped — should match
        recomputed, _ = _compute_risk_score(result)
        assert stored_score == recomputed

    @pytest.mark.anyio
    async def test_json_report_has_grouped_findings_after_scan(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        report = JsonReport().build(result)
        assert "grouped_findings" in report
        assert isinstance(report["grouped_findings"], list)
