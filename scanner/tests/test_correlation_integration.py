# WebHound — tests/test_correlation_integration.py
# Phase-8 end-to-end: security stories flow through Scanner.scan() into
# metadata, annotate grouped findings, and do not inflate the risk
# score. Mock transport — no network, no Playwright.

from __future__ import annotations

import httpx
import pytest

from webhound.core.orchestrator import Scanner, _compute_risk_score
from webhound.core.security_stories import build_security_stories
from webhound.engines.tls_dns.dns_checker import DnsRecords
from webhound.engines.tls_dns.tls_checker import TlsCertInfo
from webhound.models.finding import FindingCategory
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.scan_result import ScanResult, ScanStatus
from webhound.models.severity import Severity
from webhound.models.target import ScanOptions, Target


_HTML = (
    "<!DOCTYPE html><html><head><title>T</title></head><body>"
    "<form action='/login' method='post'>"
    "<input type='text' name='user'>"
    "<input type='password' name='pass'></form>"
    "<p>hi</p></body></html>"
)


def _transport() -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/", ""):
            return httpx.Response(
                200, text=_HTML,
                headers={"content-type": "text/html; charset=utf-8"},
            )
        return httpx.Response(404, text="Not Found")
    return httpx.MockTransport(handler)


def _patch_tls_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    from webhound.engines.tls_dns import dns_checker as _dns
    from webhound.engines.tls_dns import tls_checker as _tls
    monkeypatch.setattr(
        _tls, "probe_tls",
        lambda *a, **k: TlsCertInfo(domain="example.com",
                                    connection_failed=True))
    monkeypatch.setattr(
        _dns, "resolve_dns",
        lambda *a, **k: DnsRecords(domain="example.com",
                                   a=["93.184.216.34"]))


def _target() -> Target:
    return Target.from_url("https://example.com", scan_options=ScanOptions(
        max_pages=3, max_depth=1, rate_limit_rps=10.0, verify_tls=False))


@pytest.mark.anyio
async def test_scan_emits_security_stories_metadata(monkeypatch) -> None:
    _patch_tls_dns(monkeypatch)
    result = await Scanner(_target(), _transport=_transport()).scan()
    assert result.status == ScanStatus.COMPLETED
    assert "security_stories" in result.metadata
    assert "security_story_count" in result.metadata
    # Stories is a list of dicts with the standardized shape.
    for s in result.metadata["security_stories"]:
        assert "correlation_type" in s
        assert "confidence" in s
        assert "title" in s


def _gf(title, *, engine, category, severity=Severity.MEDIUM,
        finding_type="likely_risk") -> GroupedFinding:
    return GroupedFinding(
        title=title, severity=severity, category=category,
        scanner_engine=engine, description="d",
        metadata={"finding_type": finding_type,
                  "confidence_label": "high"},
        affected_urls=["https://t.test/"])


def test_correlation_does_not_change_risk_score() -> None:
    """Task 10: building stories over a set of grouped findings must not
    change the score those same findings produce."""
    grouped = [
        _gf("Unexpected injected script", engine="injected_js",
            category=FindingCategory.COMPROMISE, severity=Severity.MEDIUM),
        _gf("Hidden iframe detected", engine="hidden_iframes",
            category=FindingCategory.COMPROMISE, severity=Severity.MEDIUM),
        _gf("Suspicious redirect", engine="suspicious_redirects",
            category=FindingCategory.COMPROMISE, severity=Severity.MEDIUM),
    ]
    r1 = ScanResult(target=Target.from_url("https://t.test/"))
    r1.grouped_findings = list(grouped)
    score_before, level_before = _compute_risk_score(r1)

    # Correlate (mutates grouped in place by annotating).
    stories = build_security_stories(grouped)
    assert stories  # a compromise story was built

    r2 = ScanResult(target=Target.from_url("https://t.test/"))
    r2.grouped_findings = list(grouped)
    score_after, level_after = _compute_risk_score(r2)

    assert score_after == score_before
    assert level_after == level_before


def test_annotations_survive_into_grouped_metadata() -> None:
    grouped = [
        _gf("Login form", engine="form_risk", category=FindingCategory.FORM),
        _gf("Auth API referenced", engine="endpoint_discovery",
            category=FindingCategory.API),
        _gf("Session cookie missing HttpOnly", engine="cookie_scanner",
            category=FindingCategory.COOKIE),
    ]
    build_security_stories(grouped)
    annotated = [g for g in grouped if g.correlation_id is not None]
    assert annotated
    for g in annotated:
        assert g.correlation_type
        assert g.correlation_confidence
