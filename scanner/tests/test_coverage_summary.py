# WebHound — tests/test_coverage_summary.py
# Phase-6C Task 9: consolidated coverage summary + browser-failure
# resilience. End-to-end through Scanner.scan() with a mock transport
# — no Playwright, no network.

from __future__ import annotations

import httpx
import pytest

from webhound.core.orchestrator import Scanner
from webhound.engines.tls_dns.dns_checker import DnsRecords
from webhound.engines.tls_dns.tls_checker import TlsCertInfo
from webhound.models.scan_result import ScanStatus
from webhound.models.target import ScanOptions, Target

_HTML = (
    "<!DOCTYPE html><html><head><title>T</title></head><body>"
    "<script src='https://cdn.vendor.com/lib.js'></script>"
    "<form action='/contact' method='post'>"
    "<input type='text' name='q'></form>"
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
                                    connection_failed=True),
    )
    monkeypatch.setattr(
        _dns, "resolve_dns",
        lambda *a, **k: DnsRecords(domain="example.com",
                                   a=["93.184.216.34"]),
    )


def _target(browser_enabled: bool = False) -> Target:
    opts = ScanOptions(
        max_pages=3, max_depth=1, rate_limit_rps=10.0,
        verify_tls=False, browser_enabled=browser_enabled,
    )
    return Target.from_url("https://example.com", scan_options=opts)


@pytest.mark.anyio
async def test_coverage_summary_present_on_static_scan(monkeypatch) -> None:
    """Static-only scans get a coverage summary with browser fields
    zeroed and browser_pass_available=False — non-breaking metadata."""
    _patch_tls_dns(monkeypatch)
    scanner = Scanner(_target(), _transport=_transport())
    result = await scanner.scan()

    assert result.status == ScanStatus.COMPLETED
    cov = result.metadata["coverage_summary"]
    assert cov["pages_crawled"] >= 1
    assert cov["static_scripts_collected"] >= 1
    assert cov["static_forms_discovered"] == 1
    assert cov["browser_pages_rendered"] == 0
    assert cov["rendered_forms_discovered"] == 0
    assert cov["browser_pass_available"] is False


@pytest.mark.anyio
async def test_browser_failure_never_fails_scan(monkeypatch) -> None:
    """Task-10 #6: profile wants the browser, operator env is off →
    the pass defers; the scan still completes with full static
    results and the deferral is visible in coverage."""
    _patch_tls_dns(monkeypatch)
    monkeypatch.delenv("WEBHOUND_BROWSER_ENABLED", raising=False)
    scanner = Scanner(_target(browser_enabled=True),
                      _transport=_transport())
    result = await scanner.scan()

    assert result.status == ScanStatus.COMPLETED
    assert result.metadata["coverage_summary"]["browser_pass_available"] \
        is False
    # Static findings still produced (headers engine etc. ran).
    assert result.findings


@pytest.mark.anyio
async def test_standard_and_deep_profiles_request_browser() -> None:
    """Task 2: standard/deep include browser discovery when available;
    quick/monitor stay static-only."""
    from webhound.core.scan_profiles import get_profile
    assert get_profile("standard").browser_enabled is True
    assert get_profile("deep").browser_enabled is True
    assert get_profile("enterprise").browser_enabled is True
    assert get_profile("quick").browser_enabled is False
    assert get_profile("monitor").browser_enabled is False
