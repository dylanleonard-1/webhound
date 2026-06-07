# WebHound — tests/test_framework_integration.py
# Phase-9 end-to-end: framework detection flows through Scanner.scan()
# into metadata.frameworks. Mock transport — no network, no Playwright.

from __future__ import annotations

import httpx
import pytest

from webhound.core.orchestrator import Scanner
from webhound.engines.tls_dns.dns_checker import DnsRecords
from webhound.engines.tls_dns.tls_checker import TlsCertInfo
from webhound.models.scan_result import ScanStatus
from webhound.models.target import ScanOptions, Target


_WORDPRESS_HTML = (
    '<!DOCTYPE html><html><head>'
    '<meta name="generator" content="WordPress 6.4.2">'
    '<link rel="https://api.w.org/" href="https://t.test/wp-json/">'
    '<script src="https://t.test/wp-includes/js/jquery.js"></script>'
    '</head><body class="wp-embed">'
    '<img src="/wp-content/uploads/2024/01/x.png"></body></html>'
)


def _transport(html: str, headers: dict | None = None) -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/", ""):
            h = {"content-type": "text/html; charset=utf-8"}
            h.update(headers or {})
            return httpx.Response(200, text=html, headers=h)
        return httpx.Response(404, text="Not Found")
    return httpx.MockTransport(handler)


def _patch_tls_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    from webhound.engines.tls_dns import dns_checker as _dns
    from webhound.engines.tls_dns import tls_checker as _tls
    monkeypatch.setattr(
        _tls, "probe_tls",
        lambda *a, **k: TlsCertInfo(domain="t.test", connection_failed=True))
    monkeypatch.setattr(
        _dns, "resolve_dns",
        lambda *a, **k: DnsRecords(domain="t.test", a=["93.184.216.34"]))


def _target() -> Target:
    return Target.from_url("https://t.test", scan_options=ScanOptions(
        max_pages=3, max_depth=1, rate_limit_rps=10.0, verify_tls=False))


@pytest.mark.anyio
async def test_scan_detects_wordpress(monkeypatch) -> None:
    _patch_tls_dns(monkeypatch)
    result = await Scanner(
        _target(),
        _transport=_transport(
            _WORDPRESS_HTML, headers={"x-powered-by": "WordPress"}),
    ).scan()

    assert result.status == ScanStatus.COMPLETED
    fw = result.metadata.get("frameworks")
    assert fw is not None
    assert fw["primary_framework"] == "WordPress"
    assert fw["primary_confidence_label"] in ("high", "confirmed")
    # WordPress known surface candidates present (inventory, not probed).
    assert "/wp-json/" in fw["known_surface"]["apis"]
    assert "/wp-admin/" in fw["known_surface"]["admin_paths"]
    assert "frameworks" in result.engines_run


@pytest.mark.anyio
async def test_plain_site_detects_no_framework(monkeypatch) -> None:
    _patch_tls_dns(monkeypatch)
    plain = ("<!DOCTYPE html><html><head><title>Plain</title></head>"
             "<body><h1>Just HTML</h1></body></html>")
    result = await Scanner(_target(), _transport=_transport(plain)).scan()

    fw = result.metadata.get("frameworks")
    assert fw is not None
    assert fw["primary_framework"] is None
    assert fw["detected"] == []
