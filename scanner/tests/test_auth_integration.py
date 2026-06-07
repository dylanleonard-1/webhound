# WebHound — tests/test_auth_integration.py
# Phase-10 end-to-end: Scanner builds an AuthContext, threads the
# browser auth_state, writes metadata.auth, and never leaks secrets.
# Mock transport — no Playwright (browser pass defers), so we verify the
# wiring + the public_only default + secret hygiene.

from __future__ import annotations

import httpx
import pytest

from webhound.auth import AuthMode, AuthSource
from webhound.core.orchestrator import Scanner
from webhound.engines.tls_dns.dns_checker import DnsRecords
from webhound.engines.tls_dns.tls_checker import TlsCertInfo
from webhound.models.scan_result import ScanStatus
from webhound.models.target import ScanOptions, Target

_HTML = "<!DOCTYPE html><html><body><h1>hi</h1></body></html>"


def _transport() -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/", ""):
            return httpx.Response(
                200, text=_HTML,
                headers={"content-type": "text/html; charset=utf-8"})
        return httpx.Response(404, text="Not Found")
    return httpx.MockTransport(handler)


def _patch_tls_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    from webhound.engines.tls_dns import dns_checker as _dns
    from webhound.engines.tls_dns import tls_checker as _tls
    monkeypatch.setattr(_tls, "probe_tls",
                        lambda *a, **k: TlsCertInfo(domain="example.com",
                                                    connection_failed=True))
    monkeypatch.setattr(_dns, "resolve_dns",
                        lambda *a, **k: DnsRecords(domain="example.com",
                                                   a=["93.184.216.34"]))


def _target(auth_mode="public_only") -> Target:
    return Target.from_url("https://example.com", scan_options=ScanOptions(
        max_pages=2, max_depth=1, rate_limit_rps=10.0, verify_tls=False,
        auth_mode=auth_mode))


@pytest.mark.anyio
async def test_public_only_scan_writes_empty_auth(monkeypatch) -> None:
    _patch_tls_dns(monkeypatch)
    result = await Scanner(_target(), _transport=_transport()).scan()
    assert result.status == ScanStatus.COMPLETED
    auth = result.metadata.get("auth")
    assert auth is not None
    assert auth["mode"] == "public_only"
    assert auth["source"] == "none"
    assert auth["available"] is False


@pytest.mark.anyio
async def test_authenticated_scan_builds_context_and_redacts(monkeypatch) -> None:
    _patch_tls_dns(monkeypatch)
    scanner = Scanner(
        _target(auth_mode="combined"), _transport=_transport(),
        auth_session_cookies=[{
            "name": "session", "value": "SUPER-SECRET-SESSION-VALUE",
            "domain": "example.com", "secure": True, "httpOnly": True}])
    result = await scanner.scan()

    auth = result.metadata["auth"]
    assert auth["source"] == "session_cookie"
    assert auth["mode"] == "combined"
    assert auth["cookie_count"] == 1
    assert auth["cookies"][0]["name"] == "session"
    assert auth["cookies"][0]["value_length"] == len("SUPER-SECRET-SESSION-VALUE")
    # The session VALUE must appear nowhere in the scan result.
    blob = result.to_json() if hasattr(result, "to_json") else str(result.metadata)
    assert "SUPER-SECRET-SESSION-VALUE" not in str(result.metadata)
    assert "SUPER-SECRET-SESSION-VALUE" not in blob


@pytest.mark.anyio
async def test_out_of_scope_cookie_yields_no_session(monkeypatch) -> None:
    _patch_tls_dns(monkeypatch)
    scanner = Scanner(
        _target(auth_mode="authenticated_only"), _transport=_transport(),
        auth_session_cookies=[{"name": "x", "value": "v",
                               "domain": "attacker.test"}])
    result = await scanner.scan()
    auth = result.metadata["auth"]
    assert auth["available"] is False
    assert auth["errors"]
