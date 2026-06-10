# WebHound — tests/test_identity.py
# Phase 3.3 Scanner Identity. Offline. The telemetry test runs a real scan via a
# MockTransport (same pattern as test_telemetry_integration).

from __future__ import annotations

import httpx
import pytest

from webhound.identity import (
    SCANNER_IDENTITY_UPDATED,
    SCANNER_NAME,
    SCANNER_USER_AGENT,
    SCANNER_VERSION,
    identity_dict,
)


def test_identity_constants():
    assert SCANNER_NAME == "WebHoundScanner"
    assert SCANNER_VERSION == "1.0"
    assert SCANNER_USER_AGENT.startswith("WebHoundScanner/1.0")
    assert "+https://webhoundsecurity.com/scanner" in SCANNER_USER_AGENT


def test_user_agent_consistent_across_scanner():
    # One identity — the HTTP client constant and the ScanOptions default must
    # both resolve to the single source of truth.
    from webhound.core.http_client import WEBHOUND_USER_AGENT
    from webhound.models.target import ScanOptions
    assert WEBHOUND_USER_AGENT == SCANNER_USER_AGENT
    assert ScanOptions().user_agent == SCANNER_USER_AGENT


def test_identity_dict_safe_public_fields_only():
    d = identity_dict()
    assert d["scanner_name"] == "WebHoundScanner"
    assert d["scanner_version"] == "1.0"
    assert d["user_agent"] == SCANNER_USER_AGENT
    for k in ("verification_url", "docs_url", "ip_ranges_url", "contact"):
        assert d[k].strip()
    # No secrets / internal infrastructure may leak through the public identity.
    blob = repr(d).lower()
    for bad in ("secret", "token", "password", "api_key", "apikey", "railway",
                "database", "redis", "stripe", "internal", "env="):
        assert bad not in blob


def test_identity_updated_event_name():
    assert SCANNER_IDENTITY_UPDATED == "scanner.identity.updated"


def test_ua_is_honest_not_browser_spoof():
    # Honest identification — must NOT masquerade as a real browser/crawler.
    ua = SCANNER_USER_AGENT.lower()
    for browsery in ("mozilla", "chrome", "safari", "gecko", "applewebkit", "bingbot", "googlebot"):
        assert browsery not in ua


# --- telemetry: a scan stamps the identity onto result metadata ------------

def _transport() -> httpx.MockTransport:
    html = "<!DOCTYPE html><html><head><title>t</title></head><body>ok</body></html>"

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})
    return httpx.MockTransport(handler)


def _patch_net(monkeypatch) -> None:
    from webhound.engines.tls_dns import dns_checker as _dns
    from webhound.engines.tls_dns import tls_checker as _tls
    from webhound.engines.tls_dns.dns_checker import DnsRecords
    from webhound.engines.tls_dns.tls_checker import TlsCertInfo
    monkeypatch.setattr(_tls, "probe_tls",
                        lambda *a, **k: TlsCertInfo(domain="t.test", connection_failed=True))
    monkeypatch.setattr(_dns, "resolve_dns",
                        lambda *a, **k: DnsRecords(domain="t.test", a=["1.2.3.4"]))


@pytest.mark.anyio
async def test_scan_metadata_includes_scanner_identity(monkeypatch):
    from webhound.core.orchestrator import Scanner
    from webhound.models.target import ScanOptions, Target
    _patch_net(monkeypatch)
    target = Target.from_url("https://t.test", scan_options=ScanOptions(
        max_pages=2, max_depth=1, rate_limit_rps=10.0, verify_tls=False))
    result = await Scanner(target, _transport=_transport()).scan()
    ident = result.metadata.get("scanner_identity")
    assert ident is not None
    assert ident["user_agent"] == SCANNER_USER_AGENT
    assert ident["scanner_name"] == "WebHoundScanner"
