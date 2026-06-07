# WebHound — tests/test_advisor_integration.py
# Phase-15: a full scan produces metadata.advisor.

from __future__ import annotations

import httpx
import pytest

from webhound.core.orchestrator import Scanner
from webhound.engines.tls_dns.dns_checker import DnsRecords
from webhound.engines.tls_dns.tls_checker import TlsCertInfo
from webhound.models.scan_result import ScanStatus
from webhound.models.target import ScanOptions, Target

# A page with a session cookie missing flags → real findings to advise on.
_HTML = "<!DOCTYPE html><html><body><h1>hi</h1></body></html>"


def _transport() -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/", ""):
            return httpx.Response(
                200, text=_HTML,
                headers={"content-type": "text/html; charset=utf-8",
                         "set-cookie": "sessionid=abc; Path=/"})
        return httpx.Response(404, text="nf")
    return httpx.MockTransport(handler)


def _patch_tls_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    from webhound.engines.tls_dns import dns_checker as _dns
    from webhound.engines.tls_dns import tls_checker as _tls
    monkeypatch.setattr(_tls, "probe_tls",
                        lambda *a, **k: TlsCertInfo(domain="t.test",
                                                    connection_failed=True))
    monkeypatch.setattr(_dns, "resolve_dns",
                        lambda *a, **k: DnsRecords(domain="t.test",
                                                   a=["1.2.3.4"]))


@pytest.mark.anyio
async def test_scan_produces_advisor_metadata(monkeypatch) -> None:
    _patch_tls_dns(monkeypatch)
    t = Target.from_url("https://t.test", scan_options=ScanOptions(
        max_pages=2, max_depth=1, rate_limit_rps=10.0, verify_tls=False))
    result = await Scanner(t, _transport=_transport()).scan()

    assert result.status == ScanStatus.COMPLETED
    advisor = result.metadata.get("advisor")
    assert advisor is not None
    # Core advisory sections present.
    for key in ("findings", "priorities", "action_plan",
                "remediation_roadmap", "qa"):
        assert key in advisor
    # The cookie finding got a four-part explanation.
    cookie_advice = [f for f in advisor["findings"]
                     if "cookie" in f["title"].lower()]
    assert cookie_advice
    assert cookie_advice[0]["explanation"]["what_should_be_done"]
    # Q&A answers the common questions.
    assert "is_this_serious" in advisor["qa"]
    assert "did_my_website_get_hacked" in advisor["qa"]
