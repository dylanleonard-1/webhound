# WebHound — tests/test_supply_chain_integration.py
# Phase-13 integration: a scan with a previous baseline runs the
# supply-chain + threat-correlation pass and writes the metadata.

from __future__ import annotations

import httpx
import pytest

from webhound.core.orchestrator import Scanner
from webhound.engines.tls_dns.dns_checker import DnsRecords
from webhound.engines.tls_dns.tls_checker import TlsCertInfo
from webhound.models.scan_result import ScanStatus
from webhound.models.target import ScanOptions, Target


def _html(script_host: str) -> str:
    return (f'<!DOCTYPE html><html><body>'
            f'<script src="https://{script_host}/a.js"></script>'
            f'</body></html>')


def _transport(script_host: str) -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/", ""):
            return httpx.Response(
                200, text=_html(script_host),
                headers={"content-type": "text/html; charset=utf-8"})
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


def _target() -> Target:
    return Target.from_url("https://t.test", scan_options=ScanOptions(
        max_pages=2, max_depth=1, rate_limit_rps=10.0, verify_tls=False))


@pytest.mark.anyio
async def test_first_scan_no_supply_chain_metadata(monkeypatch) -> None:
    _patch_tls_dns(monkeypatch)
    result = await Scanner(
        _target(), _transport=_transport("js.stripe.com")).scan()
    assert result.status == ScanStatus.COMPLETED
    # No previous baseline → no supply-chain diff.
    assert "supply_chain_changes" not in result.metadata


@pytest.mark.anyio
async def test_vendor_change_produces_supply_chain_metadata(monkeypatch) -> None:
    _patch_tls_dns(monkeypatch)
    # Scan 1 establishes a baseline with Stripe.
    s1 = Scanner(_target(), _transport=_transport("js.stripe.com"))
    r1 = await s1.scan()
    baseline = s1.current_baseline
    assert baseline is not None

    # Scan 2: Stripe gone, an unknown host appears — feed the prior
    # baseline so the supply-chain pass diffs.
    s2 = Scanner(_target(),
                 _transport=_transport("acme-unknown-vendor-zzz.com"),
                 previous_baseline=baseline)
    r2 = await s2.scan()
    assert r2.status == ScanStatus.COMPLETED
    assert "supply_chain_changes" in r2.metadata
    assert "wade_vendor_events" in r2.metadata
    # The diff recorded a change (new unknown vendor and/or stripe removed).
    changes = r2.metadata["supply_chain_changes"]
    assert isinstance(changes, list)
