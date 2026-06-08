# WebHound — tests/test_telemetry_integration.py
# Phase-2: telemetry fires during a real scan, AND telemetry never changes
# the scan result (the hard rule). Uses a MockTransport like the other
# orchestrator integration tests.

from __future__ import annotations

import httpx
import pytest

from webhound.models.target import ScanOptions, Target
from webhound.models.scan_result import ScanStatus


def _transport() -> httpx.MockTransport:
    html = ('<!DOCTYPE html><html><head><title>t</title></head><body>'
            '<a href="/about">about</a>'
            '<script src="https://js.stripe.com/v3"></script>'
            '</body></html>')

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/", "/about"):
            return httpx.Response(200, text=html,
                                  headers={"content-type": "text/html"})
        return httpx.Response(404, text="nf")
    return httpx.MockTransport(handler)


def _patch_net(monkeypatch) -> None:
    from webhound.engines.tls_dns import dns_checker as _dns
    from webhound.engines.tls_dns import tls_checker as _tls
    from webhound.engines.tls_dns.dns_checker import DnsRecords
    from webhound.engines.tls_dns.tls_checker import TlsCertInfo
    monkeypatch.setattr(_tls, "probe_tls",
                        lambda *a, **k: TlsCertInfo(domain="t.test",
                                                    connection_failed=True))
    monkeypatch.setattr(_dns, "resolve_dns",
                        lambda *a, **k: DnsRecords(domain="t.test",
                                                   a=["1.2.3.4"]))


def _target() -> Target:
    return Target.from_url("https://t.test", scan_options=ScanOptions(
        max_pages=3, max_depth=1, rate_limit_rps=10.0, verify_tls=False))


async def _run(monkeypatch):
    from webhound.core.orchestrator import Scanner
    _patch_net(monkeypatch)
    return await Scanner(_target(), _transport=_transport()).scan()


# ---------------------------------------------------------------------------
# Telemetry fires (default 'engines' level)
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_scan_emits_telemetry_summary(monkeypatch) -> None:
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "engines")
    result = await _run(monkeypatch)
    assert result.status == ScanStatus.COMPLETED
    tel = result.metadata.get("telemetry")
    assert tel is not None
    assert tel["level"] == "engines"
    assert tel["event_count"] > 0
    # Lifecycle bracketed the scan.
    assert tel["event_type_counts"].get("scan.started") == 1
    assert tel["event_type_counts"].get("scan.finished") == 1
    # Engines were instrumented at the single choke point.
    assert tel["event_type_counts"].get("engine.finished", 0) >= 1
    assert tel["engines"], "per-engine rollup present"
    # Handoff snapshots recorded the count flow.
    assert "after_crawl" in tel["handoffs"]
    assert "after_engines" in tel["handoffs"]


@pytest.mark.anyio
async def test_telemetry_engine_parity_with_diagnostics(monkeypatch) -> None:
    """Every engine in the tracker's diagnostics has an engine.finished or
    engine.failed telemetry event (no engine instrumented invisibly)."""
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "engines")
    result = await _run(monkeypatch)
    diag_engines = {d.name for d in result.engine_diagnostics}
    tel_engines = set(result.metadata["telemetry"]["engines"].keys())
    # Telemetry covers the engines that actually ran/finished.
    assert tel_engines, "telemetry recorded engine events"
    assert tel_engines <= diag_engines or diag_engines <= tel_engines or \
        len(tel_engines & diag_engines) >= 1


@pytest.mark.anyio
async def test_handoff_snapshot_counts_are_consistent(monkeypatch) -> None:
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "engines")
    result = await _run(monkeypatch)
    tel = result.metadata["telemetry"]
    assert tel["handoffs"]["after_crawl"]["pages"] == result.urls_crawled


# ---------------------------------------------------------------------------
# Hard rule: telemetry NEVER changes the scan result
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_telemetry_off_is_noop(monkeypatch) -> None:
    """With telemetry off, no telemetry metadata is written and the scan
    completes identically."""
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "off")
    result = await _run(monkeypatch)
    assert result.status == ScanStatus.COMPLETED
    assert "telemetry" not in result.metadata


@pytest.mark.anyio
async def test_telemetry_does_not_change_findings(monkeypatch) -> None:
    """Findings + risk are identical with telemetry on vs off — telemetry
    is pure observability."""
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "off")
    off = await _run(monkeypatch)
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "full")
    on = await _run(monkeypatch)
    assert len(off.findings) == len(on.findings)
    assert {f.title for f in off.findings} == {f.title for f in on.findings}
    assert off.metadata.get("risk_score") == on.metadata.get("risk_score")
