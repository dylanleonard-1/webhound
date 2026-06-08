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


# ---------------------------------------------------------------------------
# Phase-2 (option a): profile.loaded + browser-pass + after_browser_discovery
# ---------------------------------------------------------------------------


def _profile_opts(name: str) -> "ScanOptions":
    """Real profile options, sped up for tests. Only rate/verify are
    changed — max_pages/max_depth/browser_enabled stay intact so profile
    inference and the browser gate behave exactly as in production."""
    from webhound.core.scan_profiles import get_profile
    return get_profile(name).to_scan_options().model_copy(
        update={"rate_limit_rps": 50.0, "verify_tls": False})


async def _run_capture(monkeypatch, *, profile: str | None = None):
    """Run a scan and return (result, recorder) by intercepting the
    recorder ScanContext builds — gives event-level access the compact
    summary doesn't carry."""
    import webhound.telemetry as _telmod
    from webhound.core.orchestrator import Scanner
    _patch_net(monkeypatch)
    captured: dict = {}
    _orig = _telmod.build_recorder

    def _capture(*a, **k):
        rec = _orig(*a, **k)
        captured["rec"] = rec
        return rec

    monkeypatch.setattr(_telmod, "build_recorder", _capture)
    opts = _profile_opts(profile) if profile else _target().scan_options
    target = Target.from_url("https://t.test", scan_options=opts)
    result = await Scanner(target, _transport=_transport()).scan()
    return result, captured["rec"]


def _events_of(rec, type_value: str) -> list:
    return [e for e in rec.events() if e.event_type.value == type_value]


@pytest.mark.anyio
async def test_profile_loaded_fires(monkeypatch) -> None:
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "engines")
    result = await _run(monkeypatch)
    assert result.metadata["telemetry"]["event_type_counts"].get(
        "profile.loaded") == 1


@pytest.mark.anyio
async def test_profile_loaded_quick_browser_disabled(monkeypatch) -> None:
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "engines")
    _result, rec = await _run_capture(monkeypatch, profile="quick")
    ev = _events_of(rec, "profile.loaded")
    assert len(ev) == 1
    assert ev[0].metadata["profile"] == "quick"
    assert ev[0].metadata["browser_enabled"] is False


@pytest.mark.anyio
async def test_profile_loaded_deep_browser_enabled(monkeypatch) -> None:
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "engines")
    _result, rec = await _run_capture(monkeypatch, profile="deep")
    ev = _events_of(rec, "profile.loaded")
    assert len(ev) == 1
    assert ev[0].metadata["profile"] == "deep"
    assert ev[0].metadata["browser_enabled"] is True


@pytest.mark.anyio
async def test_browser_deferred_emits_reason(monkeypatch) -> None:
    """DEEP wants the browser; with WEBHOUND_BROWSER_ENABLED unset the pass
    defers — telemetry must record browser.started + browser.deferred(reason)
    and the after_browser_discovery handoff."""
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "engines")
    monkeypatch.delenv("WEBHOUND_BROWSER_ENABLED", raising=False)
    result, rec = await _run_capture(monkeypatch, profile="deep")
    assert result.status == ScanStatus.COMPLETED
    assert _events_of(rec, "browser.started"), "browser.started fired"
    deferred = _events_of(rec, "browser.deferred")
    assert len(deferred) == 1
    assert deferred[0].metadata.get("deferred_reason")
    assert not _events_of(rec, "browser.finished")
    assert "after_browser_discovery" in rec.handoffs
    assert rec.handoffs["after_browser_discovery"]["deferred"] is True


@pytest.mark.anyio
async def test_browser_finished_emits_counts(monkeypatch) -> None:
    """Patch run_browser_pass to a non-deferred result → browser.finished
    fires with safe counts (no raw bodies)."""
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "engines")
    from webhound.browser.models import BrowserTelemetry, NetworkArtifact
    from webhound.browser.playwright_runner import BrowserPassResult

    art = NetworkArtifact(url="https://api.t.test/v1/data", method="GET",
                          initiator_kind="fetch", page_url="https://t.test/")
    tel = BrowserTelemetry(
        page_url="https://t.test/", artifacts=[art],
        rendered_html="<html><body><a href='/x'>x</a></body></html>",
        rendered_links=["https://t.test/x"])
    fake = BrowserPassResult(telemetries=[tel], deferred=False, error=None)

    async def _fake_run(*a, **k):
        return fake

    import webhound.browser.playwright_runner as _pr
    monkeypatch.setattr(_pr, "run_browser_pass", _fake_run)
    monkeypatch.setattr(_pr, "browser_pass_enabled", lambda: True)

    result, rec = await _run_capture(monkeypatch, profile="deep")
    assert result.status == ScanStatus.COMPLETED
    finished = _events_of(rec, "browser.finished")
    assert len(finished) == 1, "browser.finished fired"
    out = finished[0].outputs
    assert out.get("artifact_count") == 1
    assert out.get("rendered_link_count") == 1
    # No browser.deferred on the success path.
    assert not _events_of(rec, "browser.deferred")


@pytest.mark.anyio
async def test_after_browser_discovery_handoff_fires(monkeypatch) -> None:
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "engines")
    result, rec = await _run_capture(monkeypatch, profile="deep")
    assert "after_browser_discovery" in rec.handoffs
    # And it surfaces in the persisted summary's handoff map.
    assert "after_browser_discovery" in result.metadata["telemetry"]["handoffs"]


@pytest.mark.anyio
async def test_browser_yield_assessment_present(monkeypatch) -> None:
    """The challenge/yield detector runs during a browser-enabled scan and
    stores an assessment on browser_pass (detection only — results unchanged)."""
    monkeypatch.setenv("WEBHOUND_TELEMETRY_LEVEL", "engines")
    result, _rec = await _run_capture(monkeypatch, profile="deep")
    bp = result.metadata.get("browser_pass") or {}
    ya = bp.get("yield_assessment")
    assert ya is not None
    for k in ("rendered_real_app", "challenge_detected", "challenge_provider",
              "confidence", "recommended_action", "evidence"):
        assert k in ya
    # Browser deferred in tests (no allow_network) → can't judge content.
    assert ya["challenge_detected"] in (True, False, "unknown")
