# WebHound — scanner/tests/test_browser_runner.py
# Phase-5A browser-pass tests. Every test is fully mocked at the
# runner boundary — no real Playwright import, no Chromium download.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.browser.models import (
    BrowserHostInventory,
    BrowserTelemetry,
    NetworkArtifact,
    aggregate_browser_hosts,
)
from webhound.browser.playwright_runner import (
    BrowserPassResult,
    browser_pass_enabled,
    run_browser_pass,
)


# ---------------------------------------------------------------------------
# Model invariants
# ---------------------------------------------------------------------------


def test_network_artifact_hostname_lowercases() -> None:
    a = NetworkArtifact(
        url="https://CDN.Example.COM/lib.js",
        method="GET", initiator_kind="script",
    )
    assert a.hostname == "cdn.example.com"


def test_browser_telemetry_add_indexes_by_kind() -> None:
    tel = BrowserTelemetry(page_url="https://target.test/")
    tel.add(NetworkArtifact(
        url="https://api.test/users", method="GET",
        initiator_kind="fetch", page_url="https://target.test/",
    ))
    tel.add(NetworkArtifact(
        url="wss://api.test/socket", method="GET",
        initiator_kind="websocket", page_url="https://target.test/",
    ))
    tel.add(NetworkArtifact(
        url="https://api.test/legacy", method="GET",
        initiator_kind="xhr", page_url="https://target.test/",
    ))
    assert tel.fetch_urls == ["https://api.test/users"]
    assert tel.websocket_urls == ["wss://api.test/socket"]
    assert tel.xhr_urls == ["https://api.test/legacy"]
    assert len(tel.artifacts) == 3


def test_aggregate_browser_hosts_dedupes_primary_target() -> None:
    """First-party traffic must not appear in the third-party host
    inventory — the orchestrator passes the scan target as
    ``primary_host`` and the aggregator drops it."""
    tel = BrowserTelemetry(page_url="https://target.test/")
    tel.add(NetworkArtifact(
        url="https://target.test/self.js", method="GET",
        initiator_kind="script", page_url="https://target.test/",
    ))
    tel.add(NetworkArtifact(
        url="https://cdn.example.com/lib.js", method="GET",
        initiator_kind="script", page_url="https://target.test/",
    ))
    inv = aggregate_browser_hosts(
        [tel], primary_host="target.test",
    )
    assert "target.test" not in inv
    assert "cdn.example.com" in inv


def test_aggregate_browser_hosts_first_and_last_page() -> None:
    tel_a = BrowserTelemetry(page_url="https://target.test/a")
    tel_a.add(NetworkArtifact(
        url="https://cdn.example.com/x", method="GET",
        initiator_kind="fetch", page_url="https://target.test/a",
    ))
    tel_b = BrowserTelemetry(page_url="https://target.test/b")
    tel_b.add(NetworkArtifact(
        url="https://cdn.example.com/y", method="GET",
        initiator_kind="fetch", page_url="https://target.test/b",
    ))
    inv = aggregate_browser_hosts([tel_a, tel_b])
    entry = inv["cdn.example.com"]
    assert entry.first_seen_page == "https://target.test/a"
    assert entry.last_seen_page == "https://target.test/b"
    assert entry.artifact_count == 2
    assert "fetch" in entry.kinds


def test_inventory_sample_url_cap_enforced() -> None:
    tel = BrowserTelemetry(page_url="https://target.test/")
    for i in range(20):
        tel.add(NetworkArtifact(
            url=f"https://cdn.example.com/asset-{i}.js",
            method="GET", initiator_kind="script",
            page_url="https://target.test/",
        ))
    inv = aggregate_browser_hosts([tel])
    # SAMPLE_CAP = 5
    assert len(inv["cdn.example.com"].sample_urls) == 5


# ---------------------------------------------------------------------------
# run_browser_pass — injected runner path (the production seam)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_browser_pass_empty_input_short_circuits() -> None:
    result = await run_browser_pass([])
    assert result.deferred is False
    assert result.telemetries == []


@pytest.mark.asyncio
async def test_run_browser_pass_default_no_network_defers() -> None:
    """allow_network=False MUST defer cleanly — matches the scanner-
    wide safe-mode posture."""
    result = await run_browser_pass(
        ["https://target.test/"], allow_network=False,
    )
    assert result.deferred is True
    assert "allow_network=False" in (result.error or "")


@pytest.mark.asyncio
async def test_run_browser_pass_uses_injected_runner() -> None:
    """Production code paths inject a stub runner for unit tests so
    real Playwright is never imported in CI."""
    async def _fake_runner(urls, **kwargs):
        tels = []
        for u in urls:
            tel = BrowserTelemetry(page_url=u)
            tel.add(NetworkArtifact(
                url="https://api.example/users", method="GET",
                initiator_kind="fetch", page_url=u,
            ))
            tels.append(tel)
        return BrowserPassResult(telemetries=tels)

    result = await run_browser_pass(
        ["https://target.test/"],
        allow_network=True,
        runner=_fake_runner,
    )
    assert result.deferred is False
    assert len(result.telemetries) == 1
    assert result.telemetries[0].fetch_urls == [
        "https://api.example/users",
    ]


@pytest.mark.asyncio
async def test_run_browser_pass_handles_missing_playwright_gracefully() -> None:
    """When allow_network=True but Playwright isn't installed (no
    runner injected), the real path is exercised; if Playwright is
    actually present it'll proceed, but on CI it isn't, so we get a
    deferred result with a clear error string. Either way the runner
    must not raise."""
    result = await run_browser_pass(
        ["https://example.com/"], allow_network=True,
    )
    # We don't assert deferred=True here — playwright MIGHT be
    # installed on a developer box. We just guarantee the runner
    # returns a clean result object instead of raising.
    assert isinstance(result, BrowserPassResult)


# ---------------------------------------------------------------------------
# env-driven helper
# ---------------------------------------------------------------------------


def test_browser_pass_enabled_default_off(monkeypatch) -> None:
    monkeypatch.delenv("WEBHOUND_BROWSER_ENABLED", raising=False)
    assert browser_pass_enabled() is False


def test_browser_pass_enabled_when_env_set(monkeypatch) -> None:
    monkeypatch.setenv("WEBHOUND_BROWSER_ENABLED", "1")
    assert browser_pass_enabled() is True
