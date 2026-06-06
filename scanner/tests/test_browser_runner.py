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
    RenderedForm,
    RenderedFormField,
    aggregate_browser_hosts,
)
from webhound.browser.playwright_runner import (
    BrowserPassResult,
    _capture_rendered_dom,
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
# Rendered-DOM capture (Phase-6A) — mocked page object, no Playwright
# ---------------------------------------------------------------------------


class _FakePage:
    """Stand-in for a Playwright Page: only the two read-only calls
    the DOM capture path uses."""

    def __init__(self, html="<html></html>", eval_result=None,
                 content_raises=False, eval_raises=False):
        self._html = html
        self._eval_result = eval_result
        self._content_raises = content_raises
        self._eval_raises = eval_raises

    async def content(self):
        if self._content_raises:
            raise RuntimeError("page closed")
        return self._html

    async def evaluate(self, _script):
        if self._eval_raises:
            raise RuntimeError("execution context destroyed")
        return self._eval_result


@pytest.mark.asyncio
async def test_capture_rendered_dom_populates_telemetry() -> None:
    tel = BrowserTelemetry(page_url="https://target.test/app")
    page = _FakePage(
        html="<html><body><a href='/hidden'>x</a></body></html>",
        eval_result={
            "links": [
                "https://target.test/hidden",
                "https://target.test/hidden",  # dupe must collapse
                "https://cdn.example.com/promo",
            ],
            "forms": [{
                "action": "https://target.test/api/login",
                "method": "post",
                "fields": [
                    {"name": "user", "type": "text"},
                    {"name": "pass", "type": "password"},
                ],
                "hasPassword": True,
            }],
        },
    )
    await _capture_rendered_dom(page, tel)
    assert tel.rendered_html is not None and "hidden" in tel.rendered_html
    assert tel.rendered_links == [
        "https://target.test/hidden",
        "https://cdn.example.com/promo",
    ]
    assert len(tel.rendered_forms) == 1
    form = tel.rendered_forms[0]
    assert form.action == "https://target.test/api/login"
    assert form.method == "POST"
    assert form.has_password_field is True
    assert form.fields == (
        RenderedFormField(name="user", input_type="text"),
        RenderedFormField(name="pass", input_type="password"),
    )
    assert form.page_url == "https://target.test/app"
    assert tel.errors == []


@pytest.mark.asyncio
async def test_capture_rendered_dom_content_failure_is_isolated() -> None:
    """A dead page must not raise — and the DOM walk still runs."""
    tel = BrowserTelemetry(page_url="https://target.test/")
    page = _FakePage(
        content_raises=True,
        eval_result={"links": ["https://target.test/a"], "forms": []},
    )
    await _capture_rendered_dom(page, tel)
    assert tel.rendered_html is None
    assert tel.rendered_links == ["https://target.test/a"]
    assert any("rendered-html capture failed" in e for e in tel.errors)


@pytest.mark.asyncio
async def test_capture_rendered_dom_eval_failure_is_isolated() -> None:
    tel = BrowserTelemetry(page_url="https://target.test/")
    page = _FakePage(html="<html>ok</html>", eval_raises=True)
    await _capture_rendered_dom(page, tel)
    assert tel.rendered_html == "<html>ok</html>"
    assert tel.rendered_links == []
    assert any("rendered-dom walk failed" in e for e in tel.errors)


@pytest.mark.asyncio
async def test_capture_rendered_dom_malformed_payload_ignored() -> None:
    """Defensive parsing: junk types from the page never raise."""
    tel = BrowserTelemetry(page_url="https://target.test/")
    page = _FakePage(eval_result={
        "links": [None, 42, "", "https://target.test/ok"],
        "forms": ["not-a-dict", {"action": 99, "method": None,
                                 "fields": [None, {"name": 3, "type": None}]}],
    })
    await _capture_rendered_dom(page, tel)
    assert tel.rendered_links == ["https://target.test/ok"]
    assert len(tel.rendered_forms) == 1
    assert tel.rendered_forms[0].action is None
    assert tel.rendered_forms[0].method == "GET"
    assert tel.rendered_forms[0].fields == (
        RenderedFormField(name=None, input_type="text"),
    )


@pytest.mark.asyncio
async def test_injected_runner_receives_capture_dom_flag() -> None:
    seen_kwargs: dict = {}

    async def _fake_runner(urls, **kwargs):
        seen_kwargs.update(kwargs)
        return BrowserPassResult()

    await run_browser_pass(
        ["https://target.test/"], allow_network=True,
        capture_dom=False, runner=_fake_runner,
    )
    assert seen_kwargs.get("capture_dom") is False


def test_rendered_form_defaults_are_safe() -> None:
    form = RenderedForm(action=None, method="GET")
    assert form.fields == ()
    assert form.has_password_field is False


# ---------------------------------------------------------------------------
# env-driven helper
# ---------------------------------------------------------------------------


def test_browser_pass_enabled_default_off(monkeypatch) -> None:
    monkeypatch.delenv("WEBHOUND_BROWSER_ENABLED", raising=False)
    assert browser_pass_enabled() is False


def test_browser_pass_enabled_when_env_set(monkeypatch) -> None:
    monkeypatch.setenv("WEBHOUND_BROWSER_ENABLED", "1")
    assert browser_pass_enabled() is True
