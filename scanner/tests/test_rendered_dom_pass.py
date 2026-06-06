# WebHound — tests/test_rendered_dom_pass.py
# Phase-6A orchestrator wiring: rendered-DOM engine pass. Fully
# offline — telemetries are constructed by hand, no Playwright, no
# network. Exercises Scanner._run_rendered_dom_engines directly.

from __future__ import annotations

from types import SimpleNamespace

import pytest

from webhound.browser.models import BrowserTelemetry
from webhound.core.orchestrator import Scanner
from webhound.core.scan_context import ScanContext


RENDERED_HTML = """
<html><body>
  <a href="/spa-route">deep link only visible after hydration</a>
  <a href="https://vendor.example.com/widget">vendor</a>
  <form method="get" action="/login">
    <input type="text" name="user">
    <input type="password" name="pass">
  </form>
</body></html>
"""


def _scanner_and_ctx() -> tuple[Scanner, ScanContext]:
    scanner = Scanner("https://target.test/")
    return scanner, ScanContext(scanner._target)


def _telemetry(**overrides) -> BrowserTelemetry:
    tel = BrowserTelemetry(page_url="https://target.test/app")
    tel.rendered_html = overrides.pop("rendered_html", RENDERED_HTML)
    tel.rendered_links = overrides.pop("rendered_links", [
        "https://target.test/spa-route",
        "https://vendor.example.com/widget",
    ])
    for k, v in overrides.items():
        setattr(tel, k, v)
    return tel


@pytest.mark.asyncio
async def test_rendered_pass_tags_findings_and_counts_coverage() -> None:
    scanner, ctx = _scanner_and_ctx()
    contributions: list = []

    stats = await scanner._run_rendered_dom_engines(
        ctx, [_telemetry()], [], contributions,
    )

    assert stats["rendered_pages"] == 1
    assert stats["rendered_form_count"] == 1
    # Only the same-origin link counts as a rendered-only discovery;
    # the vendor link is third-party surface, not a crawlable route.
    assert stats["rendered_only_link_count"] == 1
    assert stats["rendered_only_links"] == ["https://target.test/spa-route"]

    # The GET+password form must reach the form engines.
    findings = ctx.scan_result.findings
    assert findings, "rendered form should have produced findings"
    assert stats["rendered_finding_count"] == len(findings)
    for f in findings:
        assert "rendered_dom" in (f.tags or [])
        assert (f.metadata or {}).get("evidence_source") == "rendered_dom"

    # Rendered links feed the scan-wide host inventory.
    assert len(contributions) == 1
    assert ("https://vendor.example.com/widget", "rendered_link") in (
        contributions[0].urls
    )


@pytest.mark.asyncio
async def test_rendered_pass_skips_pages_without_html() -> None:
    scanner, ctx = _scanner_and_ctx()
    tel = _telemetry(rendered_html=None, rendered_links=[])

    stats = await scanner._run_rendered_dom_engines(ctx, [tel], [], [])

    assert stats["rendered_pages"] == 0
    assert stats["rendered_finding_count"] == 0
    assert ctx.scan_result.findings == []


@pytest.mark.asyncio
async def test_statically_known_links_not_counted_as_rendered_only() -> None:
    """A link the static crawler already saw must not inflate the
    rendered-only coverage stat."""
    scanner, ctx = _scanner_and_ctx()
    crawl_results = [SimpleNamespace(
        response=SimpleNamespace(
            url="https://target.test/", failed=False,
        ),
        artifacts=SimpleNamespace(
            all_links=["https://target.test/spa-route"],
        ),
    )]

    stats = await scanner._run_rendered_dom_engines(
        ctx, [_telemetry()], crawl_results, [],
    )

    assert stats["rendered_only_link_count"] == 0


@pytest.mark.asyncio
async def test_rendered_pass_never_runs_header_engines() -> None:
    """The synthetic rendered response has no headers — header/CSP/
    cookie engines must not run, or they'd fabricate 'missing header'
    findings from the browser pass."""
    scanner, ctx = _scanner_and_ctx()

    await scanner._run_rendered_dom_engines(ctx, [_telemetry()], [], [])

    banned = {
        scanner._security_headers.NAME, scanner._csp.NAME,
        scanner._cors.NAME, scanner._cookies.NAME,
        scanner._injected_js.NAME, scanner._obfuscation.NAME,
    }
    assert not banned & set(ctx.scan_result.engines_run)
    assert not {f.scanner_engine for f in ctx.scan_result.findings} & banned
