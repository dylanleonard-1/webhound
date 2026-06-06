# WebHound — tests/test_browser_discovery_context.py
# Phase-6C: BrowserDiscovery container + ScanContext access. Engines
# must be able to consume browser data through ctx.browser without
# branching on availability.

from __future__ import annotations

from webhound.browser.models import (
    BrowserDiscovery,
    BrowserTelemetry,
    NetworkArtifact,
    RenderedForm,
    RenderedScript,
)
from webhound.core.scan_context import ScanContext
from webhound.models.target import Target


def _tel() -> BrowserTelemetry:
    tel = BrowserTelemetry(page_url="https://target.test/app")
    tel.final_url = "https://target.test/app"
    tel.rendered_html = "<html></html>"
    tel.rendered_links = [
        "https://target.test/spa-route", "https://vendor.com/x",
    ]
    tel.rendered_forms = [RenderedForm(action=None, method="GET")]
    tel.rendered_scripts = [
        RenderedScript(kind="script_tag", src="https://target.test/app.js"),
        RenderedScript(kind="modulepreload",
                       src="https://target.test/chunk-1a2b.js"),
        RenderedScript(kind="inline", is_inline=True, snippet="var x=1"),
    ]
    tel.add(NetworkArtifact(
        url="https://target.test/api/users", method="GET",
        initiator_kind="fetch", page_url=tel.page_url,
    ))
    tel.add(NetworkArtifact(
        url="https://cdn.vendor.com/lazy-chunk.js", method="GET",
        initiator_kind="script", page_url=tel.page_url,
    ))
    return tel


def _discovery() -> BrowserDiscovery:
    return BrowserDiscovery(telemetries=[_tel()], deferred=False)


def test_accessors_aggregate_across_telemetries() -> None:
    d = _discovery()
    assert d.available is True
    assert d.get_all_pages() == ["https://target.test/app"]
    assert "https://target.test/spa-route" in d.get_all_rendered_links()
    assert len(d.get_all_forms()) == 1
    # Script URLs: DOM scripts + chunk hints + network-observed scripts.
    urls = d.get_all_script_urls()
    assert "https://target.test/app.js" in urls
    assert "https://target.test/chunk-1a2b.js" in urls
    assert "https://cdn.vendor.com/lazy-chunk.js" in urls
    assert len(d.get_all_inline_scripts()) == 1
    assert len(d.get_all_network_requests()) == 2


def test_api_endpoint_accessor_classifies() -> None:
    apis = _discovery().get_all_api_endpoints()
    assert [a.url for a in apis] == ["https://target.test/api/users"]


def test_third_party_domains_exclude_target_registrable() -> None:
    domains = _discovery().get_all_third_party_domains(
        primary_host="target.test",
    )
    assert domains == ["cdn.vendor.com"]


def test_coverage_stats_shape() -> None:
    stats = _discovery().coverage_stats()
    assert stats["browser_pages_rendered"] == 1
    assert stats["rendered_forms_found"] == 1
    assert stats["browser_scripts_found"] == 3
    assert stats["browser_network_requests"] == 2
    assert stats["skipped_out_of_scope_browser_urls"] == 0


def test_ctx_browser_never_none_and_empty_safe() -> None:
    """Quick/static scans never run the browser pass — ctx.browser
    must still be usable with empty results everywhere."""
    ctx = ScanContext(Target.from_url("https://target.test/"))
    b = ctx.browser
    assert b.available is False
    assert b.get_all_pages() == []
    assert b.get_all_forms() == []
    assert b.get_all_script_urls() == []
    assert b.get_all_api_endpoints() == []
    assert b.get_all_third_party_domains() == []
    assert b.coverage_stats()["browser_pages_rendered"] == 0


def test_ctx_browser_returns_attached_discovery() -> None:
    ctx = ScanContext(Target.from_url("https://target.test/"))
    ctx.browser_discovery = _discovery()
    assert ctx.browser.available is True
    assert len(ctx.browser.get_all_forms()) == 1
