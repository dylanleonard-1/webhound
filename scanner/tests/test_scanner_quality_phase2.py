"""Phase-2 scanner accuracy tests.

Covers:
* Broadened static-HTML extractor (url_discovery.extract_broadened_urls):
  srcset, video/audio, object/embed, meta refresh, preconnect/dns-prefetch/
  preload/modulepreload, manifest, canonical, OG/Twitter, JSON-LD,
  inline-style url(), favicon.
* JS-content URL extractor (url_discovery.extract_js_urls): fetch, XHR
  .open, WebSocket, EventSource, dynamic import(), sourceMappingURL,
  bare string-literal URLs.
* Scan-wide host inventory aggregation (PageHostContribution +
  aggregate_host_inventory): multi-page dedup with provenance.
* VirusTotal client lifecycle states (CHECKED, CACHED, SKIPPED,
  RATE_LIMITED, UNAVAILABLE) + count fields.
* Risk-score quality weighting: many heuristic LOWs can't out-weight one
  confirmed HIGH.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.core.url_discovery import (
    PageHostContribution, aggregate_host_inventory,
    extract_broadened_urls, extract_js_urls,
)
from webhound.threat_intel.enrichment_service import EnrichmentState, ProviderResult


# ---------------------------------------------------------------------------
# Static-HTML extractor
# ---------------------------------------------------------------------------


def test_static_html_pulls_srcset_video_meta_preconnect():
    html = """
    <html><head>
      <link rel="preconnect" href="https://fonts.gstatic.com">
      <link rel="dns-prefetch" href="//cdn.dnsprefetch.example.com">
      <link rel="preload" href="https://preload.example.com/font.woff2" as="font">
      <link rel="modulepreload" href="https://modules.example.com/m.mjs">
      <link rel="manifest" href="https://manifest.example.com/site.webmanifest">
      <link rel="canonical" href="https://canon.example.com/page">
      <link rel="icon" href="https://favicon.example.com/icon.ico">
      <link rel="apple-touch-icon" href="https://favicon.example.com/apple.png">
      <meta http-equiv="refresh" content="0; url=https://refresh.example.com/x">
      <meta property="og:image" content="https://og.example.com/cover.jpg">
      <meta name="twitter:image" content="https://twitter.example.com/card.jpg">
      <script type="application/ld+json">
        {"@type":"Organization","url":"https://org.example.com",
         "logo":"https://org.example.com/logo.png"}
      </script>
    </head><body>
      <img srcset="https://cdn1.example.com/a.jpg 1x, https://cdn2.example.com/b.jpg 2x">
      <video src="https://video.example.com/clip.mp4" poster="https://video.example.com/poster.jpg">
        <source src="https://video.example.com/clip.webm" type="video/webm">
      </video>
      <object data="https://object.example.com/doc.pdf"></object>
      <embed src="https://embed.example.com/widget.swf">
      <div style="background-image: url('https://bg.example.com/bg.png');"></div>
      <style>.x { background: url(https://stylebg.example.com/x.png); }</style>
    </body></html>
    """
    out = extract_broadened_urls(html, base_url="https://example.com/")

    assert "https://fonts.gstatic.com" in out.preconnect
    assert "https://cdn.dnsprefetch.example.com" in out.dns_prefetch
    assert "https://preload.example.com/font.woff2" in out.preload
    assert "https://modules.example.com/m.mjs" in out.preload
    assert "https://manifest.example.com/site.webmanifest" in out.manifest
    assert "https://canon.example.com/page" in out.canonical
    assert any("favicon.example.com" in u for u in out.favicon)
    assert "https://refresh.example.com/x" in out.meta_refresh
    assert "https://og.example.com/cover.jpg" in out.og_twitter
    assert "https://twitter.example.com/card.jpg" in out.og_twitter
    assert any("org.example.com" in u for u in out.jsonld)

    assert "https://cdn1.example.com/a.jpg" in out.srcset
    assert "https://cdn2.example.com/b.jpg" in out.srcset
    assert "https://video.example.com/clip.mp4" in out.video_audio
    assert "https://video.example.com/poster.jpg" in out.video_audio
    assert "https://video.example.com/clip.webm" in out.video_audio
    assert "https://object.example.com/doc.pdf" in out.object_embed
    assert "https://embed.example.com/widget.swf" in out.object_embed
    assert "https://bg.example.com/bg.png" in out.inline_style
    assert "https://stylebg.example.com/x.png" in out.inline_style


def test_static_html_ignores_same_host():
    """First-party assets must not show up in 'external' buckets."""
    html = """
    <html><body>
      <img srcset="https://example.com/local.jpg 1x">
      <link rel="preconnect" href="https://example.com">
      <link rel="canonical" href="https://example.com/canonical">
    </body></html>
    """
    out = extract_broadened_urls(html, base_url="https://example.com/")
    assert out.srcset == []
    assert out.preconnect == []
    assert out.canonical == []


def test_static_html_skips_data_javascript_mailto():
    """Non-network schemes are silently dropped."""
    html = """
    <html><body>
      <img srcset="data:image/png;base64,AAAA 1x">
      <link rel="preconnect" href="javascript:void(0)">
      <a href="mailto:hi@example.com">x</a>
    </body></html>
    """
    out = extract_broadened_urls(html, base_url="https://example.com/")
    assert out.srcset == []
    assert out.preconnect == []


# ---------------------------------------------------------------------------
# JS-content URL extractor
# ---------------------------------------------------------------------------


def test_js_extracts_fetch_xhr_ws_eventsource_import_sourcemap_literals():
    js = """
    const u1 = fetch("https://api.example.com/v1/users");
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "https://api.example.com/v1/events", true);
    const ws = new WebSocket("wss://ws.example.com/stream");
    const es = new EventSource("https://sse.example.com/events");
    import("https://imports.example.com/lazy.mjs").then(m => m.run());
    // The hard-coded CDN URL below is a literal string match.
    const cdn = "https://cdn.example.com/library.min.js";
    const rel = "//proto-relative.example.com/r.js";
    //# sourceMappingURL=https://maps.example.com/app.js.map
    """
    out = extract_js_urls(js, base_url="https://example.com/app.js")
    assert "https://api.example.com/v1/users" in out.fetch_urls
    assert "https://api.example.com/v1/events" in out.xhr_urls
    assert "wss://ws.example.com/stream" in out.websocket_urls
    assert "https://sse.example.com/events" in out.eventsource_urls
    assert "https://imports.example.com/lazy.mjs" in out.dynamic_imports
    assert "https://maps.example.com/app.js.map" in out.source_maps
    assert any("cdn.example.com" in u for u in out.literal_urls)
    # Protocol-relative gets resolved to https://.
    assert any("proto-relative.example.com" in u for u in out.literal_urls)


def test_js_relative_paths_skipped_without_base():
    """Relative API paths (no base_url) are skipped — we can't safely assign
    them a hostname."""
    js = 'fetch("/api/relative/path");'
    out = extract_js_urls(js, base_url=None)
    assert out.fetch_urls == []


def test_js_empty_input_returns_empty_struct():
    out = extract_js_urls("")
    assert out.fetch_urls == []
    assert out.literal_urls == []


# ---------------------------------------------------------------------------
# Scan-wide host inventory
# ---------------------------------------------------------------------------


def test_aggregate_host_inventory_dedups_and_records_provenance():
    pages = [
        PageHostContribution(
            page_url="https://example.com/",
            page_host="example.com",
            urls=[
                ("https://api.vendor.com/v1/x", "js_fetch"),
                ("https://cdn.vendor.com/a.js", "script"),
            ],
        ),
        PageHostContribution(
            page_url="https://example.com/about",
            page_host="example.com",
            urls=[
                # Same host as page 1 — different kind. Dedup'd into one
                # inventory entry with TWO kinds, but first_seen_page stays
                # at the page where we first met it.
                ("https://api.vendor.com/v1/y", "js_xhr"),
                ("https://fonts.othervendor.com/x.woff2", "preload"),
            ],
        ),
    ]
    inv = aggregate_host_inventory(pages)
    assert set(inv) == {"api.vendor.com", "cdn.vendor.com",
                         "fonts.othervendor.com"}
    api = inv["api.vendor.com"]
    assert api.kinds == {"js_fetch", "js_xhr"}
    assert api.first_seen_page == "https://example.com/"
    assert any("v1/x" in u for u in api.sample_urls)
    assert any("v1/y" in u for u in api.sample_urls)

    fonts = inv["fonts.othervendor.com"]
    assert fonts.kinds == {"preload"}
    assert fonts.first_seen_page == "https://example.com/about"


def test_aggregate_skips_self_hostnames():
    pages = [PageHostContribution(
        page_url="https://example.com/", page_host="example.com",
        urls=[("https://example.com/local.js", "script"),
              ("https://api.vendor.com/x", "js_fetch")],
    )]
    inv = aggregate_host_inventory(pages)
    assert set(inv) == {"api.vendor.com"}


# ---------------------------------------------------------------------------
# VirusTotal cache lifecycle states
# ---------------------------------------------------------------------------


def test_provider_result_default_state_is_checked():
    """Phase-2: every ProviderResult carries an explicit lifecycle state.
    Default is CHECKED so existing call sites keep their semantics."""
    r = ProviderResult(
        provider="t", domain="x.com", reputation_score=None, confidence=0.0,
        categories=[], is_malicious=None, is_suspicious=None,
        raw={}, checked_at=datetime.now(timezone.utc),
    )
    assert r.state == EnrichmentState.CHECKED
    assert r.malicious_count is None
    assert r.cached_at is None


@pytest.mark.anyio
async def test_vt_client_skipped_state_without_api_key():
    """No API key + allow_network=True → SKIPPED (not CHECKED with error).
    Dashboard renders 'skipped' instead of 'unknown clean'."""
    from webhound.threat_intel.virustotal_client import VirusTotalClient
    client = VirusTotalClient(api_key=None, allow_network=True)
    result = await client.enrich("example.com")
    assert result.state == EnrichmentState.SKIPPED
    assert "no API key" in (result.error or "")


@pytest.mark.anyio
async def test_vt_client_skipped_state_when_network_disabled():
    """allow_network=False (offline mode) → SKIPPED."""
    from webhound.threat_intel.virustotal_client import VirusTotalClient
    client = VirusTotalClient(api_key="dummy", allow_network=False)
    result = await client.enrich("example.com")
    assert result.state == EnrichmentState.SKIPPED


# ---------------------------------------------------------------------------
# Risk-score quality weighting
# ---------------------------------------------------------------------------


def test_quality_multiplier_tiers():
    from webhound.core.orchestrator import _quality_multiplier
    assert _quality_multiplier(0.95) == 1.0
    assert _quality_multiplier(0.80) == 0.85
    assert _quality_multiplier(0.60) == 0.55
    assert _quality_multiplier(0.50) == 0.20
    assert _quality_multiplier(0.30) == 0.10


def test_risk_score_heuristic_lows_do_not_overpower_confirmed_high():
    """Phase-2: a sea of heuristic LOWs (conf ≤ 0.4) shouldn't outscore one
    confirmed HIGH. This is the noise-fatigue scenario the user surfaced."""
    from webhound.core.orchestrator import _compute_risk_score
    from webhound.models.severity import Severity
    from webhound.models.finding import FindingCategory
    from webhound.models.grouped_finding import GroupedFinding
    from webhound.models.scan_result import ScanResult, SeverityBreakdown
    from webhound.models.target import Target

    # 30 heuristic LOWs (each contributes 2 * 0.10 = 0.20 → tier cap 6.0
    # → score contribution capped at 10, but each at 0.10 mult means
    # the cumulative weighted total is 30*0.10*2 = 6 → 6 risk points).
    heuristic_lows = [
        GroupedFinding(
            title=f"weak-{i}", description="d", severity=Severity.LOW,
            scanner_engine="test", category=FindingCategory.UNKNOWN,
            confidence=0.30, count=1,
        ) for i in range(30)
    ]
    # One confirmed HIGH (conf 0.95) contributes 15 * 1.0 = 15 risk points.
    confirmed_high = GroupedFinding(
        title="real high", description="d", severity=Severity.HIGH,
        scanner_engine="test", category=FindingCategory.UNKNOWN,
        confidence=0.95, count=1,
    )

    tgt = Target.from_url("https://example.com")
    # Result A: only the heuristic noise.
    res_a = ScanResult(
        scan_id="a", target=tgt,
        findings=[], grouped_findings=heuristic_lows,
        severity_breakdown=SeverityBreakdown(low=30),
        engines_run=[], errors=[], started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    score_a, level_a = _compute_risk_score(res_a)

    # Result B: the same noise + one confirmed HIGH.
    res_b = ScanResult(
        scan_id="b", target=tgt,
        findings=[], grouped_findings=heuristic_lows + [confirmed_high],
        severity_breakdown=SeverityBreakdown(low=30, high=1),
        engines_run=[], errors=[], started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    score_b, level_b = _compute_risk_score(res_b)

    # The single confirmed HIGH must move the needle significantly more
    # than 30 heuristic LOWs.
    assert score_b > score_a + 8, (
        f"adding one confirmed HIGH should outweigh 30 heuristic LOWs; "
        f"noise-only={score_a}, noise+confirmed-high={score_b}"
    )
    # And the label gets escalated to at least "low" by the upward guard.
    assert level_b in ("low", "medium", "high", "critical")


def test_risk_score_confirmed_vs_heuristic_same_severity():
    """A confirmed HIGH (conf 0.95) scores more than a heuristic HIGH
    (conf 0.30) — same severity, different confidence."""
    from webhound.core.orchestrator import _compute_risk_score
    from webhound.models.severity import Severity
    from webhound.models.finding import FindingCategory
    from webhound.models.grouped_finding import GroupedFinding
    from webhound.models.scan_result import ScanResult, SeverityBreakdown
    from webhound.models.target import Target

    def _make(conf: float) -> ScanResult:
        gf = GroupedFinding(
            title="x", description="d", severity=Severity.HIGH,
            scanner_engine="test", category=FindingCategory.UNKNOWN,
            confidence=conf, count=1,
        )
        return ScanResult(
            scan_id="s", target=Target.from_url("https://example.com"),
            findings=[], grouped_findings=[gf],
            severity_breakdown=SeverityBreakdown(high=1),
            engines_run=[], errors=[],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )

    confirmed_score, _ = _compute_risk_score(_make(0.95))
    heuristic_score, _ = _compute_risk_score(_make(0.30))
    assert confirmed_score > heuristic_score
