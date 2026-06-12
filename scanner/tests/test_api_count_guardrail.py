# WebHound — scanner/tests/test_api_count_guardrail.py
# GUARDRAIL: the canonical headline API count is identical across every surface
# (canonical inventory == Security Graph == coverage_summary == Visibility Map),
# and the old per-request graph path is the one that inflated. Synthetic browser
# traffic that mimics a Next.js/Vercel app (query variants + _rsc + _next/data +
# analytics + ONE real /api + a graphql + an auth route + a third-party API).

from __future__ import annotations

from webhound.core.api_inventory import ApiInventory
from webhound.browser.models import BrowserDiscovery, BrowserTelemetry, NetworkArtifact
from webhound.graph.graph_builder import build_graph
from webhound.graph.graph_export import export_summary
from webhound.graph.models import NodeType

PRIMARY = "site.com"


def _artifact(url, kind="fetch", method="GET", ct="application/json"):
    return NetworkArtifact(url=url, method=method, initiator_kind=kind, content_type=ct)


def _fake_browser() -> BrowserDiscovery:
    arts = []
    # ~300 query-variant + _rsc requests that collapse to a handful of paths.
    for i in range(120):
        arts.append(_artifact(f"https://site.com/api/products?id={i}"))      # 1 real path
    for i in range(120):
        arts.append(_artifact(f"https://site.com/dashboard?_rsc={i:x}"))     # framework (RSC)
    for i in range(40):
        arts.append(_artifact(f"https://site.com/_next/data/build{i}/x.json"))  # framework
    for i in range(40):
        arts.append(_artifact(f"https://www.google-analytics.com/g/collect?v={i}"))  # analytics
    # Real distinct endpoints (headline-worthy).
    arts.append(_artifact("https://site.com/api/orders"))
    arts.append(_artifact("https://site.com/graphql"))
    arts.append(_artifact("https://site.com/api/auth/login", method="POST"))
    arts.append(_artifact("https://api.vendor.com/v2/data"))                 # third-party
    # Spread across 3 rendered pages.
    tels = []
    for p in ("https://site.com/", "https://site.com/shop", "https://site.com/account"):
        t = BrowserTelemetry(page_url=p, final_url=p, artifacts=list(arts))
        tels.append(t)
    return BrowserDiscovery(telemetries=tels, deferred=False)


class _ScanResult:
    def __init__(self):
        self.metadata = {}
        self.grouped_findings = []
        class _T:
            base_url = "https://site.com/"
        self.target = _T()


def test_guardrail_all_surfaces_agree_on_headline_count():
    browser = _fake_browser()
    inv = ApiInventory.build([], browser=browser, primary_host=PRIMARY)

    # Canonical headline = first-party API + graphql + auth (NOT third-party,
    # framework, analytics): /api/products, /api/orders, /graphql, POST /auth/login = 4
    headline = inv.headline_count
    assert headline == 4, (headline, inv.by_class())

    # Security Graph (built WITH the inventory) reports the SAME headline.
    sr = _ScanResult()
    graph = build_graph(sr, crawl_results=[], browser=browser,
                        primary_host=PRIMARY, api_inventory=inv)
    summary = export_summary(graph)
    assert summary["api_endpoint_count"] == headline

    # coverage_summary mirror (orchestrator uses inv.headline_count).
    coverage_api = inv.headline_count
    # Visibility map api.count mirror (report uses inv.headline_count).
    visibility_api = inv.headline_count

    assert headline == summary["api_endpoint_count"] == coverage_api == visibility_api == 4


def test_before_after_node_deflation():
    browser = _fake_browser()
    sr = _ScanResult()

    # BEFORE — legacy graph (no inventory): one API_ENDPOINT node per unique
    # query-bearing request URL → massive inflation.
    legacy = build_graph(sr, crawl_results=[], browser=browser, primary_host=PRIMARY)
    legacy_api_nodes = len(legacy.nodes_of_type(NodeType.API_ENDPOINT))

    # AFTER — canonical inventory: one node per real endpoint (framework +
    # analytics excluded).
    inv = ApiInventory.build([], browser=browser, primary_host=PRIMARY)
    canon = build_graph(_ScanResult(), crawl_results=[], browser=browser,
                        primary_host=PRIMARY, api_inventory=inv)
    canon_api_nodes = len(canon.nodes_of_type(NodeType.API_ENDPOINT))
    canon_headline = export_summary(canon)["api_endpoint_count"]

    # Legacy explodes (120 product variants + 120 rsc + 40 data + 40 analytics
    # + 4 real, deduped by full URL ≈ 324). Canonical: graph nodes = real
    # non-excluded endpoints (4 headline + 1 third-party = 5); headline = 4.
    assert legacy_api_nodes > 300
    assert canon_api_nodes == 5
    assert canon_headline == 4
    assert legacy_api_nodes / max(canon_headline, 1) > 50   # >50x inflation removed


def test_query_variants_do_not_create_endpoints():
    inv = ApiInventory(primary_host=PRIMARY)
    for i in range(500):
        inv.add(f"https://site.com/api/x?page={i}")
    assert inv.total_count == 1
    assert inv.headline_count == 1
    assert inv.endpoints()[0].observed_count == 500
