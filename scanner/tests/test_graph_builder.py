# WebHound — tests/test_graph_builder.py
# Phase-20 Task 2-8/13: build a graph from scan data (synthetic, no real
# scan). Uses lightweight stand-ins for ScanResult / CrawlResult /
# PageArtifacts so the builder logic is verified deterministically.

from __future__ import annotations

from types import SimpleNamespace as NS

from webhound.graph import EdgeType, NodeType, build_graph


def _script(src=None, content=None):
    return NS(src=src, content=content, is_inline=content is not None,
              is_external=src is not None,
              is_external_domain=bool(src and "t.test" not in (src or "")))


def _form(action_url=None, password=False, method="POST"):
    return NS(action_url=action_url, has_password_field=password, method=method)


def _iframe(src_url=None, hidden=False):
    return NS(src_url=src_url, is_hidden=hidden, is_external_domain=True)


def _artifacts(url, *, scripts=(), forms=(), iframes=(), cookies=(),
               headers=None):
    return NS(url=url, scripts=list(scripts), forms=list(forms),
              iframes=list(iframes), cookies=list(cookies),
              response_headers=headers or {})


def _crawl(url, **kw):
    return NS(response=NS(url=url, failed=False), artifacts=_artifacts(url, **kw))


def _result(grouped=(), metadata=None):
    return NS(target=NS(base_url="https://t.test/"),
              grouped_findings=list(grouped), metadata=metadata or {})


def _gf(title, *, engine, severity="medium", host=None, urls=(),
        finding_type="likely_risk"):
    return NS(title=title, scanner_engine=engine,
              severity=NS(value=severity), confidence=0.8,
              finding_ids=[f"id-{title}"], affected_urls=list(urls),
              metadata={"host": host, "finding_type": finding_type})


# ---------------------------------------------------------------------------
# Page relationships (Task 3)
# ---------------------------------------------------------------------------


def test_page_loads_script() -> None:
    g = build_graph(_result(), crawl_results=[
        _crawl("https://t.test/checkout",
               scripts=[_script(src="https://js.stripe.com/v3")])])
    page = g.find_node(NodeType.PAGE, "https://t.test/checkout")
    assert page is not None
    scripts = g.neighbors(page.id, EdgeType.LOADS, target_type=NodeType.SCRIPT)
    assert any("stripe" in s.value for s in scripts)


def test_page_contains_form() -> None:
    g = build_graph(_result(), crawl_results=[
        _crawl("https://t.test/login",
               forms=[_form(action_url="https://t.test/auth", password=True)])])
    page = g.find_node(NodeType.PAGE, "https://t.test/login")
    forms = g.neighbors(page.id, EdgeType.CONTAINS, target_type=NodeType.FORM)
    assert forms and forms[0].metadata["password"] is True


def test_page_embeds_iframe_and_cookie_header() -> None:
    g = build_graph(_result(), crawl_results=[
        _crawl("https://t.test/",
               iframes=[_iframe(src_url="https://ads.vendor.com/x", hidden=True)],
               cookies=["sessionid=abc; Path=/"],
               headers={"content-security-policy": "default-src 'self'"})])
    page = g.find_node(NodeType.PAGE, "https://t.test")
    assert g.neighbors(page.id, EdgeType.EMBEDS, target_type=NodeType.IFRAME)
    assert g.neighbors(page.id, EdgeType.SETS_COOKIE, target_type=NodeType.COOKIE)
    assert g.neighbors(page.id, EdgeType.HAS_HEADER, target_type=NodeType.HEADER)


# ---------------------------------------------------------------------------
# Script / domain / vendor (Task 4)
# ---------------------------------------------------------------------------


def test_script_belongs_to_known_vendor() -> None:
    g = build_graph(_result(), crawl_results=[
        _crawl("https://t.test/",
               scripts=[_script(src="https://js.stripe.com/v3")])])
    dom = g.find_node(NodeType.THIRD_PARTY_DOMAIN, "js.stripe.com")
    assert dom is not None
    vendors = g.neighbors(dom.id, EdgeType.BELONGS_TO_VENDOR,
                          target_type=NodeType.VENDOR)
    assert vendors
    assert vendors[0].metadata["category"] == "payment"
    assert vendors[0].metadata["trusted"] is True


def test_unknown_vendor_not_escalated() -> None:
    g = build_graph(_result(), crawl_results=[
        _crawl("https://t.test/",
               scripts=[_script(src="https://random-unknown-xyz.test/a.js")])])
    dom = g.find_node(NodeType.THIRD_PARTY_DOMAIN, "random-unknown-xyz.test")
    assert dom is not None
    # No vendor node + preserved unknown status (Task 4).
    assert dom.metadata.get("vendor") == "unknown"


def test_inventory_hosts_become_third_party_domains() -> None:
    # P4 fix: the scan-wide external-host inventory (incl. CSP-declared hosts a
    # same-origin SPA never loads as a <script src> or cross-origin fetch) must
    # materialize THIRD_PARTY_DOMAIN nodes — so third_parties != 0.
    g = build_graph(
        _result(metadata={"external_host_inventory": [
            "fonts.gstatic.com", "js.stripe.com", "random-unknown-xyz.test", "t.test"]}),
        primary_host="t.test")
    hosts = {n.label for n in g.nodes_of_type(NodeType.THIRD_PARTY_DOMAIN)}
    assert {"fonts.gstatic.com", "js.stripe.com", "random-unknown-xyz.test"} <= hosts
    assert "t.test" not in hosts  # first-party host is never a third-party node
    # The Stripe host resolves to a known vendor node (payment category).
    assert g.find_node(NodeType.THIRD_PARTY_DOMAIN, "js.stripe.com") is not None
    assert any(v.metadata.get("category") == "payment" for v in g.nodes_of_type(NodeType.VENDOR))


def test_inventory_hosts_no_duplicate_with_static_scripts() -> None:
    # A host present BOTH as a static <script src> and in the inventory is a single node.
    g = build_graph(
        _result(metadata={"external_host_inventory": ["js.stripe.com"]}),
        crawl_results=[_crawl("https://t.test/",
                              scripts=[_script(src="https://js.stripe.com/v3/")])],
        primary_host="t.test")
    nodes = [n for n in g.nodes_of_type(NodeType.THIRD_PARTY_DOMAIN) if n.label == "js.stripe.com"]
    assert len(nodes) == 1


# ---------------------------------------------------------------------------
# Findings (Task 6)
# ---------------------------------------------------------------------------


def test_finding_links_to_page() -> None:
    g = build_graph(_result(
        grouped=[_gf("Exposed Admin panel detected", engine="sensitive_paths",
                     urls=["https://t.test/admin"])]),
        crawl_results=[_crawl("https://t.test/admin")])
    page = g.find_node(NodeType.PAGE, "https://t.test/admin")
    findings = g.neighbors(page.id, EdgeType.RELATED_TO_FINDING,
                           target_type=NodeType.FINDING)
    assert any("Admin" in f.label for f in findings)


def test_finding_links_to_domain() -> None:
    g = build_graph(_result(
        grouped=[_gf("Likely malicious third-party host: evil.test",
                     engine="threat_intel", host="evil.test", severity="high")]))
    dom = g.find_node(NodeType.THIRD_PARTY_DOMAIN, "evil.test")
    assert dom is not None
    findings = g.neighbors(dom.id, EdgeType.RELATED_TO_FINDING,
                           target_type=NodeType.FINDING)
    assert findings


# ---------------------------------------------------------------------------
# WADE + threat intel (Task 7/8)
# ---------------------------------------------------------------------------


def test_wade_change_links_to_script() -> None:
    g = build_graph(_result(metadata={"wade_timeline": {"records": [
        {"change_key": "k1", "diff_type": "new_script_source",
         "value": "https://new-cdn.test/a.js", "change_type": "suspicious_script_change",
         "band": "medium"}]}}))
    changes = g.nodes_of_type(NodeType.WADE_CHANGE)
    assert changes
    targets = g.neighbors(changes[0].id, EdgeType.CHANGED_IN_WADE,
                          target_type=NodeType.SCRIPT)
    assert targets and "new-cdn.test" in targets[0].value


def test_threat_indicator_links_to_domain() -> None:
    g = build_graph(_result(metadata={"threat_correlations": [
        {"correlation_type": "possible_skimmer", "severity": "critical",
         "confidence": "high", "hosts": ["evil-skim.test"]}]}))
    ti = g.nodes_of_type(NodeType.THREAT_INDICATOR)
    assert ti
    doms = g.neighbors(ti[0].id, EdgeType.MATCHES_THREAT_INTEL,
                       target_type=NodeType.THIRD_PARTY_DOMAIN)
    assert any("evil-skim" in d.value for d in doms)


# ---------------------------------------------------------------------------
# Robustness (Task 2/13)
# ---------------------------------------------------------------------------


def test_graph_handles_missing_browser_and_empty_scan() -> None:
    g = build_graph(_result())            # no crawl, no browser, no findings
    assert g.find_node(NodeType.SITE, "t.test") is not None
    assert g.node_count >= 1               # at least the site node


def test_sensitive_path_probes_dont_inflate_page_count() -> None:
    """Regression: sensitive_paths findings probe uncrawled URLs (e.g.
    /phpmyadmin) that 403. They must NOT create phantom PAGE nodes — the
    '24 pages on a 1-page site' bug. They anchor to the site instead."""
    g = build_graph(_result(grouped=[
        _gf("Path '/phpmyadmin' returned HTTP 403 (heuristic)",
            engine="sensitive_paths", urls=["https://t.test/phpmyadmin"]),
        _gf("Path '/wp-config.php' returned HTTP 403 (heuristic)",
            engine="sensitive_paths", urls=["https://t.test/wp-config.php"]),
    ]), crawl_results=[_crawl("https://t.test/")])
    # Only the one crawled page is a PAGE node — not the two probes.
    assert len(g.nodes_of_type(NodeType.PAGE)) == 1
    # The probe findings are still connected (to the site), not orphaned.
    site = g.find_node(NodeType.SITE, "t.test")
    linked = g.neighbors(site.id, EdgeType.RELATED_TO_FINDING,
                         target_type=NodeType.FINDING)
    assert len(linked) == 2


def test_build_is_deterministic() -> None:
    crawl = [_crawl("https://t.test/", scripts=[_script(src="https://x.test/a.js")])]
    g1 = build_graph(_result(), crawl_results=crawl)
    g2 = build_graph(_result(), crawl_results=crawl)
    assert g1.node_count == g2.node_count
    assert {n.id for n in g1.nodes()} == {n.id for n in g2.nodes()}
