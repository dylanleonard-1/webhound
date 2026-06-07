# WebHound — tests/test_graph_query.py
# Phase-20 Task 9/10/13: query helpers + graph scoring context.

from __future__ import annotations

from types import SimpleNamespace as NS

from webhound.graph import GraphQuery, GraphScoring, NodeType, build_graph


def _script(src=None, content=None):
    return NS(src=src, content=content, is_inline=content is not None,
              is_external=src is not None, is_external_domain=True)


def _form(action_url=None, password=False):
    return NS(action_url=action_url, has_password_field=password, method="POST")


def _arts(url, *, scripts=(), forms=(), iframes=(), cookies=(), headers=None):
    return NS(url=url, scripts=list(scripts), forms=list(forms),
              iframes=list(iframes), cookies=list(cookies),
              response_headers=headers or {})


def _crawl(url, **kw):
    return NS(response=NS(url=url, failed=False), artifacts=_arts(url, **kw))


def _result(grouped=(), metadata=None):
    return NS(target=NS(base_url="https://t.test/"),
              grouped_findings=list(grouped), metadata=metadata or {})


def _gf(title, *, engine, urls=(), host=None):
    return NS(title=title, scanner_engine=engine, severity=NS(value="high"),
              confidence=0.8, finding_ids=[f"id-{title}"],
              affected_urls=list(urls), metadata={"host": host})


def _checkout_graph():
    return build_graph(_result(
        grouped=[_gf("Payment form risk", engine="form_risk",
                     urls=["https://t.test/checkout"])]),
        crawl_results=[
            _crawl("https://t.test/checkout",
                   scripts=[_script(src="https://js.stripe.com/v3"),
                            _script(src="https://unknown-xyz.test/track.js")],
                   forms=[_form(action_url="https://t.test/api/pay",
                                password=True)]),
            _crawl("https://t.test/login",
                   scripts=[_script(src="https://unknown-xyz.test/track.js")])])


# ---------------------------------------------------------------------------
# Queries (Task 9)
# ---------------------------------------------------------------------------


def test_get_page_scripts_forms_apis() -> None:
    q = GraphQuery(_checkout_graph())
    scripts = q.get_page_scripts("https://t.test/checkout")
    assert any("stripe" in s.value for s in scripts)
    forms = q.get_page_forms("https://t.test/checkout")
    assert forms
    apis = q.get_page_apis("https://t.test/checkout")
    assert any("/api/pay" in a.value for a in apis)


def test_unknown_vendors_query() -> None:
    q = GraphQuery(_checkout_graph())
    unknown = {n.value for n in q.get_unknown_vendors()}
    assert "unknown-xyz.test" in unknown
    assert "js.stripe.com" not in unknown        # stripe is a known vendor


def test_findings_for_page() -> None:
    q = GraphQuery(_checkout_graph())
    findings = q.get_findings_for_page("https://t.test/checkout")
    assert any("Payment form" in f.label for f in findings)


def test_path_from_page_to_domain() -> None:
    q = GraphQuery(_checkout_graph())
    paths = q.get_paths_from_page_to_domain(
        "https://t.test/checkout", "js.stripe.com")
    # checkout page → stripe script → stripe domain
    assert paths
    types = [n.type for n in paths[0]]
    assert NodeType.PAGE in types and NodeType.THIRD_PARTY_DOMAIN in types


def test_wade_changes_for_page() -> None:
    g = build_graph(_result(metadata={"wade_timeline": {"records": [
        {"change_key": "k1", "diff_type": "new_script_source",
         "value": "https://js.stripe.com/v3",
         "change_type": "new_payment_provider", "band": "very_low"}]}}),
        crawl_results=[_crawl("https://t.test/checkout",
                              scripts=[_script(src="https://js.stripe.com/v3")])])
    q = GraphQuery(g)
    changes = q.get_wade_changes_for_page("https://t.test/checkout")
    assert changes                                # the new-script change


# ---------------------------------------------------------------------------
# Scoring context (Task 10)
# ---------------------------------------------------------------------------


def test_unknown_script_on_login_page_queryable() -> None:
    sc = GraphScoring(_checkout_graph())
    assert sc.is_script_connected_to_login("https://unknown-xyz.test/track.js")
    assert not sc.is_script_connected_to_login("https://js.stripe.com/v3")


def test_domain_connected_to_checkout() -> None:
    sc = GraphScoring(_checkout_graph())
    assert sc.is_domain_connected_to_checkout("js.stripe.com")


def test_third_party_connected_to_form() -> None:
    sc = GraphScoring(_checkout_graph())
    # unknown-xyz is on the checkout page which has a form.
    assert sc.is_third_party_connected_to_form("unknown-xyz.test")


def test_finding_on_sensitive_page() -> None:
    sc = GraphScoring(_checkout_graph())
    assert sc.is_finding_on_sensitive_page("Payment form risk")


def test_wade_change_connected_to_finding() -> None:
    g = build_graph(_result(
        grouped=[_gf("Suspicious third-party host: new-cdn.test",
                     engine="threat_intel", host="new-cdn.test")],
        metadata={"wade_timeline": {"records": [
            {"change_key": "k1", "diff_type": "new_third_party_domain",
             "value": "new-cdn.test", "change_type": "suspicious_script_change",
             "band": "high"}]}}))
    sc = GraphScoring(g)
    assert sc.is_wade_change_connected_to_finding("k1")
