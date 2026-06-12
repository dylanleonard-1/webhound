# WebHound — scanner/tests/test_api_inventory.py
# Canonical API inventory: query-variant collapse, classification, exclusions.

from __future__ import annotations

from webhound.core.api_inventory import (
    ApiInventory,
    EndpointClass,
    canonical_key,
    classify_endpoint,
)

PRIMARY = "site.com"


# ---------------------------------------------------------------------------
# Canonical key — query string ignored, method + host + path identity
# ---------------------------------------------------------------------------


def test_canonical_key_ignores_query():
    a = canonical_key("GET", "https://site.com/api/users?id=1")
    b = canonical_key("GET", "https://site.com/api/users?id=2")
    c = canonical_key("GET", "https://site.com/api/users?id=3&x=y")
    assert a == b == c == "GET https://site.com/api/users"


def test_canonical_key_method_distinguishes():
    assert canonical_key("GET", "https://site.com/api/x") != \
        canonical_key("POST", "https://site.com/api/x")


def test_query_variants_collapse_to_one():
    inv = ApiInventory(primary_host=PRIMARY)
    for i in range(50):
        inv.add(f"https://site.com/api/users?id={i}")
    assert inv.total_count == 1
    ep = inv.endpoints()[0]
    assert ep.observed_count == 50
    assert ep.url == "https://site.com/api/users"


def test_rsc_variants_collapse_and_excluded():
    inv = ApiInventory(primary_host=PRIMARY)
    for tok in ("abc", "def", "ghi"):
        inv.add(f"https://site.com/dashboard?_rsc={tok}")
    assert inv.total_count == 1
    assert inv.endpoints()[0].endpoint_class == EndpointClass.FRAMEWORK_INTERNAL
    assert inv.headline_count == 0  # excluded from headline


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def test_classify_first_party_api():
    assert classify_endpoint("https://site.com/api/v1/orders", primary_host=PRIMARY) \
        == EndpointClass.FIRST_PARTY_API


def test_classify_graphql():
    assert classify_endpoint("https://site.com/graphql", primary_host=PRIMARY) \
        == EndpointClass.GRAPHQL


def test_classify_auth():
    assert classify_endpoint("https://site.com/api/auth/login", primary_host=PRIMARY) \
        == EndpointClass.AUTH_API


def test_classify_framework_next_internal():
    assert classify_endpoint("https://site.com/_next/data/abc/index.json",
                             primary_host=PRIMARY) == EndpointClass.FRAMEWORK_INTERNAL


def test_classify_framework_vercel():
    assert classify_endpoint("https://site.com/_vercel/insights/view",
                             primary_host=PRIMARY) == EndpointClass.FRAMEWORK_INTERNAL


def test_classify_analytics_host():
    assert classify_endpoint("https://www.google-analytics.com/g/collect?v=2",
                             primary_host=PRIMARY) == EndpointClass.ANALYTICS


def test_classify_analytics_path():
    assert classify_endpoint("https://site.com/speed-insights/vitals",
                             primary_host=PRIMARY) == EndpointClass.ANALYTICS


def test_classify_third_party_api():
    assert classify_endpoint("https://api.vendor.com/v2/data", primary_host=PRIMARY) \
        == EndpointClass.THIRD_PARTY_API


# ---------------------------------------------------------------------------
# Headline vs details
# ---------------------------------------------------------------------------


def test_headline_excludes_framework_and_analytics_and_third_party():
    inv = ApiInventory(primary_host=PRIMARY)
    inv.add("https://site.com/api/orders")                 # first-party  → headline
    inv.add("https://site.com/graphql")                    # graphql      → headline
    inv.add("https://site.com/api/auth/login")             # auth         → headline
    inv.add("https://site.com/_next/data/b/x.json")        # framework    → not
    inv.add("https://www.google-analytics.com/g/collect")  # analytics    → not
    inv.add("https://api.vendor.com/v2/data")              # third-party  → not headline
    assert inv.headline_count == 3
    assert inv.total_count == 6
    bc = inv.by_class()
    assert bc["first_party_api"] == 1
    assert bc["graphql"] == 1
    assert bc["auth_api"] == 1
    assert bc["framework_internal"] == 1
    assert bc["analytics"] == 1
    assert bc["third_party_api"] == 1
    # graph endpoints = everything real (excludes framework + analytics) = 4
    assert len(inv.graph_endpoints()) == 4


def test_method_aware_form_actions():
    inv = ApiInventory(primary_host=PRIMARY)
    inv.add("https://site.com/api/submit", method="POST")
    inv.add("https://site.com/api/submit", method="GET")
    assert inv.total_count == 2  # GET and POST are distinct endpoints


def test_to_dict_shape():
    inv = ApiInventory(primary_host=PRIMARY)
    inv.add("https://site.com/api/orders?p=1")
    d = inv.to_dict()
    assert d["headline_count"] == 1
    assert d["total_count"] == 1
    assert "by_class" in d and "endpoints" in d
    assert d["endpoints"][0]["observed_count"] == 1
