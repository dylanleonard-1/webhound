# WebHound — tests/test_frameworks.py
# Phase-9 framework-aware discovery. Each platform gets a representative
# sample (Task 11): detection, known surface, no cross-framework false
# positives.

from __future__ import annotations

import pytest

from webhound.frameworks import (
    DetectionContext,
    build_coverage,
    detect_from_context,
    detect_scan,
    is_normal_framework_change,
    normal_change_matchers,
)


def _ctx(**kw) -> DetectionContext:
    return DetectionContext(
        url=kw.get("url", "https://shop.example/"),
        headers=kw.get("headers", {}),
        meta_generator=kw.get("meta_generator", ""),
        script_urls=kw.get("script_urls", []),
        inline_scripts=kw.get("inline_scripts", []),
        link_urls=kw.get("link_urls", []),
        html=kw.get("html", ""),
        global_vars=kw.get("global_vars", []),
        hosts=kw.get("hosts", []),
    )


def _names(dets):
    return {d.name for d in dets}


# ---------------------------------------------------------------------------
# Per-platform detection (Task 11 samples)
# ---------------------------------------------------------------------------


def test_wordpress_sample() -> None:
    ctx = _ctx(
        meta_generator="WordPress 6.4.2",
        script_urls=["https://site.test/wp-content/themes/x/app.js",
                     "https://site.test/wp-includes/js/jquery.js"],
        link_urls=["https://site.test/wp-json/"],
        html='<body class="wp-embed"><img src="/wp-content/uploads/2024/x.png">',
    )
    dets = detect_from_context(ctx)
    assert "WordPress" in _names(dets)
    wp = next(d for d in dets if d.name == "WordPress")
    assert wp.confidence >= 0.75


def test_shopify_sample() -> None:
    ctx = _ctx(
        headers={"x-shopify-stage": "production", "x-shopid": "12345"},
        script_urls=["https://cdn.shopify.com/s/files/1/x/theme.js"],
        global_vars=["Shopify"],
        hosts=["cdn.shopify.com"],
    )
    dets = detect_from_context(ctx)
    assert "Shopify" in _names(dets)
    assert next(d for d in dets if d.name == "Shopify").confidence >= 0.9


def test_wix_sample() -> None:
    ctx = _ctx(
        headers={"x-wix-request-id": "abc"},
        script_urls=["https://static.parastorage.com/services/x/app.js"],
        html='<div id="SITE_CONTAINER">',
        hosts=["static.parastorage.com"],
    )
    assert "Wix" in _names(detect_from_context(ctx))


def test_webflow_sample() -> None:
    ctx = _ctx(
        meta_generator="Webflow",
        script_urls=["https://assets.website-files.com/x/webflow.js"],
        html='<html data-wf-page="123" data-wf-site="456">',
        hosts=["assets.website-files.com"],
    )
    assert "Webflow" in _names(detect_from_context(ctx))


def test_nextjs_sample() -> None:
    ctx = _ctx(
        headers={"x-powered-by": "Next.js"},
        script_urls=["https://app.test/_next/static/chunks/main-abc.js"],
        global_vars=["__NEXT_DATA__", "__BUILD_MANIFEST"],
        html='<div id="__next">',
    )
    dets = detect_from_context(ctx)
    assert "Next.js" in _names(dets)
    assert next(d for d in dets if d.name == "Next.js").confidence >= 0.9


def test_react_spa_sample() -> None:
    ctx = _ctx(
        script_urls=["https://app.test/static/js/main.1a2b3c4d.js",
                     "https://app.test/static/js/react-dom.production.min.js"],
        html='<div id="root" data-reactroot>',
    )
    assert "React" in _names(detect_from_context(ctx))


def test_vue_nuxt_sample() -> None:
    ctx = _ctx(
        script_urls=["https://app.test/_nuxt/entry.abc123de.js"],
        global_vars=["__NUXT__"],
        html='<div id="__nuxt"><div data-v-1a2b3c4d>',
    )
    assert "Vue" in _names(detect_from_context(ctx))


def test_angular_sample() -> None:
    ctx = _ctx(
        script_urls=["https://app.test/main.1a2b3c4d5e.js",
                     "https://app.test/polyfills.9f8e7d6c5b.js"],
        html='<app-root ng-version="17.0.1"></app-root>',
    )
    assert "Angular" in _names(detect_from_context(ctx))


# ---------------------------------------------------------------------------
# No cross-framework false positives (Task 11 "no major FPs")
# ---------------------------------------------------------------------------


def test_plain_static_site_detects_nothing() -> None:
    ctx = _ctx(
        url="https://static.test/",
        script_urls=["https://static.test/js/site.js"],
        html="<html><body><h1>Hello</h1></body></html>",
    )
    assert detect_from_context(ctx) == []


def test_wordpress_not_flagged_as_shopify() -> None:
    ctx = _ctx(
        meta_generator="WordPress 6.4",
        script_urls=["https://site.test/wp-content/themes/x/app.js"],
        link_urls=["https://site.test/wp-json/"],
    )
    names = _names(detect_from_context(ctx))
    assert "WordPress" in names
    assert "Shopify" not in names


def test_nextjs_primary_over_react() -> None:
    """A Next.js site is also React; the more specific meta-framework
    profile must win the primary slot."""
    ctx = _ctx(
        headers={"x-powered-by": "Next.js"},
        script_urls=["https://app.test/_next/static/chunks/main.js"],
        global_vars=["__NEXT_DATA__"],
        html='<div id="__next" data-reactroot>',
    )
    result = detect_scan([ctx])
    assert result.primary is not None
    assert result.primary.name == "Next.js"


# ---------------------------------------------------------------------------
# Coverage payload (Task 10)
# ---------------------------------------------------------------------------


def test_coverage_payload_shape() -> None:
    ctx = _ctx(
        headers={"x-shopify-stage": "production"},
        global_vars=["Shopify"],
        hosts=["cdn.shopify.com"],
        script_urls=["https://cdn.shopify.com/s/files/1/x/theme.js"],
    )
    result = detect_scan([ctx])
    cov = build_coverage(
        result, observed_routes=["/", "/cart"],
        observed_apis=["/cart.js"], observed_assets=["/cdn/shop/x.css"],
        observed_forms=2,
    )
    assert cov["primary_framework"] == "Shopify"
    assert cov["routes_observed"] == 2
    assert cov["apis_observed"] == 1
    assert cov["forms_observed"] == 2
    # Shopify known surface candidates present.
    assert "/cart.js" in cov["known_surface"]["apis"]
    assert "/products.json" in cov["known_surface"]["apis"]
    assert any("shopify" in v for v in cov["known_surface"]["third_parties"])


# ---------------------------------------------------------------------------
# WADE framework context (Task 9)
# ---------------------------------------------------------------------------


def test_nextjs_chunk_is_normal_change() -> None:
    ctx = _ctx(
        headers={"x-powered-by": "Next.js"},
        global_vars=["__NEXT_DATA__"],
        script_urls=["https://app.test/_next/static/chunks/main.js"],
    )
    matchers = normal_change_matchers(detect_scan([ctx]))
    assert is_normal_framework_change(
        "https://app.test/_next/static/chunks/page-9f8e7d.js", matchers)
    # An unrelated new script is NOT normal framework behaviour.
    assert not is_normal_framework_change(
        "https://evil.test/inject.js", matchers)


def test_wordpress_plugin_bump_is_normal() -> None:
    ctx = _ctx(
        meta_generator="WordPress 6.4",
        link_urls=["https://site.test/wp-json/"],
        script_urls=["https://site.test/wp-content/plugins/x/a.js"],
    )
    matchers = normal_change_matchers(detect_scan([ctx]))
    assert is_normal_framework_change(
        "https://site.test/wp-content/plugins/yoast/js/x.js?ver=21.5",
        matchers)


def test_shopify_theme_asset_bump_is_normal() -> None:
    ctx = _ctx(
        headers={"x-shopify-stage": "production"},
        global_vars=["Shopify"],
        hosts=["cdn.shopify.com"],
    )
    matchers = normal_change_matchers(detect_scan([ctx]))
    assert is_normal_framework_change(
        "https://cdn.shopify.com/s/files/1/x/theme.css?v=123456", matchers)


def test_no_framework_no_matchers() -> None:
    assert normal_change_matchers(detect_scan([])) == []
    assert is_normal_framework_change("anything", []) is False
