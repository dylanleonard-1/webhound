# WebHound — scanner/webhound/frameworks/profiles.py
# Phase-9: the eight built-in framework profiles. Pure data — detection
# signals + known surface + WADE normal-change patterns per platform.
#
# Known-surface lists are DISCOVERY CANDIDATES surfaced as inventory.
# The passive scanner never auto-fetches them; they tell the customer
# "a site on this platform typically exposes these" and give WADE
# context for what a normal deployment looks like.

from __future__ import annotations

from webhound.frameworks.base import (
    DetectionSignals,
    FrameworkProfile,
    KnownSurface,
)

# ---------------------------------------------------------------------------
# WordPress
# ---------------------------------------------------------------------------

WORDPRESS = FrameworkProfile(
    name="WordPress",
    category="cms",
    signals=DetectionSignals(
        header_signals=(("x-powered-by", "wordpress"),
                        ("x-redirect-by", "wordpress"),
                        ("link", "wp-json")),
        meta_generator_signals=("wordpress",),
        script_signals=(r"/wp-(content|includes)/", r"wp-emoji"),
        path_signals=("/wp-content/", "/wp-includes/", "/wp-json"),
        dom_signals=(r"wp-content/themes/", r"class=\"[^\"]*wp-"),
        third_party_signals=("gravatar.com", "s.w.org"),
    ),
    surface=KnownSurface(
        routes=("/", "/blog", "/?page_id=", "/category/", "/tag/",
                "/author/", "/feed/", "/sitemap.xml"),
        assets=("/wp-content/themes/", "/wp-content/plugins/",
                "/wp-content/uploads/", "/wp-includes/"),
        apis=("/wp-json/", "/wp-json/wp/v2/posts",
              "/wp-json/wp/v2/users", "/wp-json/wp/v2/pages",
              "/xmlrpc.php"),
        admin_paths=("/wp-admin/", "/wp-login.php"),
        forms=("comment form", "search form", "login form"),
        third_parties=("gravatar.com", "jetpack.com", "wp.com"),
    ),
    normal_change_patterns=(
        r"/wp-content/plugins/[^/]+/.*\?ver=",     # plugin asset version bump
        r"/wp-content/themes/[^/]+/.*\?ver=",      # theme asset version bump
        r"/wp-includes/.*\?ver=",
        r"/wp-content/uploads/\d{4}/\d{2}/",       # new media upload
    ),
)

# ---------------------------------------------------------------------------
# Shopify
# ---------------------------------------------------------------------------

SHOPIFY = FrameworkProfile(
    name="Shopify",
    category="commerce",
    signals=DetectionSignals(
        header_signals=(("x-shopify-stage", ""),
                        ("x-shopid", ""),
                        ("x-sorting-hat-shopid", ""),
                        ("x-shardid", "")),
        meta_generator_signals=("shopify",),
        script_signals=(r"cdn\.shopify\.com", r"shopify[_-]features",
                        r"window\.Shopify"),
        path_signals=("cdn.shopify.com", "/cdn/shop/"),
        global_var_signals=("Shopify",),
        dom_signals=(r"shopify-section", r"data-shopify"),
        third_party_signals=("cdn.shopify.com", "myshopify.com",
                             "shopifycdn.com"),
    ),
    surface=KnownSurface(
        routes=("/", "/collections", "/collections/all",
                "/products", "/cart", "/checkout", "/search",
                "/pages/contact", "/blogs/news"),
        assets=("/cdn/shop/", "cdn.shopify.com/s/files/"),
        apis=("/cart.js", "/cart/add.js", "/products.json",
              "/collections.json", "/recommendations/products.json",
              "/api/2024-01/graphql.json", "/.well-known/shopify/"),
        admin_paths=("/admin",),
        forms=("add-to-cart form", "newsletter form", "contact form",
               "customer login form"),
        third_parties=("cdn.shopify.com", "shopifycloud.com",
                       "shopifysvc.com", "shop.app"),
    ),
    normal_change_patterns=(
        r"cdn\.shopify\.com/s/files/.*\?v=",        # theme asset version bump
        r"/cdn/shop/.*\?v=",
        r"shopify[_-]features.*\.js",
    ),
)

# ---------------------------------------------------------------------------
# Wix
# ---------------------------------------------------------------------------

WIX = FrameworkProfile(
    name="Wix",
    category="site_builder",
    signals=DetectionSignals(
        header_signals=(("x-wix-request-id", ""),
                        ("x-wix-server-artifact-id", "")),
        meta_generator_signals=("wix.com",),
        script_signals=(r"static\.parastorage\.com", r"wixstatic\.com",
                        r"wix-warmup-data"),
        path_signals=("parastorage.com", "wixstatic.com"),
        dom_signals=(r"id=\"SITE_CONTAINER\"", r"wix-image"),
        third_party_signals=("wixstatic.com", "parastorage.com",
                             "wixsite.com"),
    ),
    surface=KnownSurface(
        routes=("/", "/about", "/contact", "/blog", "/shop"),
        assets=("static.parastorage.com/", "static.wixstatic.com/"),
        apis=("/_api/wix-ecommerce-storefront-web/",
              "/_api/cloud-data/v1/", "/_functions/",
              "/_serverless/"),
        forms=("contact form", "subscribe form"),
        third_parties=("wixstatic.com", "parastorage.com",
                       "wixapps.net"),
    ),
    normal_change_patterns=(
        r"static\.parastorage\.com/.*",            # Wix CDN asset rotation
        r"static\.wixstatic\.com/media/.*",
    ),
)

# ---------------------------------------------------------------------------
# Webflow
# ---------------------------------------------------------------------------

WEBFLOW = FrameworkProfile(
    name="Webflow",
    category="site_builder",
    signals=DetectionSignals(
        meta_generator_signals=("webflow",),
        script_signals=(r"assets\.website-files\.com",
                        r"assets-global\.website-files\.com",
                        r"webflow\.js"),
        path_signals=("website-files.com", "webflow.io"),
        dom_signals=(r"data-wf-page", r"data-wf-site",
                     r"class=\"w-"),
        third_party_signals=("website-files.com", "webflow.io",
                             "webflow.com"),
    ),
    surface=KnownSurface(
        routes=("/", "/about", "/contact", "/blog"),
        assets=("assets.website-files.com/",
                "assets-global.website-files.com/"),
        apis=("/api/", "/.netlify/functions/"),
        forms=("contact form", "newsletter form"),
        third_parties=("website-files.com", "webflow.io"),
    ),
    normal_change_patterns=(
        r"assets[^/]*\.website-files\.com/.*",     # Webflow CDN asset rotation
    ),
)

# ---------------------------------------------------------------------------
# Next.js
# ---------------------------------------------------------------------------

NEXTJS = FrameworkProfile(
    name="Next.js",
    category="meta_framework",
    signals=DetectionSignals(
        header_signals=(("x-powered-by", "next.js"),
                        ("x-nextjs-cache", ""),
                        ("x-nextjs-prerender", "")),
        script_signals=(r"/_next/static/", r"/_next/data/"),
        path_signals=("/_next/static/", "/_next/data/", "/_next/image"),
        global_var_signals=("__NEXT_DATA__", "__BUILD_MANIFEST",
                            "__NEXT_P"),
        dom_signals=(r"id=\"__next\"", r"/_next/static/"),
    ),
    surface=KnownSurface(
        routes=("/", "/_next/data/", "/api"),
        assets=("/_next/static/chunks/", "/_next/static/css/",
                "/_next/static/media/", "/_next/image"),
        apis=("/api/", "/_next/data/"),
        forms=(),
        third_parties=("vercel.app", "vercel-insights.com"),
    ),
    normal_change_patterns=(
        r"/_next/static/chunks/.*\.js",            # new hashed chunk per build
        r"/_next/static/[^/]+/_buildManifest\.js",
        r"/_next/static/css/.*\.css",
        r"/_next/data/[^/]+/.*\.json",             # build-id-scoped data
    ),
)

# ---------------------------------------------------------------------------
# React (generic SPA, not Next/Remix)
# ---------------------------------------------------------------------------

REACT = FrameworkProfile(
    name="React",
    category="spa_framework",
    signals=DetectionSignals(
        script_signals=(r"/react(?:\.min|\.production)?\.js",
                        r"react-dom", r"/static/js/main\.[0-9a-f]+\.js"),
        global_var_signals=("__REACT_DEVTOOLS_GLOBAL_HOOK__",),
        dom_signals=(r"data-reactroot", r"data-reactid",
                     r"id=\"root\""),
    ),
    surface=KnownSurface(
        routes=("/",),
        assets=("/static/js/", "/static/css/", "/static/media/"),
        apis=("/api/",),
        forms=(),
        third_parties=(),
    ),
    normal_change_patterns=(
        r"/static/js/[^/]*\.[0-9a-f]{8,}\.js",     # hashed CRA bundle
        r"/static/css/[^/]*\.[0-9a-f]{8,}\.css",
    ),
)

# ---------------------------------------------------------------------------
# Vue / Nuxt
# ---------------------------------------------------------------------------

VUE = FrameworkProfile(
    name="Vue",
    category="spa_framework",
    signals=DetectionSignals(
        script_signals=(r"/vue(?:\.min|\.runtime|\.global)?\.js",
                        r"/_nuxt/", r"/__nuxt"),
        path_signals=("/_nuxt/", "/__nuxt"),
        global_var_signals=("__NUXT__", "__VUE__",
                            "__VUE_DEVTOOLS_GLOBAL_HOOK__"),
        dom_signals=(r"data-v-[0-9a-f]{8}", r"id=\"__nuxt\"",
                     r"id=\"app\"\s+data-server-rendered"),
    ),
    surface=KnownSurface(
        routes=("/",),
        assets=("/_nuxt/", "/_nuxt/static/"),
        apis=("/api/", "/_nuxt/"),
        forms=(),
        third_parties=(),
    ),
    normal_change_patterns=(
        r"/_nuxt/[^/]*\.[0-9a-f]{8,}\.js",         # hashed Nuxt chunk
        r"/_nuxt/[^/]*\.[0-9a-f]{8,}\.css",
    ),
)

# ---------------------------------------------------------------------------
# Angular
# ---------------------------------------------------------------------------

ANGULAR = FrameworkProfile(
    name="Angular",
    category="spa_framework",
    signals=DetectionSignals(
        script_signals=(r"/main\.[0-9a-f]+\.js", r"/polyfills\.[0-9a-f]+\.js",
                        r"/runtime\.[0-9a-f]+\.js", r"@angular"),
        dom_signals=(r"ng-version=", r"<app-root", r"_nghost-",
                     r"ng-app="),
    ),
    surface=KnownSurface(
        routes=("/",),
        assets=("/main.js", "/polyfills.js", "/runtime.js",
                "/styles.css"),
        apis=("/api/", "/assets/config.json",
              "/assets/environment.json"),
        forms=(),
        third_parties=(),
    ),
    normal_change_patterns=(
        r"/main\.[0-9a-f]{8,}\.js",                # hashed Angular bundle
        r"/(polyfills|runtime|styles)\.[0-9a-f]{8,}\.(js|css)",
    ),
)


# All built-in profiles, ordered so platform-specific (CMS/commerce/
# site-builder/meta-framework) come before the generic SPA libraries —
# a Next.js site is also "React", but the more specific profile should
# win the primary slot.
ALL_PROFILES: tuple[FrameworkProfile, ...] = (
    WORDPRESS, SHOPIFY, WIX, WEBFLOW, NEXTJS, VUE, ANGULAR, REACT,
)
