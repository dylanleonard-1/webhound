# WebHound — scanner/webhound/core/visibility/surfaces.py
# Phases 5-8: build the forms / API / assets / third-party sections of the
# visibility report by AGGREGATING the existing discovery engines' output
# across the whole scan. No new extraction — this folds what form_discovery,
# endpoint_discovery, url_discovery's host inventory, and the domain classifier
# already produced into one report-shaped surface inventory.
#
# Safe-mode: pure aggregation. No network, no submission, no JS execution.

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from webhound.engines.forms.form_discovery import (
    DiscoveredForm,
    FormDiscoveryEngine,
)

# ---------------------------------------------------------------------------
# Phase 5 — forms inventory + lightweight purpose classification
# ---------------------------------------------------------------------------

_SEARCH_NAMES = frozenset({"q", "query", "search", "s", "keyword", "keywords", "term"})
_PAYMENT_RE = re.compile(
    r"(card|cc[-_]?num|creditcard|cvv|cvc|cardnumber|expir|billing)", re.I
)
_CONTACT_RE = re.compile(r"(email|e-mail|message|comment|subject|phone)", re.I)
_FORM_SAMPLE_CAP = 50


def _classify_form(form: DiscoveredForm) -> str:
    """Best-effort purpose label from a DiscoveredForm's shape. Inventory only —
    never a security verdict."""
    names = [n.lower() for n in (form.input_names or ()) if n]
    if form.has_password_field:
        return "login"
    if form.has_file_field:
        return "file_upload"
    if any(_PAYMENT_RE.search(n) for n in names):
        return "payment"
    if form.method == "GET" and any(n in _SEARCH_NAMES for n in names):
        return "search"
    if any(_CONTACT_RE.search(n) for n in names):
        return "contact"
    return "generic"


def _form_key(form: DiscoveredForm) -> tuple:
    """Dedup key so a form seen in both static + rendered passes counts once."""
    return (
        form.source_page,
        form.action_url,
        form.method,
        tuple(sorted(n for n in (form.input_names or ()) if n)),
    )


def build_forms_section(
    crawl_results: list,
    *,
    browser_discovery: Any | None = None,
) -> dict:
    """Aggregate every static + rendered form across the scan into the report's
    forms section. Reuses FormDiscoveryEngine per page."""
    engine = FormDiscoveryEngine()
    rendered_by_page = _rendered_forms_by_page(browser_discovery)

    seen: set[tuple] = set()
    forms: list[DiscoveredForm] = []
    for r in crawl_results or []:
        arts = getattr(r, "artifacts", None)
        if arts is None:
            continue
        rendered = rendered_by_page.get(_norm(getattr(arts, "url", None)), [])
        report = engine.discover(arts, rendered_forms=rendered)
        for f in report.forms:
            key = _form_key(f)
            if key in seen:
                continue
            seen.add(key)
            forms.append(f)

    by_type: dict[str, int] = {}
    by_method: dict[str, int] = {}
    external_domains: set[str] = set()
    samples: list[dict] = []
    for f in forms:
        kind = _classify_form(f)
        by_type[kind] = by_type.get(kind, 0) + 1
        by_method[f.method] = by_method.get(f.method, 0) + 1
        if f.action_is_external and f.action_domain:
            external_domains.add(f.action_domain)
        if len(samples) < _FORM_SAMPLE_CAP:
            samples.append({
                "page": f.source_page,
                "action": f.action_url,
                "method": f.method,
                "type": kind,
                "inputs": list(f.input_names)[:20],
                "has_password": f.has_password_field,
                "has_file": f.has_file_field,
                "action_is_external": f.action_is_external,
                "origin": f.origin,
            })

    return {
        "count": len(forms),
        "by_type": by_type,
        "by_method": by_method,
        "login_forms": by_type.get("login", 0),
        "search_forms": by_type.get("search", 0),
        "upload_forms": by_type.get("file_upload", 0),
        "payment_forms": by_type.get("payment", 0),
        "external_action_domains": sorted(external_domains),
        "samples": samples,
    }


def _rendered_forms_by_page(browser_discovery: Any | None) -> dict[str, list]:
    """Group browser RenderedForm objects by normalized page URL so each page's
    static + rendered forms are discovered together."""
    out: dict[str, list] = {}
    if browser_discovery is None:
        return out
    try:
        forms = browser_discovery.get_all_forms()
    except Exception:  # noqa: BLE001
        return out
    for rf in forms or []:
        page = _norm(getattr(rf, "page_url", None))
        out.setdefault(page, []).append(rf)
    return out


def _norm(url: str | None) -> str:
    if not url:
        return ""
    try:
        p = urlparse(url)
        return f"{(p.scheme or '').lower()}://{(p.hostname or '').lower()}{p.path or '/'}"
    except Exception:  # noqa: BLE001
        return url or ""


# ---------------------------------------------------------------------------
# Phase 6 — API endpoint inventory (passive; reuses endpoint_discovery)
# ---------------------------------------------------------------------------

_API_SAMPLE_CAP = 60


def _bare(url: str) -> str:
    """scheme://host/path — drop query/fragment so per-call query variance
    doesn't explode the endpoint inventory."""
    try:
        p = urlparse(url)
        return f"{(p.scheme or 'https').lower()}://{(p.netloc or '').lower()}{p.path or ''}"
    except Exception:  # noqa: BLE001
        return url


def build_api_section(
    crawl_results: list,
    *,
    browser_discovery: Any | None = None,
    primary_host: str | None = None,
) -> dict:
    """Aggregate the passive API surface across the scan: static references
    (endpoint_discovery._gather_endpoints) + browser-observed traffic
    (network_capture.looks_like_api). Inventory only — no endpoint is probed."""
    from webhound.engines.api_discovery.endpoint_discovery import (
        _classify,
        _gather_endpoints,
    )

    # bare_url -> {"tags": set, "origins": set("static"|"observed")}
    endpoints: dict[str, dict] = {}

    def _record(url: str, origin: str) -> None:
        bare = _bare(url)
        if not bare:
            return
        entry = endpoints.setdefault(bare, {"tags": set(), "origins": set()})
        entry["tags"].update(_classify(url))
        entry["origins"].add(origin)

    # 1. Static references in page HTML + inline JS. Relative endpoint paths
    #    (e.g. "/api/v1/users") are resolved against the page URL so same-origin
    #    classification works.
    for r in crawl_results or []:
        arts = getattr(r, "artifacts", None)
        if arts is None:
            continue
        page_url = getattr(arts, "url", None) or ""
        try:
            for u in _gather_endpoints(arts):
                resolved = urljoin(page_url, u) if page_url else u
                _record(resolved, "static")
        except Exception:  # noqa: BLE001
            continue

    # 2. Browser-observed network traffic that looks like an API.
    if browser_discovery is not None:
        try:
            from webhound.browser.network_capture import looks_like_api

            for art in browser_discovery.get_all_network_requests() or []:
                url = getattr(art, "url", None)
                if not url:
                    continue
                is_api, _reason = looks_like_api(
                    url,
                    initiator_kind=getattr(art, "initiator_kind", None),
                    content_type=getattr(art, "content_type", None),
                )
                if is_api:
                    _record(url, "observed")
        except Exception:  # noqa: BLE001
            pass

    primary = (primary_host or "").lower()
    by_type: dict[str, int] = {}
    same_origin = 0
    cross_origin = 0
    observed = 0
    samples: list[dict] = []
    for bare, entry in endpoints.items():
        for tag in entry["tags"]:
            by_type[tag] = by_type.get(tag, 0) + 1
        host = (urlparse(bare).hostname or "").lower()
        if primary and host and host == primary:
            same_origin += 1
        elif host:
            cross_origin += 1
        if "observed" in entry["origins"]:
            observed += 1
        if len(samples) < _API_SAMPLE_CAP:
            samples.append({
                "url": bare,
                "tags": sorted(entry["tags"]),
                "origins": sorted(entry["origins"]),
            })

    return {
        "count": len(endpoints),
        "by_type": by_type,
        "same_origin": same_origin,
        "cross_origin": cross_origin,
        "observed_in_browser": observed,
        "rest": by_type.get("rest", 0),
        "graphql": by_type.get("graphql", 0),
        "websocket": by_type.get("websocket", 0),
        "soap": by_type.get("soap", 0),
        "api_spec": by_type.get("api_spec", 0),
        "internal_admin": by_type.get("internal_admin", 0),
        "samples": samples,
    }


# ---------------------------------------------------------------------------
# Phase 7 — asset intelligence (scripts/styles/images/fonts/media)
# ---------------------------------------------------------------------------

_ASSET_EXT: list[tuple[str, tuple[str, ...]]] = [
    ("script", (".js", ".mjs", ".cjs")),
    ("style", (".css",)),
    ("image", (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif",
               ".ico", ".bmp")),
    ("font", (".woff", ".woff2", ".ttf", ".otf", ".eot")),
    ("media", (".mp4", ".webm", ".mp3", ".wav", ".ogg", ".mov", ".m4a")),
    ("document", (".pdf",)),
    ("wasm", (".wasm",)),
]
_ASSET_SAMPLE_CAP = 60


def _asset_type(url: str) -> str:
    path = (urlparse(url).path or "").lower()
    for kind, exts in _ASSET_EXT:
        if path.endswith(exts):
            return kind
    return "other"


def build_assets_section(
    crawl_results: list,
    *,
    browser_discovery: Any | None = None,
    primary_host: str | None = None,
) -> dict:
    """Inventory every static + rendered asset URL across the scan, classified
    by type and same- vs third-party host. Reuses the extractor's per-page
    asset fields + the browser's collected script URLs. Inventory only."""
    primary = (primary_host or "").lower()
    assets: dict[str, str] = {}   # url -> type
    inline_scripts = 0

    def _add(url: str | None) -> None:
        if url and url not in assets:
            assets[url] = _asset_type(url)

    for r in crawl_results or []:
        arts = getattr(r, "artifacts", None)
        if arts is None:
            continue
        for u in getattr(arts, "external_script_urls", None) or []:
            _add(u)
        for u in getattr(arts, "external_stylesheet_urls", None) or []:
            _add(u)
        for u in getattr(arts, "external_image_urls", None) or []:
            _add(u)
        for s in getattr(arts, "scripts", None) or []:
            if getattr(s, "is_external", False) and getattr(s, "src", None):
                _add(s.src)
            elif getattr(s, "is_inline", False):
                inline_scripts += 1

    if browser_discovery is not None:
        try:
            for u in browser_discovery.get_all_script_urls() or []:
                _add(u)
        except Exception:  # noqa: BLE001
            pass

    by_type: dict[str, int] = {}
    third_party = 0
    same_host = 0
    samples: list[dict] = []
    for url, kind in assets.items():
        by_type[kind] = by_type.get(kind, 0) + 1
        host = (urlparse(url).hostname or "").lower()
        if primary and host and host != primary:
            third_party += 1
        elif host:
            same_host += 1
        if len(samples) < _ASSET_SAMPLE_CAP:
            samples.append({"url": url, "type": kind})

    return {
        "count": len(assets),
        "by_type": by_type,
        "inline_scripts": inline_scripts,
        "third_party_assets": third_party,
        "same_host_assets": same_host,
        "scripts": by_type.get("script", 0),
        "stylesheets": by_type.get("style", 0),
        "images": by_type.get("image", 0),
        "fonts": by_type.get("font", 0),
        "media": by_type.get("media", 0),
        "samples": samples,
    }


# ---------------------------------------------------------------------------
# Phase 8 — third-party mapping (reuses the domain classifier)
# ---------------------------------------------------------------------------

_TP_SAMPLE_CAP = 100


def build_third_party_section(
    external_hosts: list[str] | None,
    *,
    primary_host: str | None = None,
) -> dict:
    """Classify every external host the scan discovered via the local domain
    classifier (graph.relationship_extractor.vendor_for_host) into vendor
    category + trust. Inventory only — no network, no reputation lookups here
    (the threat-intel engine owns enrichment)."""
    from webhound.graph.relationship_extractor import vendor_for_host

    primary = (primary_host or "").lower()
    by_category: dict[str, int] = {}
    by_vendor: dict[str, int] = {}
    trusted = 0
    unknown = 0
    hosts: list[dict] = []

    seen: set[str] = set()
    for host in external_hosts or []:
        h = (host or "").lower()
        if not h or h == primary or h in seen:
            continue
        seen.add(h)
        vendor, category, is_trusted = vendor_for_host(h)
        by_category[category] = by_category.get(category, 0) + 1
        if vendor:
            by_vendor[vendor] = by_vendor.get(vendor, 0) + 1
        if is_trusted:
            trusted += 1
        if category == "unknown":
            unknown += 1
        if len(hosts) < _TP_SAMPLE_CAP:
            hosts.append({
                "host": h,
                "vendor": vendor,
                "category": category,
                "trusted": is_trusted,
            })

    return {
        "count": len(seen),
        "by_category": by_category,
        "trusted": trusted,
        "unknown": unknown,
        "vendor_count": len(by_vendor),
        "vendors": sorted(by_vendor.keys())[:_TP_SAMPLE_CAP],
        "hosts": hosts,
    }
