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
from urllib.parse import urlparse

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
