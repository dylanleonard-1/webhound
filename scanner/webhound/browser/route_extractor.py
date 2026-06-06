# WebHound — webhound/browser/route_extractor.py
# Phase-6B: client-side route discovery. SPA routers register routes
# that never appear as <a href> in static HTML; this module collects
# route *candidates* from the rendered page without navigating to any
# of them. Routes are discovery output only — Phase 2 does NOT crawl
# them (a later phase may feed in-scope ones to the static crawler).
#
# Sources, in confidence order:
#   anchor        — resolved <a href> from the rendered DOM (strongest)
#   data_href     — data-href attributes used by JS click handlers
#   next_data     — window.__NEXT_DATA__ (Next.js page + route info)
#   nuxt          — window.__NUXT__ (Nuxt routePath)
#   script_string — route-shaped string literals in inline scripts
#                   (weakest; aggressively filtered)

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from webhound.browser.models import BrowserTelemetry

logger = logging.getLogger(__name__)

_MAX_ROUTES = 500
_MAX_SCRIPT_STRING_ROUTES = 150

# Route-shaped string literal inside JS: starts with /, sane chars,
# at least one letter, no spaces. Next.js-style params (/blog/[slug])
# and Express-style params (/user/:id) both allowed.
_ROUTE_LITERAL_RE = re.compile(
    r"""["'](/(?:[A-Za-z0-9_\-./:\[\]]){1,160})["']"""
)

# Static-asset and protocol-ish paths that match the route shape but
# are not navigable client routes.
_ASSET_SUFFIXES = (
    ".js", ".mjs", ".css", ".map", ".json", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".webp", ".avif", ".ico", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".pdf", ".txt",
    ".xml", ".wasm",
)
_NOISE_PREFIXES = ("//", "/_next/static", "/_nuxt/", "/static/",
                   "/assets/", "/node_modules/", "/__webpack")

# Captures router config + __NEXT_DATA__/__NUXT__ + data-href in one
# read-only evaluate.
ROUTE_PROBE_JS = """
() => {
  const out = { nextPage: null, nextRoutes: [], nuxtRoute: null,
                dataHrefs: [] };
  try {
    const nd = window.__NEXT_DATA__;
    if (nd) {
      if (typeof nd.page === 'string') out.nextPage = nd.page;
      const dm = nd.dynamicIds || [];
      if (nd.props && nd.props.pageProps === undefined) {}
      // Build-manifest route lists when exposed.
      const bm = window.__BUILD_MANIFEST;
      if (bm && typeof bm === 'object') {
        for (const k of Object.keys(bm)) {
          if (k.startsWith('/') && out.nextRoutes.length < 200) {
            out.nextRoutes.push(k);
          }
        }
      }
    }
  } catch (e) {}
  try {
    const nx = window.__NUXT__;
    if (nx) {
      const rp = (nx.routePath || (nx.state && nx.state.routePath));
      if (typeof rp === 'string') out.nuxtRoute = rp;
    }
  } catch (e) {}
  try {
    for (const el of document.querySelectorAll('[data-href]')) {
      if (out.dataHrefs.length >= 200) break;
      const v = el.getAttribute('data-href');
      if (v) out.dataHrefs.push(v);
    }
  } catch (e) {}
  return out;
}
"""


def _is_route_shaped(path: str) -> bool:
    if not path.startswith("/") or path.startswith(_NOISE_PREFIXES):
        return False
    if not re.search(r"[A-Za-z]", path):
        return False
    lower = path.lower()
    if lower.endswith(_ASSET_SUFFIXES):
        return False
    return True


def routes_from_script_text(text: str) -> list[str]:
    """Extract route-shaped string literals from inline JS. Weakest
    source — every candidate passes the shape filter and the result
    is capped."""
    if not text:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for m in _ROUTE_LITERAL_RE.finditer(text):
        path = m.group(1)
        if path in seen or not _is_route_shaped(path):
            continue
        seen.add(path)
        out.append(path)
        if len(out) >= _MAX_SCRIPT_STRING_ROUTES:
            break
    return out


def _push(tel: BrowserTelemetry, seen: set[str], route: str,
          source: str) -> None:
    if len(tel.client_routes) >= _MAX_ROUTES:
        return
    key = route.split("#", 1)[0]
    if not key or key in seen:
        return
    seen.add(key)
    tel.client_routes.append((key, source))


def collect_routes(tel: BrowserTelemetry, probe: object = None) -> None:
    """Fold every route source on *tel* (plus the optional ROUTE_PROBE_JS
    payload) into ``tel.client_routes`` as deduped (route, source)
    pairs. Pure — no navigation, no network."""
    seen: set[str] = set()

    # 1. Rendered anchors — same-origin ones become route candidates
    #    as paths; cross-origin anchors are links, not client routes.
    page_host = ""
    try:
        page_host = (urlparse(tel.final_url or tel.page_url).hostname
                     or "").lower()
    except Exception:  # noqa: BLE001
        pass
    for link in tel.rendered_links:
        try:
            parsed = urlparse(link)
        except Exception:  # noqa: BLE001
            continue
        if (parsed.hostname or "").lower() != page_host:
            continue
        path = parsed.path or "/"
        if _is_route_shaped(path):
            _push(tel, seen, path, "anchor")

    # 2. Probe payload (__NEXT_DATA__ / __BUILD_MANIFEST / __NUXT__ /
    #    data-href).
    if isinstance(probe, dict):
        next_page = probe.get("nextPage")
        if isinstance(next_page, str) and _is_route_shaped(next_page):
            _push(tel, seen, next_page, "next_data")
        for r in probe.get("nextRoutes") or []:
            if isinstance(r, str) and _is_route_shaped(r):
                _push(tel, seen, r, "next_data")
        nuxt = probe.get("nuxtRoute")
        if isinstance(nuxt, str) and _is_route_shaped(nuxt):
            _push(tel, seen, nuxt, "nuxt")
        for v in probe.get("dataHrefs") or []:
            if isinstance(v, str) and _is_route_shaped(v):
                _push(tel, seen, v, "data_href")

    # 3. Route-shaped literals inside inline script snippets.
    for script in tel.rendered_scripts:
        if not script.is_inline or not script.snippet:
            continue
        for path in routes_from_script_text(script.snippet):
            _push(tel, seen, path, "script_string")


async def capture_routes(page, tel: BrowserTelemetry) -> None:
    """Evaluate the route probe and fold all sources into the
    telemetry. Failures append an error note; never raise."""
    probe = None
    try:
        probe = await page.evaluate(ROUTE_PROBE_JS)
    except Exception as exc:  # noqa: BLE001
        tel.errors.append(f"route probe failed: {type(exc).__name__}")
    try:
        collect_routes(tel, probe)
    except Exception as exc:  # noqa: BLE001
        tel.errors.append(f"route collection failed: {type(exc).__name__}")
