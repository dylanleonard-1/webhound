# WebHound — scanner/webhound/graph/graph_builder.py
# Phase-20 Task 2-8: build a SecurityGraph from a completed scan. Reads
# whatever is available (static crawl artifacts, browser telemetry,
# grouped findings, WADE timeline, threat correlations) and gracefully
# skips missing pieces — a static-only scan still produces a valid graph.
#
# Deterministic: same scan → same graph (node ids are content-derived).

from __future__ import annotations

import logging
from typing import Any

from webhound.graph.models import EdgeType, NodeType, SecurityGraph
from webhound.graph.relationship_extractor import (
    FINDING_TARGET_HINT,
    WADE_TARGET_TYPE,
    hostname,
    normalize_url,
    vendor_for_host,
)

logger = logging.getLogger(__name__)

# Security-relevant headers worth graphing (avoids node explosion).
_GRAPH_HEADERS = frozenset({
    "content-security-policy", "strict-transport-security",
    "x-frame-options", "x-content-type-options", "referrer-policy",
    "permissions-policy", "set-cookie",
})


class GraphBuilder:
    def __init__(self) -> None:
        self.graph = SecurityGraph()

    def build(
        self,
        scan_result: Any,
        *,
        crawl_results: list | None = None,
        browser: Any = None,
        primary_host: str | None = None,
        api_inventory: Any = None,
    ) -> SecurityGraph:
        g = self.graph
        meta = getattr(scan_result, "metadata", {}) or {}
        primary = (primary_host
                   or hostname(getattr(getattr(scan_result, "target", None),
                                       "base_url", "")) or "").lower()
        # When a canonical API inventory is supplied, the browser pass stops
        # minting one API_ENDPOINT node per network request (the 1099-node
        # query-variant explosion); API nodes come from the deduped inventory
        # instead (one per METHOD+host+path, framework/analytics excluded).
        self._use_api_inventory = api_inventory is not None

        site = g.node(NodeType.SITE, primary or "site", label=primary or "site")
        self._site_id = site.id

        # 1. Pages + their assets (static crawl).
        for r in crawl_results or []:
            self._add_page(g, site, r, primary)

        # 2. Browser-rendered pages + assets (graceful if absent).
        if browser is not None:
            try:
                self._add_browser(g, site, browser, primary)
            except Exception:  # noqa: BLE001
                logger.debug("graph browser pass failed", exc_info=True)

        # 2c. Canonical API endpoints (single source of truth). One node per
        # deduped endpoint; framework/analytics classes are excluded so node +
        # connection counts deflate.
        if self._use_api_inventory:
            try:
                self._add_api_inventory(g, site, api_inventory, primary)
            except Exception:  # noqa: BLE001
                logger.debug("graph api-inventory pass failed", exc_info=True)

        # 2b. Scan-wide external-host inventory (script/stylesheet/img/link/iframe/
        # form-action/js-request/css-import + CSP-declared + redirect hosts). The
        # static + browser passes above only graph <script src>/<iframe src> + cross-
        # origin fetch hosts; a same-origin SPA (Next.js/Vercel) therefore yielded 0
        # third-parties even with a populated inventory. Ingest the full inventory so
        # every discovered external domain becomes a THIRD_PARTY_DOMAIN (+ vendor) node.
        self._add_inventory_hosts(g, site, meta, primary)

        # 3. Frameworks → technology nodes.
        for det in (meta.get("frameworks") or {}).get("detected", []):
            name = det.get("framework")
            if name:
                tech = g.node(NodeType.TECHNOLOGY, name.lower(), label=name,
                              confidence=float(det.get("confidence", 0.5)))
                g.edge(site, tech, EdgeType.CONTAINS, source="frameworks")

        # 4. Findings.
        for gf in getattr(scan_result, "grouped_findings", []) or []:
            self._add_finding(g, gf)

        # 5. WADE changes.
        for rec in (meta.get("wade_timeline") or {}).get("records", []):
            self._add_wade_change(g, rec)

        # 6. Threat indicators.
        for corr in meta.get("threat_correlations") or []:
            self._add_threat(g, corr)
        return g

    # ------------------------------------------------------------------

    def _ensure_domain_and_vendor(self, g: SecurityGraph, host: str,
                                  primary: str) -> Any | None:
        """Create a THIRD_PARTY_DOMAIN node (+ vendor) for an external
        host, or None for first-party/empty."""
        if not host or host == primary:
            return None
        from webhound.browser.network_capture import _registrable
        if primary and _registrable(host) == _registrable(primary):
            return None
        dom = g.node(NodeType.THIRD_PARTY_DOMAIN, host, label=host)
        vreg, vcat, trusted = vendor_for_host(host)
        if vreg:
            vendor = g.node(NodeType.VENDOR, vreg, label=vreg,
                            metadata={"category": vcat, "trusted": trusted})
            g.edge(dom, vendor, EdgeType.BELONGS_TO_VENDOR,
                   source="domain_classifier",
                   confidence=0.95 if trusted else 0.6)
        else:
            dom.metadata.setdefault("vendor", "unknown")
        return dom

    def _add_inventory_hosts(self, g, site, meta, primary) -> None:
        """Materialize a THIRD_PARTY_DOMAIN (+ vendor) node for every external host in
        the scan-wide inventory (metadata['external_host_inventory']). Idempotent —
        _ensure_domain_and_vendor skips first-party hosts and g.node de-dupes, so hosts
        already added by the static/browser passes are not duplicated."""
        for host in (meta.get("external_host_inventory") or []):
            h = (hostname(host) or host or "").lower()
            dom = self._ensure_domain_and_vendor(g, h, primary)
            if dom is not None:
                g.edge(site, dom, EdgeType.CONTAINS, source="host_inventory")

    def _add_page(self, g, site, r, primary) -> None:
        resp = getattr(r, "response", None)
        arts = getattr(r, "artifacts", None)
        url = normalize_url(getattr(resp, "url", "")
                            or getattr(arts, "url", ""))
        if not url:
            return
        page = g.node(NodeType.PAGE, url, label=url)
        g.edge(site, page, EdgeType.CONTAINS)
        if arts is None:
            return

        # Scripts.
        for s in getattr(arts, "scripts", []) or []:
            if getattr(s, "is_inline", False) and getattr(s, "content", None):
                inline = g.node(NodeType.INLINE_SCRIPT,
                                f"{url}#inline:{hash(s.content) & 0xffffff}",
                                label="inline script")
                g.edge(page, inline, EdgeType.CONTAINS)
            elif getattr(s, "src", None):
                src = normalize_url(s.src)
                node = g.node(NodeType.SCRIPT, src, label=src)
                g.edge(page, node, EdgeType.LOADS)
                dom = self._ensure_domain_and_vendor(g, hostname(src), primary)
                if dom is not None:
                    g.edge(node, dom, EdgeType.LOADS_FROM)

        # Forms.
        for f in getattr(arts, "forms", []) or []:
            action = getattr(f, "action_url", None) or f"{url}#form"
            form = g.node(NodeType.FORM, normalize_url(action),
                          label=f"form → {action}",
                          metadata={"password": bool(
                              getattr(f, "has_password_field", False)),
                              "method": getattr(f, "method", "GET")})
            g.edge(page, form, EdgeType.CONTAINS)
            g.edge(form, page, EdgeType.OBSERVED_ON)
            if getattr(f, "action_url", None):
                g.edge(form, g.node(NodeType.API_ENDPOINT,
                                    normalize_url(f.action_url),
                                    label=f.action_url),
                       EdgeType.SUBMITS_TO)

        # Iframes.
        for ifr in getattr(arts, "iframes", []) or []:
            src = getattr(ifr, "src_url", None)
            if not src:
                continue
            node = g.node(NodeType.IFRAME, normalize_url(src), label=src,
                          metadata={"hidden": bool(
                              getattr(ifr, "is_hidden", False))})
            g.edge(page, node, EdgeType.EMBEDS)
            dom = self._ensure_domain_and_vendor(g, hostname(src), primary)
            if dom is not None:
                g.edge(node, dom, EdgeType.LOADS_FROM)

        # Cookies.
        for raw in getattr(arts, "cookies", []) or []:
            name = str(raw).split("=", 1)[0].strip()
            if name:
                ck = g.node(NodeType.COOKIE, f"{primary}:{name}", label=name)
                g.edge(page, ck, EdgeType.SETS_COOKIE)

        # Headers (security-relevant).
        for k in (getattr(arts, "response_headers", {}) or {}):
            kl = k.lower()
            if kl in _GRAPH_HEADERS:
                hn = g.node(NodeType.HEADER, f"{primary}:{kl}", label=k)
                g.edge(page, hn, EdgeType.HAS_HEADER)

    def _add_browser(self, g, site, browser, primary) -> None:
        if not getattr(browser, "available", False):
            return
        for tel in getattr(browser, "telemetries", []) or []:
            url = normalize_url(getattr(tel, "final_url", None)
                                or getattr(tel, "page_url", ""))
            if not url:
                continue
            rp = g.node(NodeType.RENDERED_PAGE, url, label=f"rendered {url}",
                        source="browser")
            g.edge(site, rp, EdgeType.CONTAINS, source="browser")
            # Rendered scripts.
            for s in getattr(tel, "rendered_scripts", []) or []:
                if getattr(s, "src", None):
                    node = g.node(NodeType.SCRIPT, normalize_url(s.src),
                                  label=s.src, source="browser")
                    g.edge(rp, node, EdgeType.LOADS, source="browser")
                    dom = self._ensure_domain_and_vendor(
                        g, hostname(s.src), primary)
                    if dom is not None:
                        g.edge(node, dom, EdgeType.LOADS_FROM, source="browser")
            # Observed API calls. Legacy path (one node per request, keyed on
            # the query-bearing URL) ONLY when no canonical inventory was
            # supplied — that path caused the 1099-node explosion. With an
            # inventory, _add_api_inventory mints the deduped nodes instead.
            if self._use_api_inventory:
                continue
            for art in getattr(tel, "artifacts", []) or []:
                kind = (getattr(art, "initiator_kind", "") or "").lower()
                if kind in ("fetch", "xhr", "eventsource", "websocket"):
                    api = g.node(NodeType.API_ENDPOINT, normalize_url(art.url),
                                 label=art.url, source="browser")
                    g.edge(rp, api, EdgeType.CALLS, source="browser")
                    dom = self._ensure_domain_and_vendor(
                        g, hostname(art.url), primary)
                    if dom is not None:
                        g.edge(api, dom, EdgeType.LOADS_FROM, source="browser")

    def _add_api_inventory(self, g, site, inv, primary) -> None:
        """Materialize ONE API_ENDPOINT node per canonical endpoint (deduped by
        METHOD+host+path; framework internals + analytics excluded). The node
        carries its endpoint_class so the export can count only the headline
        classes. Connections deflate: one CALLS edge per endpoint, not per
        request."""
        for ep in inv.graph_endpoints():
            node = g.node(NodeType.API_ENDPOINT, ep.url, label=ep.url,
                          source="api_inventory",
                          metadata={
                              "endpoint_class": ep.endpoint_class.value,
                              "in_headline": ep.in_headline,
                              "party": ep.party,
                              "method": ep.method,
                              "observed_count": ep.observed_count,
                              "tags": sorted(ep.tags),
                          })
            g.edge(site, node, EdgeType.CALLS, source="api_inventory")
            if ep.party == "third":
                dom = self._ensure_domain_and_vendor(g, ep.host, primary)
                if dom is not None:
                    g.edge(node, dom, EdgeType.LOADS_FROM, source="api_inventory")

    def _add_finding(self, g, gf) -> None:
        fid = str(getattr(gf, "finding_ids", [None])[0]
                  or getattr(gf, "title", ""))
        title = getattr(gf, "title", "")
        engine = getattr(gf, "scanner_engine", "") or ""
        node = g.node(NodeType.FINDING, f"{engine}:{title}", label=title,
                      source=engine,
                      confidence=float(getattr(gf, "confidence", 1.0) or 1.0),
                      metadata={
                          "severity": getattr(getattr(gf, "severity", None),
                                              "value", "unknown"),
                          "engine": engine,
                          "finding_type": (getattr(gf, "metadata", {}) or {})
                          .get("finding_type")})
        # Link to the affected asset by engine hint + evidence location.
        hint = FINDING_TARGET_HINT.get(engine)
        md = getattr(gf, "metadata", {}) or {}
        host = md.get("host") or md.get("domain")
        urls = getattr(gf, "affected_urls", []) or []
        page_url = normalize_url(urls[0]) if urls else None

        target = None
        if hint == "third_party_domain" and host:
            target = g.find_node(NodeType.THIRD_PARTY_DOMAIN, host) \
                or g.node(NodeType.THIRD_PARTY_DOMAIN, host, label=host)
        elif page_url:
            # Link to a page only if it was actually crawled/rendered. We
            # do NOT fabricate a PAGE node for an uncrawled URL — e.g.
            # sensitive_paths probes /phpmyadmin, /wp-config.php etc. that
            # 403'd and were never real pages; creating page nodes for them
            # would inflate the graph's page_count (the '24 pages' on a
            # 1-page site bug). Anchor those to the site node instead, so
            # the finding is connected but page_count stays honest.
            target = (g.find_node(NodeType.PAGE, page_url)
                      or g.find_node(NodeType.RENDERED_PAGE, page_url)
                      or g.get_node(getattr(self, "_site_id", None)))
        if target is not None:
            g.edge(target, node, EdgeType.RELATED_TO_FINDING, source=engine)

    def _add_wade_change(self, g, rec) -> None:
        diff = rec.get("diff_type", "")
        value = rec.get("value") or rec.get("url") or diff
        change = g.node(NodeType.WADE_CHANGE,
                        rec.get("change_key", f"{diff}:{value}"),
                        label=f"{diff}: {value}", source="wade",
                        metadata={"change_type": rec.get("change_type"),
                                  "band": rec.get("band")})
        target_type = WADE_TARGET_TYPE.get(diff)
        if not target_type or not value:
            return
        nt = NodeType(target_type)
        target = g.find_node(nt, normalize_url(str(value))) \
            or g.find_node(nt, hostname(str(value))) \
            or g.node(nt, normalize_url(str(value)), label=str(value),
                      source="wade")
        g.edge(change, target, EdgeType.CHANGED_IN_WADE, source="wade")

    def _add_threat(self, g, corr) -> None:
        ctype = corr.get("correlation_type", "threat")
        ti = g.node(NodeType.THREAT_INDICATOR, f"corr:{ctype}",
                    label=ctype, source="threat_intel",
                    metadata={"severity": corr.get("severity"),
                              "confidence": corr.get("confidence")})
        for host in corr.get("hosts", []) or []:
            h = hostname(host) or host
            dom = g.find_node(NodeType.THIRD_PARTY_DOMAIN, h) \
                or g.node(NodeType.THIRD_PARTY_DOMAIN, h, label=h)
            g.edge(ti, dom, EdgeType.MATCHES_THREAT_INTEL,
                   source="threat_intel")


def build_graph(scan_result: Any, **kw: Any) -> SecurityGraph:
    return GraphBuilder().build(scan_result, **kw)
