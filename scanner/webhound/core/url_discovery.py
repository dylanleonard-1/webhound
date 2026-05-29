# WebHound — scanner/webhound/core/url_discovery.py
# Broadened third-party URL discovery — used by the threat_intel engine to
# build a complete inventory of external hosts the page actually touches.
#
# Phase 2 of the scanner accuracy audit: the original PageArtifacts only
# pulled script/style/img/iframe/form/css-import. This module covers the
# rest of the surface (srcset, video/audio sources, preload, preconnect,
# dns-prefetch, modulepreload, manifest, canonical, OG/Twitter URLs,
# JSON-LD, inline style url(), favicon-link, video poster, object/embed,
# meta refresh, …) AND adds JS-content URL extraction so referenced JS
# files contribute the hosts they fetch from.
#
# Safe-mode: parsing only. No HTTP requests, no JS execution.

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Tag


# ---------------------------------------------------------------------------
# Regexes for JS-content extraction. We never *run* JS — we scan source
# strings for URL-shaped tokens. Each pattern is conservative; false
# positives turn into "domain seen but never reported" rather than findings.
# ---------------------------------------------------------------------------

_JS_FETCH_RE = re.compile(r'\bfetch\s*\(\s*["\'`]([^"\'`]+)["\'`]')
_JS_XHR_RE = re.compile(
    r'\.open\s*\(\s*["\'`](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["\'`]\s*,\s*'
    r'["\'`]([^"\'`]+)["\'`]',
    re.IGNORECASE,
)
_JS_WS_RE = re.compile(r'\bnew\s+WebSocket\s*\(\s*["\'`]([^"\'`]+)["\'`]')
_JS_EVENTSOURCE_RE = re.compile(r'\bnew\s+EventSource\s*\(\s*["\'`]([^"\'`]+)["\'`]')
_JS_IMPORT_RE = re.compile(r'\bimport\s*\(\s*["\'`]([^"\'`]+)["\'`]\s*\)')
_JS_SOURCEMAP_RE = re.compile(
    r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
    re.IGNORECASE,
)
# Bare URLs embedded in string literals. Matches absolute http(s) and
# protocol-relative URLs. Used after the structural patterns above to catch
# CDN strings, hard-coded API hosts, etc.
_JS_URL_LITERAL_RE = re.compile(
    r'["\'`]((?:https?:)?//[^\s"\'`<>]{4,})["\'`]'
)

# Generic url() inside CSS / inline style.
_CSS_URL_RE = re.compile(
    r'url\s*\(\s*[\'"]?([^\'")]+)[\'"]?\s*\)',
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _DiscoveredUrl:
    url: str
    kind: str           # e.g. "script", "preconnect", "js_fetch", …
    source: str         # "static_html" | "js_content"
    initiator: str | None = None  # which JS file / page surfaced it


@dataclass
class ExtractedExternalUrls:
    """Per-page bucket of URLs the Phase-1 PageArtifacts missed. Stored on
    PageArtifacts via the new external_*_urls fields; the threat_intel
    engine consumes both shapes."""

    srcset: list[str] = field(default_factory=list)
    video_audio: list[str] = field(default_factory=list)
    object_embed: list[str] = field(default_factory=list)
    meta_refresh: list[str] = field(default_factory=list)
    preconnect: list[str] = field(default_factory=list)
    dns_prefetch: list[str] = field(default_factory=list)
    preload: list[str] = field(default_factory=list)        # preload + modulepreload
    manifest: list[str] = field(default_factory=list)
    canonical: list[str] = field(default_factory=list)
    og_twitter: list[str] = field(default_factory=list)
    jsonld: list[str] = field(default_factory=list)
    inline_style: list[str] = field(default_factory=list)
    favicon: list[str] = field(default_factory=list)


def _resolve(base_url: str, raw: str | None) -> str | None:
    """Resolve `raw` against `base_url` and return an absolute URL, or None
    if the URL is unusable. Skips data:, javascript:, mailto:, tel:, blob:."""
    if not raw:
        return None
    raw = raw.strip()
    if not raw or raw.startswith(("#", "data:", "javascript:", "mailto:",
                                  "tel:", "blob:")):
        return None
    try:
        absolute = urljoin(base_url, raw)
        parsed = urlparse(absolute)
        if not parsed.scheme or not parsed.netloc:
            return None
        if parsed.scheme not in ("http", "https", "ws", "wss"):
            return None
        return absolute
    except Exception:  # noqa: BLE001 — malformed URL = silently skip
        return None


def _hostname(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return (urlparse(url).hostname or "").lower() or None
    except Exception:  # noqa: BLE001
        return None


def _is_external(url: str, page_host: str | None) -> bool:
    host = _hostname(url)
    return bool(host) and host != page_host


# ---------------------------------------------------------------------------
# Static-HTML extraction
# ---------------------------------------------------------------------------


def _parse_srcset(value: str) -> list[str]:
    """A srcset is `url descriptor, url descriptor, …`. We only care about
    the URLs (descriptor is `1x` / `2x` / `400w` / etc.)."""
    out: list[str] = []
    for part in value.split(","):
        token = part.strip().split(" ", 1)[0].strip()
        if token:
            out.append(token)
    return out


def extract_broadened_urls(
    html: str, base_url: str,
) -> ExtractedExternalUrls:
    """Run the Phase-2 static-HTML extractors. Returns an
    ``ExtractedExternalUrls`` with external (non-same-host) URLs only.

    This is callable independently so the orchestrator can fold these into
    PageArtifacts without changing the original Extractor."""
    page_host = _hostname(base_url)
    soup = BeautifulSoup(html or "", "html.parser")
    out = ExtractedExternalUrls()

    def _add(bucket: list[str], raw: str | None) -> None:
        url = _resolve(base_url, raw)
        if url and _is_external(url, page_host):
            bucket.append(url)

    # <img srcset>, <source srcset>
    for tag in soup.find_all(["img", "source"]):
        if not isinstance(tag, Tag):
            continue
        srcset = tag.get("srcset") or tag.get("data-srcset")
        if isinstance(srcset, str):
            for u in _parse_srcset(srcset):
                _add(out.srcset, u)

    # <video src> / <audio src> / <video poster> / nested <source src>
    for tag in soup.find_all(["video", "audio"]):
        if not isinstance(tag, Tag):
            continue
        _add(out.video_audio, _attr(tag, "src"))
        _add(out.video_audio, _attr(tag, "poster"))
        for child in tag.find_all("source"):
            if isinstance(child, Tag):
                _add(out.video_audio, _attr(child, "src"))

    # <object data>, <embed src>
    for tag in soup.find_all("object"):
        if isinstance(tag, Tag):
            _add(out.object_embed, _attr(tag, "data"))
    for tag in soup.find_all("embed"):
        if isinstance(tag, Tag):
            _add(out.object_embed, _attr(tag, "src"))

    # <meta http-equiv="refresh" content="0; url=...">
    for tag in soup.find_all("meta", attrs={"http-equiv": True}):
        if not isinstance(tag, Tag):
            continue
        if str(tag.get("http-equiv", "")).lower() != "refresh":
            continue
        content = _attr(tag, "content") or ""
        # content syntax: "<seconds>; url=<url>"
        if "url=" in content.lower():
            url_part = content.split("url=", 1)[1].strip().strip("'\"")
            _add(out.meta_refresh, url_part)

    # <link rel=...> rels we care about. One tag can have multiple rels.
    for tag in soup.find_all("link"):
        if not isinstance(tag, Tag):
            continue
        href = _attr(tag, "href")
        if not href:
            continue
        rels = _rel_tokens(tag)
        if "preconnect" in rels:
            _add(out.preconnect, href)
        if "dns-prefetch" in rels:
            _add(out.dns_prefetch, href)
        if "preload" in rels or "modulepreload" in rels:
            _add(out.preload, href)
        if "manifest" in rels:
            _add(out.manifest, href)
        if "canonical" in rels:
            _add(out.canonical, href)
        if any(r in rels for r in ("icon", "shortcut", "apple-touch-icon",
                                    "mask-icon")):
            _add(out.favicon, href)

    # <meta property="og:image" content="..."> / twitter:image / og:url
    _OG_TW = {
        "og:image", "og:image:url", "og:image:secure_url", "og:video",
        "og:video:url", "og:audio", "og:url",
        "twitter:image", "twitter:image:src", "twitter:player",
    }
    for tag in soup.find_all("meta"):
        if not isinstance(tag, Tag):
            continue
        prop = (_attr(tag, "property") or _attr(tag, "name") or "").lower()
        if prop in _OG_TW:
            _add(out.og_twitter, _attr(tag, "content"))

    # JSON-LD: scan @id / url fields inside ld+json scripts.
    for tag in soup.find_all("script", attrs={"type": "application/ld+json"}):
        if not isinstance(tag, Tag):
            continue
        content = tag.string or tag.get_text() or ""
        for url in _jsonld_urls(content):
            _add(out.jsonld, url)

    # Inline style="url(...)" and <style>...url(...)...</style>.
    for tag in soup.find_all(style=True):
        if not isinstance(tag, Tag):
            continue
        style_val = tag.get("style")
        if isinstance(style_val, str):
            for match in _CSS_URL_RE.findall(style_val):
                _add(out.inline_style, match)
    for tag in soup.find_all("style"):
        if not isinstance(tag, Tag):
            continue
        css = tag.string or tag.get_text() or ""
        for match in _CSS_URL_RE.findall(css):
            _add(out.inline_style, match)

    return out


def _attr(tag: Tag, name: str) -> str | None:
    """BeautifulSoup attrs can be lists for multi-value attrs (rel, class, …).
    Coerce to string."""
    val = tag.get(name)
    if isinstance(val, list):
        return " ".join(str(v) for v in val) if val else None
    return val if isinstance(val, str) else None


def _rel_tokens(tag: Tag) -> set[str]:
    rel = tag.get("rel")
    if isinstance(rel, list):
        return {str(r).lower() for r in rel}
    if isinstance(rel, str):
        return {r.lower() for r in rel.split()}
    return set()


def _jsonld_urls(content: str) -> Iterable[str]:
    """Yield string values from JSON-LD payloads that look like URLs."""
    try:
        data = json.loads(content)
    except (ValueError, json.JSONDecodeError):
        return []
    out: list[str] = []
    _walk_jsonld(data, out)
    return out


def _walk_jsonld(node: object, out: list[str]) -> None:
    """Walk a JSON-LD tree and collect URL-looking string values. We only
    surface http(s) absolute URLs; relative or nonsense strings are skipped."""
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str) and v.lower().startswith(("http://", "https://")):
                # Most useful keys: @id, url, contentUrl, image, sameAs, logo,
                # potentialAction.target. We surface any value that's already
                # a URL — minimal false positives, simple to maintain.
                out.append(v)
            else:
                _walk_jsonld(v, out)
    elif isinstance(node, list):
        for item in node:
            _walk_jsonld(item, out)


# ---------------------------------------------------------------------------
# JS-content extraction
# ---------------------------------------------------------------------------


@dataclass
class JsExtractedUrls:
    """Per-JS-file bucket of URLs referenced inside the file's source."""

    fetch_urls: list[str] = field(default_factory=list)
    xhr_urls: list[str] = field(default_factory=list)
    websocket_urls: list[str] = field(default_factory=list)
    eventsource_urls: list[str] = field(default_factory=list)
    dynamic_imports: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    # Bare URLs from string literals (CDN hosts, hard-coded endpoints, …).
    # Filtered to absolute / protocol-relative; relative API paths skipped.
    literal_urls: list[str] = field(default_factory=list)


def extract_js_urls(content: str, *, base_url: str | None = None) -> JsExtractedUrls:
    """Scan one JS file's *source* for URLs. Never executes anything; the
    regexes only see characters, not behaviour.

    Pass `base_url` (the JS file's own URL) so protocol-relative + relative
    references resolve to absolute strings ready for hostname comparison.
    """
    out = JsExtractedUrls()
    if not content:
        return out

    def _push(bucket: list[str], match: str) -> None:
        # Coerce `match` to a usable absolute URL. We DON'T resolve against
        # the page host here — the JS file is the right base.
        cleaned = match.strip()
        if not cleaned:
            return
        if cleaned.startswith("//"):
            cleaned = "https:" + cleaned
        if cleaned.startswith(("http://", "https://", "ws://", "wss://")):
            bucket.append(cleaned)
            return
        if base_url:
            absolute = _resolve(base_url, cleaned)
            if absolute:
                bucket.append(absolute)

    for m in _JS_FETCH_RE.findall(content):
        _push(out.fetch_urls, m)
    for m in _JS_XHR_RE.findall(content):
        _push(out.xhr_urls, m)
    for m in _JS_WS_RE.findall(content):
        _push(out.websocket_urls, m)
    for m in _JS_EVENTSOURCE_RE.findall(content):
        _push(out.eventsource_urls, m)
    for m in _JS_IMPORT_RE.findall(content):
        _push(out.dynamic_imports, m)
    for m in _JS_SOURCEMAP_RE.findall(content):
        _push(out.source_maps, m)
    for m in _JS_URL_LITERAL_RE.findall(content):
        _push(out.literal_urls, m)

    # Dedupe per-bucket to keep callers tidy.
    out.fetch_urls = _dedupe(out.fetch_urls)
    out.xhr_urls = _dedupe(out.xhr_urls)
    out.websocket_urls = _dedupe(out.websocket_urls)
    out.eventsource_urls = _dedupe(out.eventsource_urls)
    out.dynamic_imports = _dedupe(out.dynamic_imports)
    out.source_maps = _dedupe(out.source_maps)
    out.literal_urls = _dedupe(out.literal_urls)
    return out


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


# ---------------------------------------------------------------------------
# Scan-wide host inventory
# ---------------------------------------------------------------------------


@dataclass
class HostInventoryEntry:
    """One unique third-party host the scan discovered, with provenance.

    Phase-5B expansion: tracks *which discovery mechanism* surfaced the
    host (static HTML, JS literal, browser telemetry, redirect chain,
    DNS reference, CSP source, iframe), the ``last_seen_page`` in
    addition to first, and per-host fields populated downstream by the
    enrichment + classification pipeline (vendor classification,
    threat-intel state, VirusTotal status, WADE baseline status).

    Each "downstream" field defaults to None and is set by its owner
    service when it runs. A host that's never enriched still serialises
    correctly — every consumer must tolerate None for these fields."""

    hostname: str
    registrable_domain: str | None = None
    kinds: set[str] = field(default_factory=set)         # script / fetch / preconnect / …
    discovery_sources: set[str] = field(default_factory=set)
    first_seen_page: str | None = None
    last_seen_page: str | None = None
    sample_urls: list[str] = field(default_factory=list)  # capped, dedup'd
    # Downstream-populated (Phase-5C / WADE / threat-intel):
    vendor_classification: str | None = None    # 'trusted' | 'risky' | …
    threat_intel_state: str | None = None       # 'pending' | 'checked' | …
    vt_status: str | None = None                # 'clean' | 'suspicious' | …
    baseline_status: str | None = None          # 'known' | 'new' | …

    _SAMPLE_CAP = 5
    # Mapping from the kind string (the per-(url, kind) pair the
    # caller passes in) to the high-level discovery_source bucket.
    # New buckets fall back to ``"static"`` to stay backwards-
    # compatible with engines that pre-date Phase-5.
    _KIND_TO_SOURCE: dict[str, str] = field(default_factory=lambda: {
        "script":          "static_html",
        "stylesheet":      "static_html",
        "image":           "static_html",
        "link":            "static_html",
        "form_action":     "static_html",
        "iframe":          "iframe",
        "preconnect":      "static_html",
        "dns_prefetch":    "static_html",
        "preload":         "static_html",
        "manifest":        "static_html",
        "canonical":       "static_html",
        "css_import":      "static_html",
        "og_url":          "static_html",
        "twitter_url":     "static_html",
        "jsonld":          "static_html",
        "js_request":      "js_literal",
        "js_fetch":        "js_literal",
        "js_xhr":          "js_literal",
        "js_eventsource":  "js_literal",
        "js_websocket":    "js_literal",
        "js_import":       "js_literal",
        "js_literal":      "js_literal",
        "fetch":           "browser",
        "xhr":             "browser",
        "websocket":       "browser",
        "eventsource":     "browser",
        "dynamic_import":  "browser",
        "navigation":      "browser",
        "redirect":        "redirect",
        "dns":             "dns",
        "csp":             "csp",
    })

    def add(self, *, kind: str, url: str, page_url: str | None) -> None:
        self.kinds.add(kind)
        # Bucket the kind into a high-level discovery_source so the
        # dashboard / JSON export can render "this host was found via:
        # static_html + browser" rather than the granular kind list.
        source = self._KIND_TO_SOURCE.get(kind, "static")
        self.discovery_sources.add(source)
        if self.first_seen_page is None and page_url:
            self.first_seen_page = page_url
        if page_url:
            self.last_seen_page = page_url
        if url not in self.sample_urls and len(self.sample_urls) < self._SAMPLE_CAP:
            self.sample_urls.append(url)


def aggregate_host_inventory(
    pages: Iterable["PageHostContribution"],   # noqa: F821
) -> dict[str, HostInventoryEntry]:
    """Take a sequence of per-page contributions and merge into a scan-wide
    `{hostname: HostInventoryEntry}` map. `first_seen_page` reflects the
    first contribution order — feed pages in crawl order to keep it
    chronological."""
    import tldextract

    inventory: dict[str, HostInventoryEntry] = {}
    for page in pages:
        for url, kind in page.urls:
            host = _hostname(url)
            if not host or host == page.page_host:
                continue
            entry = inventory.get(host)
            if entry is None:
                ext = tldextract.extract(host)
                reg = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else None
                entry = HostInventoryEntry(hostname=host, registrable_domain=reg)
                inventory[host] = entry
            entry.add(kind=kind, url=url, page_url=page.page_url)
    return inventory


# ---------------------------------------------------------------------------
# Phase-5B: extend the inventory with signals the per-page contribution
# loop doesn't capture (CSP source hosts, redirect-chain intermediaries).
# Called by the orchestrator post-crawl. Idempotent — re-running adds
# nothing new.
# ---------------------------------------------------------------------------


_CSP_DIRECTIVES_WITH_HOSTS = (
    "default-src", "script-src", "script-src-elem", "script-src-attr",
    "style-src", "style-src-elem", "style-src-attr",
    "img-src", "font-src", "connect-src", "media-src", "object-src",
    "frame-src", "child-src", "form-action", "frame-ancestors",
    "worker-src", "manifest-src", "prefetch-src",
)


def _csp_source_hosts(csp_value: str) -> list[str]:
    """Parse a Content-Security-Policy header value, return every
    host (or registrable domain) listed in a source-list directive.

    Skips ``'self'``, ``'unsafe-*'``, ``data:``, ``blob:``, ``*``,
    and nonce / hash sources — only real host names land in the
    output. Wildcards like ``*.example.com`` keep the literal base
    domain so the inventory at least records ``example.com``."""
    hosts: list[str] = []
    if not csp_value:
        return hosts
    for chunk in csp_value.split(";"):
        parts = chunk.strip().split()
        if not parts:
            continue
        directive = parts[0].lower()
        if directive not in _CSP_DIRECTIVES_WITH_HOSTS:
            continue
        for src in parts[1:]:
            s = src.strip().strip("'\"")
            if not s or s in (
                "self", "none", "unsafe-inline", "unsafe-eval",
                "unsafe-hashes", "strict-dynamic", "report-sample",
                "*",
            ):
                continue
            if s.startswith(("nonce-", "sha256-", "sha384-", "sha512-")):
                continue
            if ":" in s and "//" not in s and not s.startswith("*."):
                # data:, blob:, filesystem:, mediastream:
                continue
            # Strip scheme + wildcard prefix to get a bare host.
            host = s
            for prefix in ("http://", "https://", "wss://", "ws://"):
                if host.startswith(prefix):
                    host = host[len(prefix):]
                    break
            host = host.split("/", 1)[0].lstrip("*.").lower()
            if host and "." in host:
                hosts.append(host)
    return hosts


def build_response_inventory_contribution(
    page_url: str,
    *,
    headers: dict[str, str] | None = None,
    redirect_chain: list[str] | None = None,
) -> "PageHostContribution":
    """Build a synthetic ``PageHostContribution`` representing every
    host the page's HTTP response surfaced via CSP source-list +
    redirect-chain intermediaries.

    The orchestrator appends these contributions to the existing
    per-page list before calling ``aggregate_host_inventory`` so the
    canonical inventory includes CSP-allowed vendors that no element
    on the page actually references, and redirect hops the static
    crawler followed transparently. Backwards-compatible — when both
    inputs are empty the resulting contribution carries zero URLs and
    is a harmless no-op in the aggregator."""
    pairs: list[tuple[str, str]] = []
    csp = (headers or {}).get(
        "content-security-policy",
        (headers or {}).get("Content-Security-Policy", ""),
    )
    if csp:
        for h in _csp_source_hosts(csp):
            pairs.append((f"https://{h}/", "csp"))
    for r in (redirect_chain or []):
        if r:
            pairs.append((r, "redirect"))
    return PageHostContribution(
        page_url=page_url,
        page_host=_hostname(page_url),
        urls=pairs,
    )


@dataclass
class PageHostContribution:
    """One page's contribution to the scan-wide host inventory. Build from
    PageArtifacts via `from_artifacts` — bundles every external-URL field
    we care about into a single (url, kind) sequence."""

    page_url: str
    page_host: str | None
    urls: list[tuple[str, str]] = field(default_factory=list)

    @classmethod
    def from_artifacts(
        cls,
        artifacts,  # PageArtifacts; avoid the import cycle
        js_urls_by_file: dict[str, JsExtractedUrls] | None = None,
    ) -> "PageHostContribution":
        page_url = artifacts.url
        page_host = _hostname(page_url)
        pairs: list[tuple[str, str]] = []

        def _take(urls: Iterable[str] | None, kind: str) -> None:
            for u in (urls or []):
                if u:
                    pairs.append((u, kind))

        # Phase-1 surfaces (already on PageArtifacts).
        _take(artifacts.external_script_urls, "script")
        _take(artifacts.external_stylesheet_urls, "stylesheet")
        _take(artifacts.external_image_urls, "image")
        _take(artifacts.inline_js_request_urls, "js_request")
        _take(artifacts.inline_css_import_urls, "css_import")
        _take(artifacts.external_links, "link")
        for f in getattr(artifacts, "forms", []) or []:
            if getattr(f, "action_url", None):
                pairs.append((f.action_url, "form_action"))
        for iframe in getattr(artifacts, "iframes", []) or []:
            if getattr(iframe, "src_url", None):
                pairs.append((iframe.src_url, "iframe"))

        # Phase-2 surfaces (new on PageArtifacts; default empty → safe).
        _take(getattr(artifacts, "external_srcset_urls", []),       "srcset")
        _take(getattr(artifacts, "external_video_audio_urls", []),  "media")
        _take(getattr(artifacts, "external_object_embed_urls", []), "object_embed")
        _take(getattr(artifacts, "external_meta_refresh_urls", []), "meta_refresh")
        _take(getattr(artifacts, "external_preconnect_urls", []),   "preconnect")
        _take(getattr(artifacts, "external_dns_prefetch_urls", []), "dns_prefetch")
        _take(getattr(artifacts, "external_preload_urls", []),      "preload")
        _take(getattr(artifacts, "external_manifest_urls", []),     "manifest")
        _take(getattr(artifacts, "external_canonical_urls", []),    "canonical")
        _take(getattr(artifacts, "external_og_twitter_urls", []),   "og_twitter")
        _take(getattr(artifacts, "external_jsonld_urls", []),       "jsonld")
        _take(getattr(artifacts, "external_inline_style_urls", []), "inline_style")
        _take(getattr(artifacts, "external_favicon_urls", []),      "favicon")

        # JS-content URLs, keyed by source JS file so the dashboard can show
        # provenance (`js_file → host`).
        if js_urls_by_file:
            for jf in js_urls_by_file.values():
                _take(jf.fetch_urls,        "js_fetch")
                _take(jf.xhr_urls,          "js_xhr")
                _take(jf.websocket_urls,    "js_websocket")
                _take(jf.eventsource_urls,  "js_eventsource")
                _take(jf.dynamic_imports,   "js_import")
                _take(jf.literal_urls,      "js_literal")

        return cls(page_url=page_url, page_host=page_host, urls=pairs)
