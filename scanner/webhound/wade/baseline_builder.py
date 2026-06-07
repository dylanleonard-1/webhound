# WebHound — scanner/webhound/wade/baseline_builder.py
# Captures a security-relevant snapshot of a site's observable state from a
# completed crawl so diff_engine can detect changes on the next scan.
# No live external calls are made.

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from webhound.core.crawler import CrawlResult
from webhound.models.scan_result import ScanResult


@dataclass
class PageSnapshot:
    """Security-relevant state captured for one crawled page.

    WADE 2.0 expanded the inventory beyond scripts/forms/headers to cover
    rendered structure, resource-loading third parties, API surface,
    iframes, redirect behaviour, and detected technologies. Every new
    field carries a default so baselines persisted by WADE 1.x still
    deserialize cleanly.

    The captured inventories are *normalised* (sorted, deduplicated,
    version-stripped where relevant) so they don't churn between scans —
    ``dom_hash`` fingerprints page *structure* rather than text content,
    precisely so a blog edit or marketing-copy change does not register
    as a structural change.
    """

    url: str
    status_code: int
    content_hash: str                   # SHA-256[:16] of page body
    headers: dict[str, str]             # lowercase response headers
    script_sources: list[str]           # sorted external script src URLs
    inline_hashes: list[str]            # SHA-256[:16] of each inline script block
    external_domains: list[str]         # sorted unique hostnames from external links
    form_signatures: list[str]          # sorted "METHOD|action_url|f1,f2,..."
    cookie_signatures: dict[str, str]   # cookie_name → "Secure;HttpOnly;..."

    # --- WADE 2.0 expanded inventory (defaults keep v1 baselines loadable) -
    dom_hash: str = ""                  # SHA-256[:16] of structural tag census
    third_party_domains: list[str] = field(default_factory=list)   # resource-loading hosts
    api_endpoints: list[str] = field(default_factory=list)         # normalised endpoint paths
    iframe_signatures: list[str] = field(default_factory=list)     # "host|hidden|sandboxed"
    redirect_chain: list[str] = field(default_factory=list)        # ordered hop hostnames
    technologies: list[str] = field(default_factory=list)          # version-stripped tech tokens


@dataclass
class SiteBaseline:
    """Aggregated WADE baseline produced from one complete site crawl."""

    target_url: str
    scan_id: str                        # UUID string of source ScanResult
    created_at: str                     # ISO-8601 timestamp
    pages: dict[str, PageSnapshot]      # url → PageSnapshot
    all_script_sources: list[str]       # sorted, deduplicated across all pages
    all_external_domains: list[str]     # sorted, deduplicated across all pages
    page_count: int

    # --- WADE 2.0 site-wide inventories (defaults keep v1 baselines loadable) -
    all_third_party_domains: list[str] = field(default_factory=list)
    all_api_endpoints: list[str] = field(default_factory=list)
    all_technologies: list[str] = field(default_factory=list)


class BaselineBuilder:
    """Build a :class:`SiteBaseline` from a completed crawl (no I/O)."""

    def build(
        self,
        crawl_results: list[CrawlResult],
        scan_result: ScanResult,
    ) -> SiteBaseline:
        pages: dict[str, PageSnapshot] = {}
        all_scripts: set[str] = set()
        all_domains: set[str] = set()
        all_third_party: set[str] = set()
        all_apis: set[str] = set()
        all_tech: set[str] = set()

        for cr in crawl_results:
            if cr.response.failed or cr.artifacts is None:
                continue
            snap = self._snapshot(cr)
            pages[cr.url] = snap
            all_scripts.update(snap.script_sources)
            all_domains.update(snap.external_domains)
            all_third_party.update(snap.third_party_domains)
            all_apis.update(snap.api_endpoints)
            all_tech.update(snap.technologies)

        return SiteBaseline(
            target_url=scan_result.target.base_url,
            scan_id=str(scan_result.id),
            created_at=datetime.now(timezone.utc).isoformat(),
            pages=pages,
            all_script_sources=sorted(all_scripts),
            all_external_domains=sorted(all_domains),
            page_count=len(pages),
            all_third_party_domains=sorted(all_third_party),
            all_api_endpoints=sorted(all_apis),
            all_technologies=sorted(all_tech),
        )

    def _snapshot(self, cr: CrawlResult) -> PageSnapshot:
        arts = cr.artifacts
        resp = cr.response
        page_host = (urlparse(cr.url).hostname or "").lower()

        script_sources = sorted({
            s.src for s in arts.scripts if not s.is_inline and s.src
        })
        inline_hashes = sorted({
            _sha16(s.content) for s in arts.scripts if s.is_inline and s.content
        })
        external_domains = sorted({
            urlparse(link).hostname.lower()
            for link in arts.external_links
            if urlparse(link).hostname
        })
        form_signatures = sorted({_form_sig(f) for f in arts.forms})

        cookie_signatures: dict[str, str] = {}
        for raw in arts.cookies:
            name, flags = _parse_cookie(raw)
            if name:
                cookie_signatures[name] = flags

        return PageSnapshot(
            url=cr.url,
            status_code=resp.status_code,
            content_hash=_sha16(resp.body or ""),
            headers={k.lower(): v for k, v in arts.response_headers.items()},
            script_sources=script_sources,
            inline_hashes=inline_hashes,
            external_domains=external_domains,
            form_signatures=form_signatures,
            cookie_signatures=cookie_signatures,
            dom_hash=_dom_hash(resp.body or ""),
            third_party_domains=_third_party_domains(arts, page_host),
            api_endpoints=_api_endpoints(arts, page_host),
            iframe_signatures=_iframe_signatures(arts),
            redirect_chain=_redirect_chain(resp),
            technologies=_detect_technologies(arts),
        )

    # ------------------------------------------------------------------
    # Serialization — round-trips cleanly through JSON
    # ------------------------------------------------------------------

    def to_dict(self, baseline: SiteBaseline) -> dict[str, Any]:
        return asdict(baseline)

    def from_dict(self, data: dict[str, Any]) -> SiteBaseline:
        pages = {
            url: _page_snapshot_from_dict(snap)
            for url, snap in data["pages"].items()
        }
        return SiteBaseline(
            target_url=data["target_url"],
            scan_id=data["scan_id"],
            created_at=data["created_at"],
            pages=pages,
            all_script_sources=data["all_script_sources"],
            all_external_domains=data["all_external_domains"],
            page_count=data["page_count"],
            all_third_party_domains=data.get("all_third_party_domains", []),
            all_api_endpoints=data.get("all_api_endpoints", []),
            all_technologies=data.get("all_technologies", []),
        )


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _sha16(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


# Known PageSnapshot field names — used to drop unexpected / future keys when
# deserialising so a newer-on-disk baseline can't crash an older reader.
_SNAPSHOT_FIELDS: frozenset[str] = frozenset(f.name for f in fields(PageSnapshot))


def _page_snapshot_from_dict(snap: dict[str, Any]) -> PageSnapshot:
    """Rebuild a :class:`PageSnapshot`, tolerating missing/extra keys.

    Missing keys fall back to the dataclass defaults (so WADE 1.x baselines
    load); extra keys are ignored (so a baseline written by a newer build
    doesn't raise here)."""
    known = {k: v for k, v in snap.items() if k in _SNAPSHOT_FIELDS}
    return PageSnapshot(**known)


# Tag-census fingerprint: matches an opening HTML tag name. We deliberately
# hash *structure* (which tags appear and how often) rather than text, so a
# copy edit / blog update / image swap leaves dom_hash unchanged while an
# injected <iframe>/<script>/<form> shifts it.
_TAG_RE: re.Pattern[str] = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)")


def _dom_hash(body: str) -> str:
    """Structural fingerprint of a page: SHA-256[:16] of its tag census."""
    if not body:
        return ""
    census = Counter(t.lower() for t in _TAG_RE.findall(body))
    skeleton = ";".join(f"{tag}:{n}" for tag, n in sorted(census.items()))
    return _sha16(skeleton)


def _host(url: str | None) -> str:
    if not url:
        return ""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


# Resource-loading surfaces whose hosts count as "third parties". These are
# distinct from anchor-link external_domains — a third-party that *executes
# code or frames content* is a supply-chain trust decision, an outbound link
# is not.
def _third_party_domains(arts: Any, page_host: str) -> list[str]:
    hosts: set[str] = set()
    for s in arts.scripts:
        if s.src:
            hosts.add(_host(s.src))
    for attr in (
        "external_stylesheet_urls", "external_image_urls",
        "inline_js_request_urls", "inline_css_import_urls",
        "external_preconnect_urls", "external_dns_prefetch_urls",
        "external_preload_urls", "external_object_embed_urls",
        "external_video_audio_urls",
    ):
        for url in getattr(arts, attr, []) or []:
            hosts.add(_host(url))
    for frame in getattr(arts, "iframes", []) or []:
        if frame.src_url:
            hosts.add(_host(frame.src_url))
    hosts.discard("")
    hosts.discard(page_host)
    return sorted(hosts)


# Endpoint detection: anything that looks like a programmatic API surface.
_API_PATH_RE: re.Pattern[str] = re.compile(
    r"(?:/api/|/graphql|/rest/|/v\d+/|/oauth|/auth/|\.json(?:$|\?))",
    re.IGNORECASE,
)


def _endpoint_key(url: str) -> str | None:
    """Normalise a URL into a stable 'host/path' endpoint key (no scheme,
    no query) when it looks like an API surface; else None."""
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    candidate = f"{host}{path}"
    if _API_PATH_RE.search(path) or _API_PATH_RE.search(url):
        return candidate.rstrip("/") or candidate
    return None


def _api_endpoints(arts: Any, page_host: str) -> list[str]:
    endpoints: set[str] = set()
    # JS-issued requests (fetch/XHR/WebSocket) are the strongest API signal.
    for url in getattr(arts, "inline_js_request_urls", []) or []:
        key = _endpoint_key(url)
        endpoints.add(key if key else _normalise_request_url(url))
    # Links / form actions that match API path conventions.
    for url in (list(arts.internal_links) + list(arts.external_links)):
        key = _endpoint_key(url)
        if key:
            endpoints.add(key)
    for form in arts.forms:
        if form.action_url:
            key = _endpoint_key(form.action_url)
            if key:
                endpoints.add(key)
    endpoints.discard("")
    endpoints.discard(None)  # type: ignore[arg-type]
    return sorted(e for e in endpoints if e)


def _normalise_request_url(url: str) -> str:
    """host/path form for an XHR/fetch/WS URL (always an endpoint)."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return f"{(parsed.hostname or '').lower()}{parsed.path or '/'}".rstrip("/") or url


def _iframe_signatures(arts: Any) -> list[str]:
    """Stable per-iframe signature: 'host|hidden|sandboxed'."""
    sigs: set[str] = set()
    for frame in getattr(arts, "iframes", []) or []:
        host = _host(frame.src_url) or "about:blank"
        hidden = "hidden" if frame.is_hidden else "visible"
        sandboxed = "sandboxed" if frame.sandbox is not None else "unsandboxed"
        sigs.add(f"{host}|{hidden}|{sandboxed}")
    return sorted(sigs)


def _redirect_chain(resp: Any) -> list[str]:
    """Ordered list of distinct hop hostnames for a cross-host redirect.

    Returns [] when there was no redirect or every hop stayed on one host
    (a path-only / scheme-only redirect is not a behaviour change WADE
    needs to track)."""
    if getattr(resp, "redirect_count", 0) <= 0:
        return []
    raw = [getattr(resp, "original_url", "")] \
        + list(getattr(resp, "redirect_chain", []) or []) \
        + [getattr(resp, "url", "")]
    hops: list[str] = []
    for u in raw:
        h = _host(u)
        if h and (not hops or hops[-1] != h):
            hops.append(h)
    return hops if len(hops) > 1 else []


# Technology fingerprints. Version numbers are intentionally stripped — a
# framework version bump is a deploy, not a security change, and tracking
# versions would make the inventory churn on every patch release.
_HEADER_TECH: dict[str, str] = {
    "x-powered-by": "",          # value is the tech (e.g. "PHP/8.1" → "php")
    "x-aspnet-version": "asp.net",
    "x-aspnetmvc-version": "asp.net mvc",
    "x-drupal-cache": "drupal",
    "x-generator": "",
    "x-shopify-stage": "shopify",
}
_SCRIPT_TECH: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"wp-content|wp-includes", re.I), "wordpress"),
    (re.compile(r"cdn\.shopify\.com|shopifycdn", re.I), "shopify"),
    (re.compile(r"/_next/|next/static", re.I), "next.js"),
    (re.compile(r"/_nuxt/", re.I), "nuxt"),
    (re.compile(r"react(?:-dom)?(?:\.min)?\.js", re.I), "react"),
    (re.compile(r"vue(?:\.min)?\.js", re.I), "vue"),
    (re.compile(r"angular(?:\.min)?\.js", re.I), "angular"),
    (re.compile(r"jquery", re.I), "jquery"),
    (re.compile(r"googletagmanager\.com/gtm", re.I), "google tag manager"),
    (re.compile(r"drupal", re.I), "drupal"),
    (re.compile(r"wix\.com|wixstatic", re.I), "wix"),
    (re.compile(r"squarespace", re.I), "squarespace"),
]
_VERSION_RE: re.Pattern[str] = re.compile(r"[/\s-]?v?\d[\d._-]*")


def _detect_technologies(arts: Any) -> list[str]:
    techs: set[str] = set()
    headers = {k.lower(): v for k, v in arts.response_headers.items()}

    server = headers.get("server", "")
    if server:
        techs.add(_strip_version(server.split()[0]) if server.split() else server)

    for hdr, fixed in _HEADER_TECH.items():
        if hdr in headers:
            techs.add(fixed or _strip_version(headers[hdr]))

    generator = (arts.meta_tags or {}).get("generator", "")
    if generator:
        techs.add(_strip_version(generator.split()[0]) if generator.split() else generator)

    blob = " ".join(s.src for s in arts.scripts if s.src)
    for pattern, name in _SCRIPT_TECH:
        if pattern.search(blob):
            techs.add(name)

    techs.discard("")
    return sorted(t.lower() for t in techs)


def _strip_version(token: str) -> str:
    """'PHP/8.1.2' → 'php', 'nginx/1.25' → 'nginx', 'WordPress 6.2' → 'wordpress'."""
    base = _VERSION_RE.sub("", token).strip().strip("/").lower()
    return base or token.lower()


def _form_sig(form: Any) -> str:
    """Stable string key: METHOD|action_url|sorted_field_names."""
    method = (form.method or "GET").upper()
    action = form.action_url or form.action or ""
    fields = ",".join(sorted(inp.name for inp in form.inputs if inp.name))
    return f"{method}|{action}|{fields}"


def _parse_cookie(raw: str) -> tuple[str, str]:
    """Return (name, security_flags_string) for a raw Set-Cookie header."""
    if not raw:
        return "", ""
    parts = [p.strip() for p in raw.split(";")]
    if not parts:
        return "", ""
    name = parts[0].split("=", 1)[0].strip()
    flags: list[str] = []
    for part in parts[1:]:
        pl = part.lower()
        if pl == "secure":
            flags.append("Secure")
        elif pl == "httponly":
            flags.append("HttpOnly")
        elif pl.startswith("samesite="):
            flags.append(f"SameSite={part.split('=',1)[1].strip()}")
    return name, ";".join(sorted(flags))
