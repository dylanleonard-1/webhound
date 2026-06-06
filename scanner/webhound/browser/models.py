# WebHound — webhound/browser/models.py
# Phase-5A models: structured browser telemetry that downstream
# engines + the orchestrator's scan-wide passes can consume.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlparse


def _hostname(url: str) -> str:
    if not url:
        return ""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


@dataclass
class NetworkArtifact:
    """One captured network request/response.

    ``initiator_kind`` is the high-level source the browser reports:
    ``"fetch"``, ``"xhr"``, ``"websocket"``, ``"eventsource"``,
    ``"script"``, ``"iframe"``, ``"image"``, ``"stylesheet"``,
    ``"dynamic_import"``, ``"redirect"``, ``"navigation"``,
    ``"unknown"``. Used by the host-inventory merger as the
    ``discovery_source`` so the dashboard can attribute each external
    host to the precise mechanism that pulled it in.

    ``timing_ms`` is the duration from request start → response end
    (None when the response never landed — typical for cancelled
    requests after navigation). ``page_url`` is the page the request
    fired from; ``redirected_to`` is the final URL after any
    redirect chain.
    """

    url: str
    method: str
    initiator_kind: str
    status_code: int | None = None
    content_type: str | None = None
    page_url: str | None = None
    redirected_to: str | None = None
    timing_ms: float | None = None
    request_started_at: datetime | None = None

    @property
    def hostname(self) -> str:
        return _hostname(self.url)


@dataclass(frozen=True)
class RenderedFormField:
    """One input/select/textarea inside a rendered form. Metadata only —
    the field is read from the DOM, never filled, never submitted."""

    name: str | None
    input_type: str


@dataclass(frozen=True)
class RenderedForm:
    """A <form> observed in the *rendered* DOM (post-hydration).

    Captured read-only so lazy-loaded / JS-injected forms reach the form
    engines. Safe-mode contract: the runner never focuses, fills, or
    submits these forms — it only reads their attributes."""

    action: str | None        # Resolved form.action (absolute URL) or None
    method: str               # Uppercased; defaults to "GET"
    fields: tuple[RenderedFormField, ...] = ()
    has_password_field: bool = False
    page_url: str | None = None
    has_file_input: bool = False
    hidden_field_names: tuple[str, ...] = ()
    # The form's action points at a different registrable domain than
    # the page it renders on — exfil-shaped, worth surfacing later.
    action_is_external: bool = False


@dataclass(frozen=True)
class RenderedScript:
    """A script the rendered page references or embeds.

    ``kind`` is the discovery mechanism: ``script_tag`` (classic src),
    ``module`` (type=module), ``inline`` (embedded body — only a
    bounded ``snippet`` plus its hash are kept), ``preload`` /
    ``prefetch`` / ``modulepreload`` (link hints for dynamic chunks),
    ``service_worker`` (registration visible to the page)."""

    kind: str
    src: str | None = None
    is_inline: bool = False
    snippet: str | None = None       # First _SNIPPET_CAP chars only
    snippet_hash: str | None = None  # sha256 of the captured snippet
    snippet_truncated: bool = False


@dataclass(frozen=True)
class BrowserCookie:
    """A cookie visible to the browser context after navigation.

    TRUST POSTURE: the cookie *value* is never stored — only its
    length. Attribute flags are what the cookie engines reason about;
    holding customer session material in scan output is a liability,
    not evidence."""

    name: str
    domain: str
    path: str
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    value_length: int = 0


@dataclass
class BrowserTelemetry:
    """All artifacts captured for one page navigation.

    Includes both the raw ``artifacts`` list and convenience indices
    the orchestrator + engines need without re-scanning the list.
    """

    page_url: str
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    finished_at: datetime | None = None
    final_url: str | None = None
    artifacts: list[NetworkArtifact] = field(default_factory=list)
    # Rendered-DOM capture (Phase-6A). ``rendered_html`` is the
    # post-hydration ``page.content()`` snapshot — what the user's
    # browser actually shows, as opposed to the static HTML the crawler
    # fetched. ``rendered_links`` are resolved <a href> URLs read from
    # the live DOM; ``rendered_forms`` are read-only form descriptors.
    # All three stay None/empty when DOM capture is disabled or failed,
    # so existing consumers see no behavioural change.
    rendered_html: str | None = None
    rendered_links: list[str] = field(default_factory=list)
    rendered_forms: list[RenderedForm] = field(default_factory=list)
    # Phase-6B discovery extensions — all default-empty so existing
    # consumers and serialized telemetry are unaffected.
    rendered_text_summary: str | None = None
    rendered_scripts: list[RenderedScript] = field(default_factory=list)
    browser_cookies: list[BrowserCookie] = field(default_factory=list)
    console_messages: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    # Client-side routes discovered without navigation (anchors,
    # __NEXT_DATA__/__NUXT__, route-like script strings, data-href).
    # ``(route, source)`` pairs; populated by route_extractor.
    client_routes: list[tuple[str, str]] = field(default_factory=list)
    # Safe interactions performed (labels) + how many candidate
    # clicks the deny-list blocked. Forms are never submitted.
    interactions: list[str] = field(default_factory=list)
    blocked_interactions: int = 0
    # Subset views — populated by ``add()`` for cheap lookups.
    fetch_urls: list[str] = field(default_factory=list)
    xhr_urls: list[str] = field(default_factory=list)
    websocket_urls: list[str] = field(default_factory=list)
    eventsource_urls: list[str] = field(default_factory=list)
    dynamic_import_urls: list[str] = field(default_factory=list)
    iframe_urls: list[str] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    # Errors hit during the navigation (browser-side timeouts,
    # navigation aborts, JS errors). Surfaces in scan diagnostics so
    # operators can see when the browser pass partially failed.
    errors: list[str] = field(default_factory=list)

    def add(self, artifact: NetworkArtifact) -> None:
        self.artifacts.append(artifact)
        k = (artifact.initiator_kind or "unknown").lower()
        if k == "fetch":
            self.fetch_urls.append(artifact.url)
        elif k == "xhr":
            self.xhr_urls.append(artifact.url)
        elif k == "websocket":
            self.websocket_urls.append(artifact.url)
        elif k == "eventsource":
            self.eventsource_urls.append(artifact.url)
        elif k == "dynamic_import":
            self.dynamic_import_urls.append(artifact.url)
        elif k == "iframe":
            self.iframe_urls.append(artifact.url)
        elif k == "redirect":
            self.redirect_chain.append(artifact.url)


@dataclass
class BrowserDiscovery:
    """Scan-wide browser discovery output, attached to ScanContext by
    the orchestrator after the browser pass (Phase-6C).

    The single access point engines + reporting use for browser data —
    instead of each consumer re-walking raw telemetries. All accessors
    return empty collections when the pass was deferred or failed, so
    callers never need to branch on availability."""

    telemetries: list[BrowserTelemetry] = field(default_factory=list)
    deferred: bool = True
    error: str | None = None
    skipped_urls: list[tuple[str, str]] = field(default_factory=list)

    @property
    def available(self) -> bool:
        return not self.deferred and bool(self.telemetries)

    @property
    def rendered_pages(self) -> list[BrowserTelemetry]:
        return [t for t in self.telemetries if t.rendered_html]

    def get_all_pages(self) -> list[str]:
        """Final URLs of every page the browser successfully visited."""
        out, seen = [], set()
        for t in self.telemetries:
            url = t.final_url or t.page_url
            if url and url not in seen:
                seen.add(url)
                out.append(url)
        return out

    def get_all_rendered_links(self) -> list[str]:
        out, seen = [], set()
        for t in self.telemetries:
            for link in t.rendered_links:
                if link not in seen:
                    seen.add(link)
                    out.append(link)
        return out

    def get_all_forms(self) -> list[RenderedForm]:
        return [f for t in self.telemetries for f in t.rendered_forms]

    def get_all_script_urls(self) -> list[str]:
        """Every script URL the browser saw: rendered <script src>,
        module/preload chunk hints, service workers, plus scripts the
        network capture observed loading (dynamic imports the DOM walk
        can't attribute). Deduped, order-stable."""
        out, seen = [], set()
        for t in self.telemetries:
            for s in t.rendered_scripts:
                if s.src and s.src not in seen:
                    seen.add(s.src)
                    out.append(s.src)
            for art in t.artifacts:
                if (art.initiator_kind or "") == "script" \
                        and art.url and art.url not in seen:
                    seen.add(art.url)
                    out.append(art.url)
        return out

    def get_all_inline_scripts(self) -> list[RenderedScript]:
        return [
            s for t in self.telemetries
            for s in t.rendered_scripts if s.is_inline
        ]

    def get_all_network_requests(self) -> list[NetworkArtifact]:
        return [a for t in self.telemetries for a in t.artifacts]

    def get_all_api_endpoints(self) -> list[NetworkArtifact]:
        """Network artifacts classified as API traffic (fetch/XHR/
        JSON/api-shaped paths). Late import — network_capture imports
        these models at module level."""
        from webhound.browser.network_capture import looks_like_api
        out = []
        for t in self.telemetries:
            for art in t.artifacts:
                is_api, _ = looks_like_api(
                    art.url,
                    initiator_kind=art.initiator_kind,
                    content_type=art.content_type,
                )
                if is_api:
                    out.append(art)
        return out

    def get_all_third_party_domains(
        self, primary_host: str | None = None,
    ) -> list[str]:
        """Hostnames observed by the browser that differ from the scan
        target's registrable domain — sorted for stable output."""
        from webhound.browser.network_capture import _registrable
        primary_reg = _registrable((primary_host or "").lower())
        domains: set[str] = set()
        for t in self.telemetries:
            for art in t.artifacts:
                host = art.hostname
                if not host:
                    continue
                if primary_reg and _registrable(host) == primary_reg:
                    continue
                domains.add(host)
        return sorted(domains)

    def coverage_stats(self) -> dict:
        tels = self.telemetries
        return {
            "browser_pages_visited": len(tels),
            "browser_pages_rendered": sum(
                1 for t in tels if t.rendered_html
            ),
            "browser_render_failures": sum(
                1 for t in tels if t.errors or not t.rendered_html
            ),
            "rendered_links_found": sum(
                len(t.rendered_links) for t in tels
            ),
            "rendered_forms_found": sum(
                len(t.rendered_forms) for t in tels
            ),
            "browser_scripts_found": sum(
                len(t.rendered_scripts) for t in tels
            ),
            "browser_network_requests": sum(
                len(t.artifacts) for t in tels
            ),
            "browser_client_routes_found": sum(
                len(t.client_routes) for t in tels
            ),
            "skipped_out_of_scope_browser_urls": len(self.skipped_urls),
        }


@dataclass
class BrowserHostInventory:
    """Per-host rollup of every artifact pointing at the host.

    Built by ``aggregate_browser_hosts(...)`` after the orchestrator
    has finished every page-level browser pass for the scan."""

    hostname: str
    first_seen_page: str | None = None
    last_seen_page: str | None = None
    kinds: set[str] = field(default_factory=set)
    sample_urls: list[str] = field(default_factory=list)
    artifact_count: int = 0
    _SAMPLE_CAP = 5

    def add(self, artifact: NetworkArtifact) -> None:
        self.kinds.add(artifact.initiator_kind or "unknown")
        if self.first_seen_page is None and artifact.page_url:
            self.first_seen_page = artifact.page_url
        if artifact.page_url:
            self.last_seen_page = artifact.page_url
        if (artifact.url not in self.sample_urls
                and len(self.sample_urls) < self._SAMPLE_CAP):
            self.sample_urls.append(artifact.url)
        self.artifact_count += 1


def aggregate_browser_hosts(
    telemetries: Iterable[BrowserTelemetry],
    *,
    primary_host: str | None = None,
) -> dict[str, BrowserHostInventory]:
    """Roll the per-page browser telemetries into a scan-wide
    ``{hostname: BrowserHostInventory}`` map.

    ``primary_host`` is the scan target. Artifacts whose hostname
    matches ``primary_host`` are dropped — they're first-party traffic
    and clutter the third-party inventory."""
    out: dict[str, BrowserHostInventory] = {}
    primary = (primary_host or "").lower().strip(".")
    for tel in telemetries:
        for art in tel.artifacts:
            host = art.hostname
            if not host or host == primary:
                continue
            entry = out.get(host)
            if entry is None:
                entry = BrowserHostInventory(hostname=host)
                out[host] = entry
            entry.add(art)
    return out
