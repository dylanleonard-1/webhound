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
