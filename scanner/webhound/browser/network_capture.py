# WebHound — webhound/browser/network_capture.py
# Phase-6B: classification of browser-captured network requests.
#
# Pure functions over NetworkArtifact — no Playwright dependency, no
# network activity. The runner captures raw artifacts; this module
# answers three questions per artifact:
#   * is it same-origin with the page that fired it?
#   * is it third-party traffic (different registrable domain)?
#   * does it look like API traffic (fetch/XHR, JSON, API-ish path)?
#
# Classification is DISCOVERY data only. Nothing here feeds risk
# scoring, severity, or engine findings — it lands in browser-pass
# coverage metadata until a later phase wires it into reporting.

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse

import tldextract

from webhound.browser.models import BrowserTelemetry, NetworkArtifact

# Path substrings that mark a request as API traffic. Matched against
# the URL *path* only (never the query string, to avoid tracker URLs
# that echo arbitrary page paths in parameters).
_API_PATH_TOKENS = (
    "/api",
    "/graphql",
    "/wp-json",
    "/admin-ajax.php",
)

# Path *segments* that suggest application/API endpoints even without
# an explicit /api prefix. Segment-anchored (full path component) so
# "/research" does not light up on "search".
_API_SEGMENT_TOKENS = frozenset({
    "auth", "session", "sessions", "cart", "checkout",
    "customer", "customers", "order", "orders", "search",
})

# initiator kinds that are programmatic requests by definition.
_API_KINDS = frozenset({"fetch", "xhr", "eventsource", "websocket"})

_JSON_CONTENT_RE = re.compile(r"\bjson\b", re.IGNORECASE)


def _is_ip_literal(host: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _registrable(host: str) -> str:
    """Registrable domain (eTLD+1) for *host*; falls back to the raw
    host when extraction fails (IP literals, single-label hosts)."""
    if not host:
        return ""
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    # Host has no recognised public suffix (.test, .internal, bare
    # names, IP literals). Approximate with the last two labels so
    # sub.example.test still groups with example.test.
    labels = host.split(".")
    if len(labels) >= 2 and not _is_ip_literal(host):
        return ".".join(labels[-2:])
    return host


def looks_like_api(
    url: str,
    *,
    initiator_kind: str | None = None,
    content_type: str | None = None,
) -> tuple[bool, str | None]:
    """Classify one request as API traffic.

    Returns ``(is_api, reason)`` where reason is a short machine token
    naming the rule that fired — kept in the coverage output so a
    customer-facing surface can later explain *why* a URL was called
    an API endpoint instead of asserting it without evidence."""
    kind = (initiator_kind or "").lower()
    if kind in _API_KINDS:
        return True, f"initiator:{kind}"
    if content_type and _JSON_CONTENT_RE.search(content_type):
        return True, "content_type:json"
    try:
        path = (urlparse(url).path or "").lower()
    except Exception:  # noqa: BLE001
        return False, None
    for token in _API_PATH_TOKENS:
        if token in path:
            return True, f"path:{token}"
    segments = {s for s in path.split("/") if s}
    hit = segments & _API_SEGMENT_TOKENS
    if hit:
        return True, f"segment:{sorted(hit)[0]}"
    return False, None


@dataclass(frozen=True)
class ClassifiedRequest:
    """One NetworkArtifact plus its discovery classification."""

    artifact: NetworkArtifact
    is_same_origin: bool
    is_third_party: bool       # different registrable domain than the page
    is_api: bool
    api_reason: str | None = None


def classify_artifact(
    artifact: NetworkArtifact,
    *,
    page_host: str | None = None,
) -> ClassifiedRequest:
    """Classify one captured request relative to the page that fired it.

    ``page_host`` defaults to the hostname of ``artifact.page_url``.
    Same-origin means identical hostname; third-party means a different
    *registrable domain* (cdn.target.com is cross-origin but still
    first-party for discovery purposes)."""
    if page_host is None:
        page_host = ""
        if artifact.page_url:
            try:
                page_host = (urlparse(artifact.page_url).hostname or "").lower()
            except Exception:  # noqa: BLE001
                page_host = ""
    page_host = (page_host or "").lower()
    req_host = artifact.hostname

    same_origin = bool(req_host) and req_host == page_host
    third_party = (
        bool(req_host) and bool(page_host)
        and _registrable(req_host) != _registrable(page_host)
    )
    is_api, reason = looks_like_api(
        artifact.url,
        initiator_kind=artifact.initiator_kind,
        content_type=artifact.content_type,
    )
    return ClassifiedRequest(
        artifact=artifact,
        is_same_origin=same_origin,
        is_third_party=third_party,
        is_api=is_api,
        api_reason=reason,
    )


@dataclass
class NetworkCaptureSummary:
    """Scan-wide rollup of classified browser network traffic.

    Feeds the browser-pass coverage block — counts only, plus capped
    URL samples so the JSON export stays bounded."""

    total_requests: int = 0
    api_requests: int = 0
    same_origin_requests: int = 0
    third_party_requests: int = 0
    third_party_domains: set[str] = field(default_factory=set)
    api_sample_urls: list[str] = field(default_factory=list)
    _API_SAMPLE_CAP = 25

    def to_dict(self) -> dict:
        return {
            "browser_network_requests": self.total_requests,
            "browser_api_requests": self.api_requests,
            "browser_same_origin_requests": self.same_origin_requests,
            "browser_third_party_requests": self.third_party_requests,
            "browser_third_party_domains": sorted(self.third_party_domains),
            "browser_api_sample_urls": list(self.api_sample_urls),
        }


def summarize_network(
    telemetries: Iterable[BrowserTelemetry],
    *,
    primary_host: str | None = None,
) -> NetworkCaptureSummary:
    """Classify every artifact across all telemetries and roll up.

    ``primary_host`` (the scan target) is used as the page host
    fallback when an artifact has no ``page_url``."""
    summary = NetworkCaptureSummary()
    fallback = (primary_host or "").lower()
    for tel in telemetries:
        page_host = ""
        if tel.page_url:
            try:
                page_host = (urlparse(tel.page_url).hostname or "").lower()
            except Exception:  # noqa: BLE001
                page_host = ""
        page_host = page_host or fallback
        for art in tel.artifacts:
            cls = classify_artifact(art, page_host=page_host)
            summary.total_requests += 1
            if cls.is_same_origin:
                summary.same_origin_requests += 1
            if cls.is_third_party:
                summary.third_party_requests += 1
                if art.hostname:
                    summary.third_party_domains.add(art.hostname)
            if cls.is_api:
                summary.api_requests += 1
                if (art.url not in summary.api_sample_urls
                        and len(summary.api_sample_urls)
                        < summary._API_SAMPLE_CAP):
                    summary.api_sample_urls.append(art.url)
    return summary
