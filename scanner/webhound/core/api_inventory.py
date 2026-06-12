# WebHound — scanner/webhound/core/api_inventory.py
# THE canonical API inventory — single source of truth for "how many APIs".
#
# Problem it fixes: three different counters computed "APIs" three different
# ways (graph kept the query string per request → 1099; observed-requests
# deduped by bare URL → 24; coverage_summary didn't dedup at all). This module
# produces ONE deduped, classified endpoint list that every surface reads:
# Browser Discovery / Visibility Map / Security Graph / WADE / Findings / UI.
#
# Canonical key = METHOD + scheme://host/path  (QUERY STRING IGNORED). So
# /api/users?id=1, ?id=2, ?id=3 collapse to ONE entry `GET …/api/users` count=1.
#
# Headline metric = FIRST_PARTY_API + GRAPHQL + AUTH_API only. Framework
# internals (_next/_rsc/_vercel) and analytics beacons are still inventoried
# (so nothing is hidden) but excluded from the headline.
#
# Reuses existing detectors — looks_like_api (network_capture), _gather_endpoints
# + _classify + the path regexes (endpoint_discovery), _registrable
# (network_capture) — rather than adding a 4th detection implementation.
#
# Safe-mode: pure aggregation. No network, no submission, no JS execution.

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse


class EndpointClass(str, Enum):
    """What a canonical endpoint IS. Only the first three count toward the
    headline API metric; all six appear in the details breakdown."""

    FIRST_PARTY_API = "first_party_api"
    GRAPHQL = "graphql"
    AUTH_API = "auth_api"
    FRAMEWORK_INTERNAL = "framework_internal"
    ANALYTICS = "analytics"
    THIRD_PARTY_API = "third_party_api"


#: Classes that count toward the customer-facing "APIs" headline number.
HEADLINE_CLASSES: frozenset[EndpointClass] = frozenset({
    EndpointClass.FIRST_PARTY_API,
    EndpointClass.GRAPHQL,
    EndpointClass.AUTH_API,
})

#: Classes the Security Graph should NOT materialize as API_ENDPOINT nodes
#: (so node/connection counts deflate). Still inventoried + shown in details.
GRAPH_EXCLUDED_CLASSES: frozenset[EndpointClass] = frozenset({
    EndpointClass.FRAMEWORK_INTERNAL,
    EndpointClass.ANALYTICS,
})

# --- Framework-internal path/query markers (Next.js / Nuxt / Vercel / etc.) ---
_FRAMEWORK_PATH_RE = re.compile(
    r"^/(?:_next/|_nuxt/|__nextjs|_vercel/|_analytics/|cdn-cgi/|__webpack)",
    re.I,
)
_FRAMEWORK_QUERY_RE = re.compile(r"(?:^|&)_rsc=", re.I)  # Next App-Router RSC

# --- Analytics / beacon / telemetry hosts + paths -----------------------------
_ANALYTICS_HOST_SUBSTR = (
    "google-analytics.com", "googletagmanager.com", "analytics.google.com",
    "stats.g.doubleclick.net", "g.doubleclick.net",
    "sentry.io", "ingest.sentry.io", "segment.io", "segment.com",
    "mixpanel.com", "amplitude.com", "hotjar.com", "hotjar.io",
    "plausible.io", "posthog.com", "fullstory.com", "datadoghq.com",
    "newrelic.com", "nr-data.net", "bugsnag.com", "intercom.io",
    "clarity.ms", "cloudflareinsights.com", "vercel-insights.com",
    "vitals.vercel-insights.com", "vercel-analytics.com",
)
_ANALYTICS_PATH_RE = re.compile(
    r"(?:/_vercel/(?:insights|speed-insights)|/speed-insights|/vitals\b|"
    r"/collect\b|/g/collect\b|/beacon\b|/telemetry\b|/track\b|/pageview\b|"
    r"/__vercel_analytics|/api/track\b|/i/v\d+/e\b)",
    re.I,
)

# Reused from endpoint_discovery (auth + graphql shapes).
_GRAPHQL_RE = re.compile(r"(?:/graphql\b|/graphiql\b|/__graphql\b|\?__schema\b)", re.I)
_AUTH_RE = re.compile(
    r"/(?:oauth\d?|sso|saml|openid|auth|login|signin|signup|register|"
    r"token|refresh|logout|session|otp|mfa|2fa|password[-_]?reset|"
    r"forgot[-_]?password)\b",
    re.I,
)
_API_SHAPE_RE = re.compile(
    r"(?:/api(?:/|$)|/rest(?:/|$)|/graphql\b|/gql\b|/v\d+(?:/|$)|/wp-json/|"
    r"/services?/|/internal/|/rpc(?:/|$)|/jsonrpc\b|\.json(?:$|\?|/))",
    re.I,
)

_SAMPLE_CAP = 3
_TOKEN_RE = re.compile(
    r'([?&](?:token|key|api_key|apikey|secret|sig|password|auth|session)=)[^&\s]+',
    re.I,
)


def _redact(url: str) -> str:
    return _TOKEN_RE.sub(r"\1<redacted>", url or "")


def _hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def _registrable(host: str) -> str:
    """eTLD+1 via the existing helper; falls back to the bare host."""
    try:
        from webhound.browser.network_capture import _registrable as _r
        return _r(host)
    except Exception:  # noqa: BLE001
        return host


def canonical_key(method: str, url: str) -> str | None:
    """`METHOD scheme://host/path` with the QUERY STRING and fragment dropped.
    Returns None for an unusable URL (no host)."""
    try:
        p = urlparse(url)
    except Exception:  # noqa: BLE001
        return None
    host = (p.hostname or "").lower()
    if not host:
        return None
    scheme = (p.scheme or "https").lower()
    port = f":{p.port}" if p.port else ""
    path = p.path or "/"
    m = (method or "GET").upper()
    return f"{m} {scheme}://{host}{port}{path}"


def classify_endpoint(url: str, *, primary_host: str | None) -> EndpointClass:
    """Classify a single endpoint URL. Order matters: framework + analytics are
    detected first so they never inflate the API headline."""
    p = urlparse(url)
    host = (p.hostname or "").lower()
    path = p.path or "/"
    query = p.query or ""
    primary_reg = _registrable((primary_host or "").lower()) if primary_host else ""
    host_reg = _registrable(host)
    is_first_party = bool(primary_reg) and host_reg == primary_reg

    # 1. Framework internals (Next.js RSC / _next / _vercel / Nuxt / …).
    if _FRAMEWORK_PATH_RE.search(path) or _FRAMEWORK_QUERY_RE.search(query):
        return EndpointClass.FRAMEWORK_INTERNAL
    # 2. Analytics / beacons / telemetry (host or path).
    if any(s in host for s in _ANALYTICS_HOST_SUBSTR) or _ANALYTICS_PATH_RE.search(path):
        return EndpointClass.ANALYTICS
    # 3. GraphQL.
    if _GRAPHQL_RE.search(path) or _GRAPHQL_RE.search("?" + query):
        return EndpointClass.GRAPHQL
    # 4. Auth APIs.
    if _AUTH_RE.search(path):
        return EndpointClass.AUTH_API
    # 5. First- vs third-party real API.
    return (EndpointClass.FIRST_PARTY_API if is_first_party
            else EndpointClass.THIRD_PARTY_API)


@dataclass
class CanonicalEndpoint:
    key: str                       # METHOD scheme://host/path (dedup identity)
    method: str
    url: str                       # representative scheme://host/path (no query)
    host: str
    path: str
    endpoint_class: EndpointClass
    party: str                     # "first" | "third"
    tags: set[str] = field(default_factory=set)
    observed_count: int = 0        # how many raw requests collapsed into this
    sample_urls: list[str] = field(default_factory=list)  # redacted, capped

    @property
    def in_headline(self) -> bool:
        return self.endpoint_class in HEADLINE_CLASSES

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "class": self.endpoint_class.value,
            "party": self.party,
            "tags": sorted(self.tags),
            "observed_count": self.observed_count,
            "in_headline": self.in_headline,
            "samples": list(self.sample_urls),
        }


class ApiInventory:
    """Deduped, classified canonical API inventory for one scan."""

    def __init__(self, primary_host: str | None = None) -> None:
        self.primary_host = (primary_host or "").lower()
        self._by_key: dict[str, CanonicalEndpoint] = {}

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def add(self, raw_url: str, *, method: str = "GET",
            base_url: str | None = None) -> CanonicalEndpoint | None:
        """Canonicalize, classify, and merge one endpoint reference."""
        if not raw_url:
            return None
        url = urljoin(base_url, raw_url) if base_url else raw_url
        key = canonical_key(method, url)
        if key is None:
            return None
        existing = self._by_key.get(key)
        p = urlparse(url)
        host = (p.hostname or "").lower()
        bare = f"{(p.scheme or 'https').lower()}://{host}{p.path or '/'}"
        if existing is None:
            cls = classify_endpoint(url, primary_host=self.primary_host)
            primary_reg = (_registrable(self.primary_host)
                           if self.primary_host else "")
            party = ("first" if primary_reg and _registrable(host) == primary_reg
                     else "third")
            tags: set[str] = set()
            try:
                from webhound.engines.api_discovery.endpoint_discovery import (
                    _classify as _ep_classify,
                )
                tags = _ep_classify(url)
            except Exception:  # noqa: BLE001
                pass
            existing = CanonicalEndpoint(
                key=key, method=(method or "GET").upper(), url=bare,
                host=host, path=p.path or "/", endpoint_class=cls,
                party=party, tags=tags,
            )
            self._by_key[key] = existing
        existing.observed_count += 1
        if len(existing.sample_urls) < _SAMPLE_CAP:
            r = _redact(url)
            if r not in existing.sample_urls:
                existing.sample_urls.append(r)
        return existing

    @classmethod
    def build(
        cls,
        crawl_results: Iterable[Any] | None = None,
        *,
        browser: Any = None,
        primary_host: str | None = None,
    ) -> "ApiInventory":
        """Build the canonical inventory from static crawl artifacts +
        browser-observed network traffic. Reuses endpoint_discovery's static
        extractor and network_capture.looks_like_api for the browser side."""
        inv = cls(primary_host=primary_host)

        # 1. Static references in page HTML + inline JS.
        try:
            from webhound.engines.api_discovery.endpoint_discovery import (
                _gather_endpoints,
            )
        except Exception:  # noqa: BLE001
            _gather_endpoints = None
        for r in crawl_results or []:
            arts = getattr(r, "artifacts", None)
            if arts is None or _gather_endpoints is None:
                continue
            page_url = getattr(arts, "url", None) or ""
            try:
                for u in _gather_endpoints(arts):
                    inv.add(u, method="GET", base_url=page_url or None)
            except Exception:  # noqa: BLE001
                continue
            # Form actions carry a method.
            for f in getattr(arts, "forms", None) or []:
                action = getattr(f, "action_url", None)
                if action:
                    inv.add(action, method=getattr(f, "method", "GET") or "GET",
                            base_url=page_url or None)

        # 2. Browser-observed traffic that looks like an API.
        if browser is not None:
            try:
                from webhound.browser.network_capture import looks_like_api
                for art in browser.get_all_network_requests() or []:
                    url = getattr(art, "url", None)
                    if not url:
                        continue
                    is_api, _reason = looks_like_api(
                        url,
                        initiator_kind=getattr(art, "initiator_kind", None),
                        content_type=getattr(art, "content_type", None),
                    )
                    if is_api:
                        inv.add(url, method=getattr(art, "method", "GET") or "GET")
            except Exception:  # noqa: BLE001
                pass
        return inv

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def endpoints(self) -> list[CanonicalEndpoint]:
        return list(self._by_key.values())

    def headline_endpoints(self) -> list[CanonicalEndpoint]:
        return [e for e in self._by_key.values() if e.in_headline]

    def graph_endpoints(self) -> list[CanonicalEndpoint]:
        """Endpoints the Security Graph should node-ify (everything real —
        excludes only framework internals + analytics)."""
        return [e for e in self._by_key.values()
                if e.endpoint_class not in GRAPH_EXCLUDED_CLASSES]

    @property
    def headline_count(self) -> int:
        return sum(1 for e in self._by_key.values() if e.in_headline)

    @property
    def total_count(self) -> int:
        return len(self._by_key)

    def by_class(self) -> dict[str, int]:
        out: dict[str, int] = {c.value: 0 for c in EndpointClass}
        for e in self._by_key.values():
            out[e.endpoint_class.value] += 1
        return out

    def to_dict(self, *, cap: int = 200) -> dict:
        eps = sorted(self._by_key.values(),
                     key=lambda e: (not e.in_headline, e.endpoint_class.value, e.url))
        return {
            "headline_count": self.headline_count,
            "total_count": self.total_count,
            "by_class": self.by_class(),
            "headline_classes": sorted(c.value for c in HEADLINE_CLASSES),
            "endpoints": [e.to_dict() for e in eps[:cap]],
        }
