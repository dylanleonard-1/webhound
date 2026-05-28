# WebHound — scanner/webhound/threat_intel/virustotal_client.py
# VirusTotal v3 provider for domain reputation.
#
# VirusTotal's domains endpoint (GET /api/v3/domains/{domain}) requires an
# API key (free tier: 4 requests/minute, 500/day). Without a key, this
# client returns an error ProviderResult.
#
# OFFLINE-SAFE BY DEFAULT: the client raises immediately unless the caller
# passes ``allow_network=True``. Reads the API key from the VIRUSTOTAL_API_KEY
# env var or the explicit constructor argument.
#
# Built-in protections for the VT free tier (4 req/min, 500/day):
#   - Per-instance in-memory cache (TTL configurable, default 6h) so the
#     same domain isn't re-queried within a single scan or across pages.
#   - Token-bucket rate limiter (default 4 calls per 60s) that waits
#     instead of failing when the budget is exhausted.

from __future__ import annotations

import asyncio
import json
import os
import time
from collections import deque
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

import httpx

from .enrichment_service import BaseProvider, EnrichmentState, ProviderResult

_VT_DOMAIN_API = "https://www.virustotal.com/api/v3/domains/{domain}"


class _TokenBucket:
    """Simple sliding-window rate limiter: at most N calls per window seconds.

    Records the timestamp of each call; before granting a new call, evicts
    timestamps older than `window` and (if the bucket is full) sleeps until
    the oldest slot frees up. Thread-safe in a single asyncio loop via an
    asyncio.Lock.
    """

    def __init__(self, max_calls: int, window_seconds: float) -> None:
        self._max = max_calls
        self._window = window_seconds
        self._calls: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                while self._calls and now - self._calls[0] > self._window:
                    self._calls.popleft()
                if len(self._calls) < self._max:
                    self._calls.append(now)
                    return
                sleep_for = self._window - (now - self._calls[0]) + 0.05
                await asyncio.sleep(max(0.05, sleep_for))


class VirusTotalClient(BaseProvider):
    """VirusTotal v3 domain-reputation provider — offline-safe by default."""

    name = "virustotal"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        allow_network: bool = False,
        timeout: float = 10.0,
        rate_limit_calls: int = 4,
        rate_limit_window: float = 60.0,
        cache_ttl_seconds: float = 6 * 3600.0,
    ) -> None:
        self._api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self._allow_network = allow_network
        self._timeout = timeout
        self._bucket = _TokenBucket(rate_limit_calls, rate_limit_window)
        self._cache: dict[str, tuple[float, ProviderResult]] = {}
        self._cache_ttl = cache_ttl_seconds

    async def enrich(self, domain: str) -> ProviderResult:
        now = datetime.now(timezone.utc)
        cache_key = domain.lower().strip()

        # In-memory cache check first — never re-hit VT for the same host.
        cached = self._cache.get(cache_key)
        if cached is not None:
            ts, result = cached
            age = time.monotonic() - ts
            if age < self._cache_ttl:
                # Return the cached verdict but flag it as cached so the
                # dashboard can render "VT (cached, age 12m)" instead of
                # implying a fresh lookup.
                cached_dt = result.cached_at or result.checked_at
                # If the original was rate-limited / unavailable, surface
                # that same state — cached doesn't change the verdict
                # category, only its provenance.
                final_state = (result.state
                               if result.state in _NON_CHECKED_STATES
                               else EnrichmentState.CACHED)
                return replace(
                    result,
                    checked_at=now, cached_at=cached_dt,
                    state=final_state, cache_ttl_seconds=int(self._cache_ttl),
                )

        if not self._allow_network:
            return ProviderResult(
                provider=self.name, domain=domain,
                reputation_score=None, confidence=0.0,
                categories=[], is_malicious=None, is_suspicious=None,
                raw={}, checked_at=now,
                error="virustotal disabled: allow_network=False (offline mode)",
                state=EnrichmentState.SKIPPED,
            )
        if not self._api_key:
            return ProviderResult(
                provider=self.name, domain=domain,
                reputation_score=None, confidence=0.0,
                categories=[], is_malicious=None, is_suspicious=None,
                raw={}, checked_at=now,
                error="virustotal: no API key (set VIRUSTOTAL_API_KEY)",
                state=EnrichmentState.SKIPPED,
            )

        await self._bucket.acquire()

        headers = {"x-apikey": self._api_key, "Accept": "application/json"}
        url = _VT_DOMAIN_API.format(domain=domain)
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(url, headers=headers)
            if resp.status_code == 429:
                # Daily quota exhausted — record but don't hammer further.
                result = ProviderResult(
                    provider=self.name, domain=domain,
                    reputation_score=None, confidence=0.0,
                    categories=[], is_malicious=None, is_suspicious=None,
                    raw={}, checked_at=now,
                    error="virustotal: rate-limited (HTTP 429)",
                    state=EnrichmentState.RATE_LIMITED,
                    cached_at=now, cache_ttl_seconds=int(self._cache_ttl),
                )
                self._cache[cache_key] = (time.monotonic(), result)
                return result
            payload = resp.json() if resp.headers.get(
                "content-type", "").startswith("application/json") else {}
            result = _parse_vt_response(domain, payload, now,
                                        cache_ttl_seconds=int(self._cache_ttl))
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            result = ProviderResult(
                provider=self.name, domain=domain,
                reputation_score=None, confidence=0.0,
                categories=[], is_malicious=None, is_suspicious=None,
                raw={}, checked_at=now,
                error=f"virustotal lookup failed: {exc}",
                state=EnrichmentState.UNAVAILABLE,
            )

        self._cache[cache_key] = (time.monotonic(), result)
        return result


# States that should be preserved through a cache hit — cached
# rate-limited / unavailable verdict should NOT be reported as a fresh
# "cached" success.
_NON_CHECKED_STATES = frozenset({
    EnrichmentState.RATE_LIMITED, EnrichmentState.UNAVAILABLE,
    EnrichmentState.SKIPPED, EnrichmentState.DEFERRED,
})


def _parse_vt_response(
    domain: str, payload: dict[str, Any], checked_at: datetime,
    *, cache_ttl_seconds: int | None = None,
) -> ProviderResult:
    data = (payload.get("data") or {}).get("attributes") or {}
    stats = data.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return ProviderResult(
            provider="virustotal", domain=domain,
            reputation_score=None, confidence=0.0,
            categories=[], is_malicious=None, is_suspicious=None,
            raw=payload, checked_at=checked_at,
            error="virustotal: no analysis stats in response",
            state=EnrichmentState.UNAVAILABLE,
            cached_at=checked_at, cache_ttl_seconds=cache_ttl_seconds,
        )
    detect_ratio = (malicious + suspicious) / total
    rep_score = round(detect_ratio * 10.0, 2)
    categories_dict = data.get("categories") or {}
    categories = sorted({str(v).lower() for v in categories_dict.values()
                         if isinstance(v, str)})
    return ProviderResult(
        provider="virustotal", domain=domain,
        reputation_score=rep_score,
        confidence=0.9 if total >= 20 else 0.7,
        categories=categories,
        is_malicious=malicious >= 2,
        is_suspicious=(malicious + suspicious) >= 1,
        raw=payload, checked_at=checked_at,
        state=EnrichmentState.CHECKED,
        cached_at=checked_at, cache_ttl_seconds=cache_ttl_seconds,
        malicious_count=malicious, suspicious_count=suspicious,
        harmless_count=harmless, undetected_count=undetected,
    )
