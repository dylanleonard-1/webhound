# WebHound — scanner/webhound/core/http_client.py
# Safe, read-only async HTTP client for security scanning.
#
# Design constraints (safe-mode-first):
#   - Only GET and HEAD methods — no state-mutating requests.
#   - Identifies itself honestly via a fixed WebHound User-Agent.
#   - Rate-limiting delay enforced between requests.
#   - Hard timeout on every request — never blocks indefinitely.
#   - Cookies are not stored between requests (stateless scanner session).
#   - TLS verification on by default.
#   - Redirects followed up to a configurable maximum hop count.
#   - All responses wrapped in HttpResponse with request metadata.
#   - Exponential backoff retries on transient errors (429, 5xx, timeout).

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import httpx

from webhound.core.retry_policy import (
    DEFAULT_RETRY_POLICY,
    FetchStats,
    RetryPolicy,
    compute_backoff_delay,
    parse_retry_after,
    should_retry,
)
from webhound.core.session_context import SessionContext
from webhound.core.ssrf_guard import build_guarded_transport
from webhound.identity import SCANNER_USER_AGENT
from webhound.models.target import ScanOptions

# WebHound identifies itself clearly so site owners can recognize and allow it.
# The canonical value lives in webhound.identity (single source of truth);
# this name is kept as a back-compat alias.
WEBHOUND_USER_AGENT = SCANNER_USER_AGENT

# Maximum redirects the client will follow before giving up.
_MAX_REDIRECTS: int = 10

# Maximum response body size read into memory (4 MB).
_MAX_BODY_BYTES: int = 4 * 1024 * 1024


@dataclass(frozen=True)
class HttpResponse:
    """Structured result of a single HTTP request including metadata."""

    request_id: UUID
    original_url: str
    url: str                          # Final URL after any redirects
    status_code: int
    headers: dict[str, str]
    body: str
    content_type: str | None
    elapsed_ms: float
    redirect_count: int
    redirect_chain: list[str]         # Intermediate URLs traversed
    captured_at: datetime
    error: str | None = None          # Set when the request failed; status_code = 0
    retry_count: int = 0              # Number of retry attempts made

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return self.status_code >= 500

    @property
    def failed(self) -> bool:
        return self.error is not None

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower())


def _error_response(
    request_id: UUID,
    original_url: str,
    error: str,
    captured_at: datetime,
    retry_count: int = 0,
) -> HttpResponse:
    return HttpResponse(
        request_id=request_id,
        original_url=original_url,
        url=original_url,
        status_code=0,
        headers={},
        body="",
        content_type=None,
        elapsed_ms=0.0,
        redirect_count=0,
        redirect_chain=[],
        captured_at=captured_at,
        error=error,
        retry_count=retry_count,
    )


class SafeHttpClient:
    """Async, read-only HTTP client for WebHound security scanning.

    Usage::

        async with SafeHttpClient(options) as client:
            response = await client.get("https://example.com/")

    The client enforces a minimum inter-request delay derived from
    ``options.rate_limit_rps``.  All requests carry the WebHound User-Agent
    and a unique ``X-WebHound-Request-ID`` header for traceability.

    Transient errors (429, 5xx, timeouts) are retried with exponential backoff
    according to the supplied ``retry_policy`` (defaults to
    :data:`DEFAULT_RETRY_POLICY`).  Fetch statistics are accumulated in
    :attr:`fetch_stats` for reporting.
    """

    def __init__(
        self,
        options: ScanOptions | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        retry_policy: RetryPolicy | None = None,
        session_context: SessionContext | None = None,
    ) -> None:
        self._options: ScanOptions = options or ScanOptions()
        self._transport = transport
        self._retry_policy: RetryPolicy = retry_policy or DEFAULT_RETRY_POLICY
        self._session_context: SessionContext | None = session_context
        self._client: httpx.AsyncClient | None = None
        self._min_delay: float = 1.0 / self._options.rate_limit_rps
        self._last_request_time: float = 0.0
        self._fetch_stats: FetchStats = FetchStats()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "SafeHttpClient":
        await self._ensure_client()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def _ensure_client(self) -> None:
        if self._client is None:
            base_headers: dict[str, str] = {
                "User-Agent": self._options.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
            base_cookies: dict[str, str] = {}
            if self._session_context is not None:
                # Session headers override defaults; session cookies are merged in.
                base_headers.update(self._session_context.merged_headers())
                base_cookies.update(self._session_context.merged_cookies())
            # Provider trusted-automation bypass headers (e.g. Vercel
            # x-vercel-protection-bypass). Applied last so they always take effect.
            # Never logged.
            extra = getattr(self._options, "extra_http_headers", None)
            if extra:
                base_headers.update(extra)
            kwargs: dict[str, Any] = {
                "headers": base_headers,
                "cookies": base_cookies or None,
                "timeout": httpx.Timeout(
                    connect=10.0,
                    read=float(self._options.request_timeout_seconds),
                    write=10.0,
                    pool=5.0,
                ),
                "follow_redirects": self._options.follow_redirects,
                "max_redirects": _MAX_REDIRECTS,
            }
            # SSRF egress guard: connections are pinned to a validated public
            # IP on the initial request and every redirect hop (no DNS-rebinding
            # TOCTOU). An injected transport (tests) is trusted and used as-is —
            # the guard only wraps real network egress. TLS verification lives on
            # the guarded transport since a custom transport overrides the
            # client-level `verify` kwarg.
            if self._transport is not None:
                kwargs["transport"] = self._transport
            else:
                kwargs["transport"] = build_guarded_transport(
                    verify=self._options.verify_tls
                )
            self._client = httpx.AsyncClient(**kwargs)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Request methods — GET and HEAD only (safe-mode)
    # ------------------------------------------------------------------

    async def get(self, url: str) -> HttpResponse:
        """Perform a safe GET request and return a structured HttpResponse."""
        return await self._request("GET", url)

    async def head(self, url: str) -> HttpResponse:
        """Perform a safe HEAD request and return a structured HttpResponse."""
        return await self._request("HEAD", url)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @property
    def fetch_stats(self) -> FetchStats:
        """Cumulative HTTP fetch statistics across all requests made so far."""
        return self._fetch_stats

    async def _rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self._min_delay:
            await asyncio.sleep(self._min_delay - elapsed)

    async def _request(self, method: str, url: str) -> HttpResponse:
        request_id = uuid4()
        captured_at = datetime.now(timezone.utc)

        await self._ensure_client()
        assert self._client is not None

        retry_count = 0

        for attempt in range(self._retry_policy.max_retries + 1):
            await self._rate_limit()
            start = time.monotonic()

            try:
                response = await self._client.request(
                    method,
                    url,
                    headers={"X-WebHound-Request-ID": str(request_id)},
                )
            except httpx.TimeoutException as exc:
                self._last_request_time = time.monotonic()
                error = f"timeout: {exc}"
                self._fetch_stats.timed_out += 1
                if should_retry(0, error, attempt, self._retry_policy):
                    delay = compute_backoff_delay(attempt, self._retry_policy)
                    self._fetch_stats.retried += 1
                    retry_count += 1
                    await asyncio.sleep(delay)
                    continue
                self._fetch_stats.record(0.0, is_success=False)
                return _error_response(request_id, url, error, captured_at, retry_count)
            except httpx.TooManyRedirects:
                self._last_request_time = time.monotonic()
                self._fetch_stats.record(0.0, is_success=False)
                return _error_response(
                    request_id, url, "too many redirects", captured_at, retry_count
                )
            except httpx.RequestError as exc:
                self._last_request_time = time.monotonic()
                self._fetch_stats.record(0.0, is_success=False)
                return _error_response(
                    request_id, url, f"request error: {exc}", captured_at, retry_count
                )

            self._last_request_time = time.monotonic()
            elapsed_ms = (time.monotonic() - start) * 1000.0

            # 429 — honour Retry-After header when present
            if response.status_code == 429:
                self._fetch_stats.rate_limited += 1
                if should_retry(429, None, attempt, self._retry_policy):
                    retry_after = parse_retry_after(
                        response.headers.get("retry-after")
                    )
                    delay = retry_after or compute_backoff_delay(
                        attempt, self._retry_policy
                    )
                    self._fetch_stats.retried += 1
                    retry_count += 1
                    await asyncio.sleep(delay)
                    continue
            elif should_retry(response.status_code, None, attempt, self._retry_policy):
                delay = compute_backoff_delay(attempt, self._retry_policy)
                self._fetch_stats.retried += 1
                retry_count += 1
                await asyncio.sleep(delay)
                continue

            is_success = 200 <= response.status_code < 300
            self._fetch_stats.record(elapsed_ms, is_success=is_success)

            redirect_chain: list[str] = [str(r.url) for r in response.history]
            redirect_count = len(redirect_chain)

            try:
                raw_body = response.content[:_MAX_BODY_BYTES]
                encoding = response.encoding or "utf-8"
                body = raw_body.decode(encoding, errors="replace")
            except Exception:
                body = ""

            headers = {k.lower(): v for k, v in response.headers.items()}
            content_type = headers.get("content-type")

            return HttpResponse(
                request_id=request_id,
                original_url=url,
                url=str(response.url),
                status_code=response.status_code,
                headers=headers,
                body=body,
                content_type=content_type,
                elapsed_ms=round(elapsed_ms, 2),
                redirect_count=redirect_count,
                redirect_chain=redirect_chain,
                captured_at=captured_at,
                retry_count=retry_count,
            )

        # All retry attempts exhausted (should not be reached in normal flow)
        self._fetch_stats.record(0.0, is_success=False)
        return _error_response(
            request_id, url, "max retries exhausted", captured_at, retry_count
        )

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def user_agent(self) -> str:
        return self._options.user_agent

    @property
    def timeout_seconds(self) -> int:
        return self._options.request_timeout_seconds

    @property
    def rate_limit_rps(self) -> float:
        return self._options.rate_limit_rps
