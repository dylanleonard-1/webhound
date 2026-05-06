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

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import httpx

from webhound.models.target import ScanOptions

# WebHound identifies itself clearly so site owners can recognize and allow it.
WEBHOUND_USER_AGENT = "WebHound/1.0 (security-scanner; +https://webhound.io/bot)"

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
    )


class SafeHttpClient:
    """Async, read-only HTTP client for WebHound security scanning.

    Usage::

        async with SafeHttpClient(options) as client:
            response = await client.get("https://example.com/")

    The client enforces a minimum inter-request delay derived from
    ``options.rate_limit_rps``.  All requests carry the WebHound User-Agent
    and a unique ``X-WebHound-Request-ID`` header for traceability.
    """

    def __init__(
        self,
        options: ScanOptions | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._options: ScanOptions = options or ScanOptions()
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self._min_delay: float = 1.0 / self._options.rate_limit_rps
        self._last_request_time: float = 0.0

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
            kwargs: dict[str, Any] = {
                "headers": {
                    "User-Agent": self._options.user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                },
                "timeout": httpx.Timeout(
                    connect=10.0,
                    read=float(self._options.request_timeout_seconds),
                    write=10.0,
                    pool=5.0,
                ),
                "follow_redirects": self._options.follow_redirects,
                "max_redirects": _MAX_REDIRECTS,
                "verify": self._options.verify_tls,
            }
            if self._transport is not None:
                kwargs["transport"] = self._transport
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

    async def _rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self._min_delay:
            await asyncio.sleep(self._min_delay - elapsed)

    async def _request(self, method: str, url: str) -> HttpResponse:
        request_id = uuid4()
        captured_at = datetime.now(timezone.utc)

        await self._ensure_client()
        await self._rate_limit()

        assert self._client is not None
        start = time.monotonic()

        try:
            response = await self._client.request(
                method,
                url,
                headers={"X-WebHound-Request-ID": str(request_id)},
            )
        except httpx.TimeoutException as exc:
            self._last_request_time = time.monotonic()
            return _error_response(request_id, url, f"timeout: {exc}", captured_at)
        except httpx.TooManyRedirects:
            self._last_request_time = time.monotonic()
            return _error_response(request_id, url, "too many redirects", captured_at)
        except httpx.RequestError as exc:
            self._last_request_time = time.monotonic()
            return _error_response(request_id, url, f"request error: {exc}", captured_at)
        finally:
            self._last_request_time = time.monotonic()

        elapsed_ms = (time.monotonic() - start) * 1000.0

        # Collect redirect chain from response history
        redirect_chain: list[str] = [str(r.url) for r in response.history]
        redirect_count = len(redirect_chain)

        # Read body up to the size limit
        try:
            raw_body = response.content[:_MAX_BODY_BYTES]
            encoding = response.encoding or "utf-8"
            body = raw_body.decode(encoding, errors="replace")
        except Exception:
            body = ""

        # Normalise header keys to lowercase
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
