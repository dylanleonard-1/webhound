from __future__ import annotations

import time
import uuid
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a request ID to every request for log/Sentry correlation.

    Honors an inbound X-Request-ID (e.g. from the proxy) or generates one,
    exposes it on request.state.request_id, tags the Sentry scope, and echoes
    it back in the X-Request-ID response header.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = rid
        try:
            import sentry_sdk
            sentry_sdk.set_tag("request_id", rid)
        except Exception:  # noqa: BLE001 — correlation is best-effort
            pass
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            response.headers[name] = value
        if not request.url.path.startswith("/health"):
            response.headers["Cache-Control"] = "no-store"
        return response


def _client_ip(request: Request) -> str:
    """Best-effort real client IP.

    Behind Railway/Vercel, request.client.host is the proxy's IP — so keying
    on it lumps every user into one bucket. Prefer the original client from
    X-Forwarded-For (leftmost). That value is client-spoofable, but it
    correctly separates legitimate clients here; targeted auth abuse is
    independently mitigated by per-account login lockout.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    real = request.headers.get("x-real-ip")
    if real and real.strip():
        return real.strip()
    return request.client.host if request.client else "unknown"


class MaintenanceModeMiddleware(BaseHTTPMiddleware):
    """When the Redis flag `webhound:maintenance_mode` is set, return 503 for
    write paths that would queue scan work. Read-only paths (health, /internal
    dashboards, billing-read, etc.) keep working so staff can still see what's
    happening. Toggled from /control/team."""

    # Path prefixes blocked while engaged. Conservative — we want the SOC + the
    # auth flow to keep functioning so staff can recover.
    _BLOCKED_WRITE_PREFIXES = ("/scan-jobs", "/websites", "/scan-schedules")

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return await call_next(request)
        path = request.url.path
        if not any(path.startswith(p) for p in self._BLOCKED_WRITE_PREFIXES):
            return await call_next(request)
        try:
            from apps.api.services.maintenance import is_active
            if await is_active():
                return JSONResponse(
                    status_code=503,
                    content={"error": {"code": "maintenance",
                                       "message": "WebHound is in maintenance — try again shortly."}},
                    headers={"Retry-After": "60"},
                )
        except Exception:  # noqa: BLE001 — fail open
            pass
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self, app, *, requests_per_minute: int = 100, enabled: bool = True
    ) -> None:
        super().__init__(app)
        self._rpm = requests_per_minute
        self._enabled = enabled
        self._window = 60
        self._counts: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self._enabled:
            return await call_next(request)

        client_ip = _client_ip(request)
        now = time.time()
        cutoff = now - self._window
        self._counts[client_ip] = [t for t in self._counts[client_ip] if t > cutoff]

        if len(self._counts[client_ip]) >= self._rpm:
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "rate_limit_exceeded",
                        "message": "Too many requests.",
                        "details": {},
                    }
                },
                headers={"Retry-After": "60"},
            )

        self._counts[client_ip].append(now)
        return await call_next(request)
