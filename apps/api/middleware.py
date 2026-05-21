from __future__ import annotations

import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

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

        client_ip = request.client.host if request.client else "unknown"
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
