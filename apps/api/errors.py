from __future__ import annotations

import logging

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

_STATUS_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    422: "validation_error",
    429: "rate_limit_exceeded",
    500: "internal_error",
}


def _body(code: str, message: str, details: dict | None = None) -> dict:
    return {"error": {"code": code, "message": message, "details": details or {}}}


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    code = _STATUS_CODES.get(exc.status_code, "error")
    message = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return JSONResponse(status_code=exc.status_code, content=_body(code, message))


def _safe_errors(errors: list) -> list:
    safe = []
    for e in errors:
        ctx = e.get("ctx", {})
        safe.append(
            {
                "loc": list(e.get("loc", [])),
                "msg": e.get("msg", ""),
                "type": e.get("type", ""),
                "ctx": {k: str(v) for k, v in ctx.items()},
            }
        )
    return safe


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=_body(
            "validation_error",
            "Validation failed.",
            {"errors": _safe_errors(exc.errors())},
        ),
    )


async def internal_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    logger.exception("unhandled exception on %s %s", request.method, request.url.path)
    # Report to Sentry if configured. capture_exception is a no-op when Sentry
    # isn't initialized, so this is safe in dev / unconfigured environments.
    try:
        import sentry_sdk
        sentry_sdk.capture_exception(exc)
    except Exception:  # noqa: BLE001
        pass
    # Also surface in the /control Log Explorer so on-call staff don't need to
    # tab over to Sentry to see what's happening. Best-effort, runs on its own
    # session so a DB issue can't shadow the real 500.
    try:
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from apps.api.database import get_session_factory
        from apps.api.services.logs import record_server_error
        factory = get_session_factory()
        if factory is not None:
            async with factory() as db:
                await record_server_error(
                    db,
                    request_method=request.method,
                    request_path=str(request.url.path),
                    exception=exc,
                    request_id=getattr(request.state, "request_id", None),
                )
    except Exception:  # noqa: BLE001 — logging must never shadow the real 500
        pass
    return JSONResponse(
        status_code=500,
        content=_body("internal_error", "An unexpected error occurred."),
    )
