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
    return JSONResponse(
        status_code=500,
        content=_body("internal_error", "An unexpected error occurred."),
    )
