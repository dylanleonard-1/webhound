from __future__ import annotations

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from apps.api.config import get_settings
from apps.api.errors import (
    http_exception_handler,
    internal_exception_handler,
    validation_exception_handler,
)
from apps.api.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from apps.api.routers import (
    auth,
    baselines,
    health,
    notifications,
    oauth,
    phone,
    scan_jobs,
    scan_results,
    scan_schedules,
    websites,
)

settings = get_settings()

app = FastAPI(
    title="WebHound API",
    version="0.1.0",
    description=(
        "WebHound is a security scanning and monitoring platform. "
        "Use this API to manage websites, trigger scans, review findings, "
        "configure schedules, and receive security alerts."
    ),
    docs_url="/docs" if settings.app_env != "production" else None,
    redoc_url=None,
)

# ---------------------------------------------------------------------------
# Middleware (outermost → innermost)
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    RateLimitMiddleware,
    requests_per_minute=settings.rate_limit_requests_per_minute,
    enabled=settings.rate_limit_enabled,
)

# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------

app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, internal_exception_handler)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(health.router, tags=["health"])
app.include_router(auth.router)
app.include_router(oauth.router)
app.include_router(phone.router)
app.include_router(websites.router)
app.include_router(scan_jobs.router)
app.include_router(scan_results.router)
app.include_router(baselines.router)
app.include_router(scan_schedules.router)
app.include_router(notifications.router)
