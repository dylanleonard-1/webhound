from __future__ import annotations

import logging

import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from apps.api.config import get_settings
from apps.api.database import AsyncSessionLocal
from apps.api.errors import (
    http_exception_handler,
    internal_exception_handler,
    validation_exception_handler,
)
from apps.api.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from apps.api.models.user import User
from apps.api.routers import (
    auth,
    baselines,
    billing,
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

# Configure root logging once at process start. Without this, every
# logger.info() in the codebase is silently dropped (Python's default
# root level is WARNING). Reads the level from LOG_LEVEL env var via
# the settings model — defaults to INFO.
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
# Don't drown the logs in SQLAlchemy's verbose statement / parameter
# output even when LOG_LEVEL=INFO — those have their own engine.echo
# knob, and Railway access logs already pin the request flow.
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)

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
    allow_origin_regex=settings.cors_origin_regex or None,
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
app.include_router(billing.router)


@app.on_event("startup")
async def _backfill_admin_emails() -> None:
    emails = settings.admin_emails
    if not emails:
        return
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            sa.update(User)
            .where(sa.func.lower(User.email).in_(emails), User.is_admin.is_(False))
            .values(is_admin=True)
        )
        await db.commit()
        if result.rowcount:
            logging.getLogger(__name__).info(
                "Promoted %d user(s) to admin via admin_emails", result.rowcount
            )
