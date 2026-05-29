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
from apps.api.middleware import (
    MaintenanceModeMiddleware,
    RateLimitMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
)
from apps.api.models.user import User
from apps.api.routers import (
    auth,
    baselines,
    billing,
    health,
    notifications,
    oauth,
    orgs,
    phone,
    public_scan,
    suppressions,
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

# Error monitoring — no-op unless SENTRY_DSN is set and app_env != development.
from apps.api.observability import init_sentry  # noqa: E402
init_sentry()

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
app.add_middleware(MaintenanceModeMiddleware)

app.add_middleware(
    RateLimitMiddleware,
    requests_per_minute=settings.rate_limit_requests_per_minute,
    enabled=settings.rate_limit_enabled,
)

# Added last → outermost → runs first, so the request ID is set before the
# other middleware and available everywhere (logs, Sentry scope, response).
app.add_middleware(RequestIdMiddleware)

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
app.include_router(orgs.router)
app.include_router(suppressions.router)
app.include_router(public_scan.router)
app.include_router(websites.router)
app.include_router(scan_jobs.router)
app.include_router(scan_results.router)
app.include_router(baselines.router)
app.include_router(scan_schedules.router)
app.include_router(notifications.router)
app.include_router(billing.router)

# Internal /control command center (RBAC-gated staff APIs).
from apps.api.internal.router import router as internal_router  # noqa: E402
from apps.api.internal.scan_ops import router as internal_scan_ops_router  # noqa: E402
from apps.api.internal.alerts import router as internal_alerts_router  # noqa: E402
from apps.api.internal.customers import router as internal_customers_router  # noqa: E402
from apps.api.internal.billing_ops import router as internal_billing_router  # noqa: E402
from apps.api.internal.abuse import router as internal_abuse_router  # noqa: E402
from apps.api.internal.support import router as internal_support_router  # noqa: E402
from apps.api.internal.team_deploys import router as internal_team_deploys_router  # noqa: E402
from apps.api.internal.logs import router as internal_logs_router  # noqa: E402
from apps.api.internal.threat_intel import router as internal_threat_intel_router  # noqa: E402
from apps.api.internal.incidents import router as internal_incidents_router  # noqa: E402
from apps.api.internal.engines import router as internal_engines_router  # noqa: E402
app.include_router(internal_router)
app.include_router(internal_scan_ops_router)
app.include_router(internal_alerts_router)
app.include_router(internal_customers_router)
app.include_router(internal_billing_router)
app.include_router(internal_abuse_router)
app.include_router(internal_support_router)
app.include_router(internal_team_deploys_router)
app.include_router(internal_logs_router)
app.include_router(internal_threat_intel_router)
app.include_router(internal_incidents_router)
app.include_router(internal_engines_router)


@app.on_event("startup")
async def _backfill_admin_emails() -> None:
    emails = settings.admin_emails
    if not emails:
        return
    async with AsyncSessionLocal() as db:
        # admin_emails accounts are both is_admin AND internal super_admins.
        result = await db.execute(
            sa.update(User)
            .where(
                sa.func.lower(User.email).in_(emails),
                sa.or_(User.is_admin.is_(False), User.admin_role != "super_admin"),
            )
            .values(is_admin=True, admin_role="super_admin")
        )
        await db.commit()
        if result.rowcount:
            logging.getLogger(__name__).info(
                "Promoted %d user(s) to admin/super_admin via admin_emails",
                result.rowcount,
            )
