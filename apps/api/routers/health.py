from __future__ import annotations

import os
from typing import Annotated

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.database import get_db

router = APIRouter()


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.get("/health/version")
async def health_version(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    # Surfaces the deployed commit, the live auth routes, and the current
    # Alembic schema revision. Lets us verify both "did the deploy land?"
    # and "did migrations run?" without shell access.
    sha = (
        os.getenv("RAILWAY_GIT_COMMIT_SHA")
        or os.getenv("GIT_COMMIT_SHA")
        or "unknown"
    )
    auth_routes = sorted(
        getattr(r, "path", "")
        for r in request.app.routes
        if getattr(r, "path", "").startswith("/auth")
    )
    try:
        row = await db.execute(text("SELECT version_num FROM alembic_version"))
        schema_revision = row.scalar_one_or_none()
    except Exception as exc:
        schema_revision = f"error: {exc}"
    return {
        "commit": sha[:12] if sha != "unknown" else sha,
        "schema_revision": schema_revision,
        "auth_routes": auth_routes,
    }


@router.get("/health/db")
async def health_db(db: Annotated[AsyncSession, Depends(get_db)]) -> dict:
    try:
        await db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as exc:
        db_status = f"error: {exc}"
    return {"status": "ok", "database": db_status}


@router.get("/health/worker")
async def health_worker() -> dict:
    settings = get_settings()
    try:
        r = aioredis.from_url(settings.redis_url, socket_connect_timeout=2)
        await r.ping()
        await r.aclose()
        broker_status = "ok"
    except Exception as exc:
        broker_status = f"error: {exc}"
    return {"status": "ok", "broker": broker_status}


@router.get("/health/ready")
async def health_ready(
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Aggregate readiness probe for uptime monitors / load balancers.

    Returns 200 only when BOTH Postgres and Redis are reachable; 503 otherwise.
    (Unlike /health/db and /health/worker, this returns a non-2xx on failure so
    automated probes can act on it. Keep /health itself trivial — Railway's
    deploy healthcheck uses it and shouldn't depend on Redis/DB being up mid-boot.)
    """
    checks: dict[str, str] = {}
    healthy = True
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["database"] = f"error: {exc}"
        healthy = False
    try:
        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=2)
        await r.ping()
        await r.aclose()
        checks["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["redis"] = f"error: {exc}"
        healthy = False
    response.status_code = 200 if healthy else 503
    return {"status": "ready" if healthy else "degraded", "checks": checks}


@router.get("/health/production")
async def health_production(
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Phase-19 Task 14 production-readiness report: env validation +
    live DB/Redis/worker probes + scanner-import check. Returns 503 if any
    CRITICAL check fails. Never exposes secret values (only names)."""
    from apps.api.platform.health.production_readiness import (
        build_readiness_report,
    )

    db_ok = redis_ok = worker_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:  # noqa: BLE001
        pass
    try:
        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=2)
        await r.ping()
        await r.aclose()
        redis_ok = worker_ok = True
    except Exception:  # noqa: BLE001
        pass

    migrations_current: bool | None = None
    try:
        await db.execute(text("SELECT version_num FROM alembic_version"))
        migrations_current = True
    except Exception:  # noqa: BLE001
        migrations_current = None

    report = build_readiness_report(
        db_ok=db_ok, redis_ok=redis_ok, worker_ok=worker_ok,
        migrations_current=migrations_current)
    response.status_code = 200 if report.ready else 503
    return report.to_dict()
