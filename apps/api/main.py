from __future__ import annotations

from fastapi import FastAPI

from apps.api.config import get_settings
from apps.api.routers import auth, baselines, health, scan_jobs, scan_results, scan_schedules, websites

settings = get_settings()

app = FastAPI(
    title="WebHound API",
    version="0.1.0",
    docs_url="/docs" if settings.app_env != "production" else None,
    redoc_url=None,
)

app.include_router(health.router, tags=["health"])
app.include_router(auth.router)
app.include_router(websites.router)
app.include_router(scan_jobs.router)
app.include_router(scan_results.router)
app.include_router(baselines.router)
