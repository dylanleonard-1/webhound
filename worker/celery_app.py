from __future__ import annotations

import os

from celery import Celery
from celery.schedules import crontab

# Error monitoring — captures task failures, exhausted retries, and async
# crashes. No-op unless SENTRY_DSN is set and APP_ENV != development.
_sentry_dsn = os.getenv("SENTRY_DSN", "")
if _sentry_dsn and os.getenv("APP_ENV", "development") != "development":
    try:
        import sentry_sdk
        from sentry_sdk.integrations.celery import CeleryIntegration

        sentry_sdk.init(
            dsn=_sentry_dsn,
            environment=os.getenv("APP_ENV", "production"),
            integrations=[CeleryIntegration(monitor_beat_tasks=True)],
            traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0") or 0),
            send_default_pii=False,
        )
    except Exception:  # noqa: BLE001 — never let monitoring setup crash the worker
        pass

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery = Celery(
    "webhound",
    broker=redis_url,
    backend=redis_url,
    include=[
        "worker.scan_tasks",
        "worker.report_tasks",
        "worker.monitoring_tasks",
        "worker.alert_tasks",
    ],
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    # Beat schedule — runs every minute, finds due scan_schedules,
    # creates ScanJob rows, and enqueues run_scan for each.
    beat_schedule={
        "dispatch-scheduled-scans": {
            "task": "worker.monitoring_tasks.dispatch_scheduled_scans",
            "schedule": crontab(minute="*"),       # every minute
            "options": {"expires": 50},            # drop if not picked up in 50s
        },
        "worker-heartbeat": {
            "task": "worker.monitoring_tasks.heartbeat",
            "schedule": crontab(minute="*/5"),     # every 5 minutes
        },
        "evaluate-alerts": {
            "task": "worker.alert_tasks.evaluate_alerts",
            "schedule": crontab(minute="*/5"),     # SOC alert evaluation, every 5 min
        },
    },
)
