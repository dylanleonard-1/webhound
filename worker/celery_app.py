from __future__ import annotations

import os

from celery import Celery
from celery.schedules import crontab

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery = Celery(
    "webhound",
    broker=redis_url,
    backend=redis_url,
    include=[
        "worker.scan_tasks",
        "worker.report_tasks",
        "worker.monitoring_tasks",
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
    },
)
