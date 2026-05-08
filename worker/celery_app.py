from __future__ import annotations

import os

from celery import Celery

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
)
