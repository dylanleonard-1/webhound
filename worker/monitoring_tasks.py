from __future__ import annotations

import logging

from worker.celery_app import celery

logger = logging.getLogger(__name__)


@celery.task(name="worker.monitoring_tasks.heartbeat")
def heartbeat() -> dict:
    """Periodic liveness ping — scheduled via celery beat in a future phase."""
    logger.debug("worker heartbeat")
    return {"status": "alive"}
