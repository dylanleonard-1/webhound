from __future__ import annotations

import logging

from worker.celery_app import celery

logger = logging.getLogger(__name__)


@celery.task(name="worker.report_tasks.generate_report")
def generate_report(scan_id: str) -> dict:
    """Placeholder — will generate reports once scan results exist."""
    logger.info("report generation queued: scan_id=%s", scan_id)
    return {"scan_id": scan_id, "status": "queued"}
