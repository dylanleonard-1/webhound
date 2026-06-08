# WebHound — worker/notification_tasks.py
# FIX 6 — Celery task that delivers a customer notification by email.
#
# Retries with exponential backoff are owned here (Celery self.retry); the
# delivery policy + status bookkeeping live in
# apps.api.services.notification_delivery. Feature-flagged: enqueued only when
# NOTIFICATIONS_ENABLED=1 and a provider is configured, so by default this
# task never runs.

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from worker._db import get_async_db_url
from worker.celery_app import celery

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3


@celery.task(
    name="worker.notification_tasks.deliver_notification_email",
    bind=True,
    max_retries=_MAX_RETRIES,
)
def deliver_notification_email(self, notification_id: str, to_email: str) -> dict:
    """Deliver one notification by email, retrying with backoff on transient
    failure. On the final attempt the notification is marked ``failed``."""
    from apps.api.services.notification_delivery import (
        RetryableDeliveryError,
        attempt_delivery,
    )

    is_final = self.request.retries >= _MAX_RETRIES
    try:
        status = asyncio.run(
            _run(notification_id, to_email, is_final_attempt=is_final)
        )
        return {"notification_id": notification_id, "status": status}
    except RetryableDeliveryError as exc:
        # 30s, 60s, 120s backoff.
        countdown = 30 * (2 ** self.request.retries)
        logger.info(
            "notification email retry %d/%d for %s in %ds",
            self.request.retries + 1, _MAX_RETRIES, notification_id, countdown,
        )
        raise self.retry(exc=exc, countdown=countdown)
    except Exception:
        logger.exception("notification delivery task crashed for %s", notification_id)
        raise


async def _run(
    notification_id: str, to_email: str, *, is_final_attempt: bool,
    _session_factory: Any = None,
) -> str:
    import apps.api.models  # noqa: F401 — register models

    from apps.api.services.notification_delivery import attempt_delivery

    own_engine = None
    if _session_factory is None:
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        own_engine = create_async_engine(get_async_db_url())
        factory = async_sessionmaker(own_engine, expire_on_commit=False)
    else:
        factory = _session_factory

    try:
        async with factory() as db:
            status = await attempt_delivery(
                db, uuid.UUID(notification_id), to_email,
                is_final_attempt=is_final_attempt,
            )
            await db.commit()
            return status
    finally:
        if own_engine is not None:
            await own_engine.dispose()
