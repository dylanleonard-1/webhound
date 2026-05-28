from __future__ import annotations

import asyncio
import logging

from worker._db import get_async_db_url
from worker.celery_app import celery

logger = logging.getLogger(__name__)


@celery.task(name="worker.fraud_tasks.evaluate_abuse")
def evaluate_abuse() -> dict:
    """Walk candidate users, score them, upsert/dismiss flags. Fires every 15m."""
    try:
        return asyncio.run(_evaluate())
    except Exception:
        logger.exception("evaluate_abuse failed")
        raise


async def _evaluate() -> dict:
    import apps.api.models  # noqa: F401 — register models
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from apps.api.models.abuse import AbuseFlag
    from apps.api.models.user import User
    from apps.api.services import fraud as fraud_svc

    counts = {"opened": 0, "updated": 0, "dismissed": 0, "evaluated": 0}
    engine = create_async_engine(get_async_db_url())
    factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        async with factory() as db:
            candidates = await fraud_svc.find_candidates(db)
            counts["evaluated"] = len(candidates)

            # Plus every user with an existing pending flag — so cleared
            # conditions auto-resolve even if the user no longer matches
            # any candidate query.
            pending_user_ids = await db.scalars(
                select(AbuseFlag.user_id).where(
                    AbuseFlag.status == "pending",
                    AbuseFlag.user_id.is_not(None),
                )
            )
            all_ids = set(candidates) | {uid for uid in pending_user_ids.all() if uid}

            for uid in all_ids:
                user = await db.get(User, uid)
                if user is None:
                    continue
                score = await fraud_svc.evaluate_user(db, uid, email=user.email)
                if score["score"] >= fraud_svc.FLAG_THRESHOLD:
                    _, created = await fraud_svc.upsert_flag(
                        db, user_id=uid, ip_address=None,
                        score=score["score"], severity=score["severity"],
                        reasons=score["reasons"], detail=score["detail"],
                    )
                    counts["opened" if created else "updated"] += 1
                else:
                    # Clear any leftover pending flag for a user that's now clean.
                    flag = await db.scalar(
                        select(AbuseFlag).where(
                            AbuseFlag.dedup_key == f"user:{uid}",
                            AbuseFlag.status == "pending",
                        )
                    )
                    if flag is not None:
                        if await fraud_svc.auto_resolve_if_cleared(db, flag, new_score=score["score"]):
                            counts["dismissed"] += 1

            await db.commit()
    finally:
        await engine.dispose()

    if any(counts.values()):
        logger.info("abuse evaluation: %s", counts)
    return counts
