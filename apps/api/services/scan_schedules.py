from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_schedule import ScanSchedule
from apps.api.models.website import Website
from apps.api.schemas.scan_schedules import ScanScheduleCreate, ScanSchedulePatch


class WebsiteNotFoundError(Exception):
    pass


async def create_schedule(
    db: AsyncSession, data: ScanScheduleCreate, user_id: uuid.UUID, *, is_admin: bool = False
) -> ScanSchedule:
    if is_admin:
        website = await db.get(Website, data.website_id)
    else:
        website = await db.scalar(
            sa.select(Website).where(
                Website.id == data.website_id, Website.user_id == user_id
            )
        )
    if website is None:
        raise WebsiteNotFoundError(f"Website not found: {data.website_id}")

    schedule = ScanSchedule(
        user_id=user_id,
        website_id=data.website_id,
        profile=data.profile,
        frequency=data.frequency,
        is_enabled=data.is_enabled,
        use_latest_baseline=data.use_latest_baseline,
        save_baseline=data.save_baseline,
        next_run_at=data.next_run_at,
    )
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)
    return schedule


async def get_schedule(
    db: AsyncSession, schedule_id: uuid.UUID, user_id: uuid.UUID | None
) -> ScanSchedule | None:
    if user_id is None:
        return await db.get(ScanSchedule, schedule_id)
    return await db.scalar(
        sa.select(ScanSchedule).where(
            ScanSchedule.id == schedule_id, ScanSchedule.user_id == user_id
        )
    )


async def list_schedules(
    db: AsyncSession,
    user_id: uuid.UUID | None,
    *,
    website_id: uuid.UUID | None = None,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[ScanSchedule], int]:
    base = sa.select(ScanSchedule)
    count_base = sa.select(sa.func.count()).select_from(ScanSchedule)

    if user_id is not None:
        base = base.where(ScanSchedule.user_id == user_id)
        count_base = count_base.where(ScanSchedule.user_id == user_id)

    if website_id is not None:
        base = base.where(ScanSchedule.website_id == website_id)
        count_base = count_base.where(ScanSchedule.website_id == website_id)

    total: int = (await db.scalar(count_base)) or 0
    rows = await db.scalars(
        base.order_by(ScanSchedule.created_at.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), total


async def update_schedule(
    db: AsyncSession,
    schedule_id: uuid.UUID,
    data: ScanSchedulePatch,
    user_id: uuid.UUID | None,
) -> ScanSchedule | None:
    schedule = await get_schedule(db, schedule_id, user_id)
    if schedule is None:
        return None

    updates = data.model_dump(exclude_unset=True)
    for field, value in updates.items():
        setattr(schedule, field, value)

    await db.flush()
    await db.refresh(schedule)
    return schedule


async def delete_schedule(
    db: AsyncSession, schedule_id: uuid.UUID, user_id: uuid.UUID | None
) -> bool:
    schedule = await get_schedule(db, schedule_id, user_id)
    if schedule is None:
        return False
    await db.delete(schedule)
    await db.flush()
    return True


async def dispatch_due_schedules(
    db: AsyncSession, *, now: datetime | None = None
) -> list[dict]:
    """Enqueue scan jobs for all enabled schedules whose next_run_at is due.

    Returns a list of dicts suitable for celery dispatch:
        [{"job_id": str, "url": str, "profile": str}, …]

    Quota enforcement is intentionally NOT applied to scheduled runs — the
    user already committed to running these by setting up the schedule, and
    a quota-blocked scheduled run would silently disappear with no UI
    surface for the user to see. If we want to enforce quotas on
    scheduled runs in the future, do it here.
    """
    from apps.api.models.enums import ScanStatus

    if now is None:
        now = datetime.now(timezone.utc)

    schedules = await db.scalars(
        sa.select(ScanSchedule).where(
            ScanSchedule.is_enabled.is_(True),
            ScanSchedule.next_run_at <= now,
        )
    )
    due = list(schedules.all())

    dispatched: list[dict] = []
    for schedule in due:
        website = await db.get(Website, schedule.website_id)
        if website is None:
            # Orphaned schedule — disable it so it doesn't loop forever.
            schedule.is_enabled = False
            continue
        job = ScanJob(
            website_id=schedule.website_id,
            profile=schedule.profile,
            requested_url=website.url,
            status=ScanStatus.QUEUED,
            use_latest_baseline=schedule.use_latest_baseline,
            save_baseline=schedule.save_baseline,
        )
        db.add(job)
        await db.flush()
        dispatched.append({
            "job_id": str(job.id),
            "url": website.url,
            "profile": schedule.profile.value,
        })

        schedule.last_run_at = now
        schedule.next_run_at = _next_run(schedule.frequency, now)

    await db.flush()
    return dispatched


def _next_run(frequency: str, from_dt: datetime) -> datetime:
    """Compute next run time, handling month-end correctly.

    Monthly: if the source day doesn't exist in the target month
    (e.g. Jan 31 → Feb), clamps to the last day of the target month.
    """
    from calendar import monthrange
    from datetime import timedelta

    from apps.api.models.enums import ScheduleFrequency

    if frequency == ScheduleFrequency.DAILY:
        return from_dt + timedelta(days=1)
    if frequency == ScheduleFrequency.WEEKLY:
        return from_dt + timedelta(weeks=1)
    # Monthly
    target_month = from_dt.month + 1
    target_year = from_dt.year
    if target_month > 12:
        target_month = 1
        target_year += 1
    last_day = monthrange(target_year, target_month)[1]
    target_day = min(from_dt.day, last_day)
    return from_dt.replace(year=target_year, month=target_month, day=target_day)
