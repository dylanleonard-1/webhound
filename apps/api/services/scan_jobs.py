from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.models.enums import ScanStatus, VerificationStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.website import Website
from apps.api.schemas.scan_jobs import ScanJobCreate, ScanJobStatusUpdate


class WebsiteNotFoundError(Exception):
    pass


class WebsiteNotVerifiedError(Exception):
    pass


class InvalidStatusTransitionError(Exception):
    def __init__(self, from_status: ScanStatus, to_status: ScanStatus) -> None:
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(
            f"Cannot transition scan job from '{from_status.value}' to '{to_status.value}'"
        )


# Terminal states — no further transitions allowed
_TERMINAL = frozenset({ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED})

# Valid outgoing transitions for each status
_VALID_TRANSITIONS: dict[ScanStatus, frozenset[ScanStatus]] = {
    ScanStatus.QUEUED: frozenset({ScanStatus.RUNNING, ScanStatus.CANCELLED}),
    ScanStatus.RUNNING: frozenset(
        {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}
    ),
    ScanStatus.COMPLETED: frozenset(),
    ScanStatus.FAILED: frozenset(),
    ScanStatus.CANCELLED: frozenset(),
}

_CANCELLABLE = frozenset({ScanStatus.QUEUED, ScanStatus.RUNNING})


async def create_scan_job(
    db: AsyncSession,
    data: ScanJobCreate,
    user_id: uuid.UUID | None = None,
    *,
    is_admin: bool = False,
) -> ScanJob:
    if is_admin or user_id is None:
        website = await db.get(Website, data.website_id)
    else:
        website = await db.scalar(
            sa.select(Website).where(
                Website.id == data.website_id, Website.user_id == user_id
            )
        )
    if website is None:
        raise WebsiteNotFoundError(f"Website not found: {data.website_id}")

    settings = get_settings()
    if (
        website.verification_status != VerificationStatus.VERIFIED
        and not settings.dev_allow_unverified_scans
        and not is_admin
    ):
        raise WebsiteNotVerifiedError(
            "Website must be verified before scanning. "
            "Complete domain verification or set DEV_ALLOW_UNVERIFIED_SCANS=true in development."
        )

    job = ScanJob(
        website_id=data.website_id,
        profile=data.profile,
        requested_url=website.url,
        status=ScanStatus.QUEUED,
        use_latest_baseline=data.use_latest_baseline,
        save_baseline=data.save_baseline,
        # Phase-4 invariant: a scan job inherits its parent website's
        # tenancy. Backfill migration 0028 ensures every existing
        # website.org_id is populated where appropriate; this line
        # ensures every *new* scan job lands with the same org_id
        # without needing a separate maintenance script.
        org_id=website.org_id,
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)
    return job


async def get_scan_job(
    db: AsyncSession, job_id: uuid.UUID, user_id: uuid.UUID | None = None
) -> ScanJob | None:
    if user_id is None:
        return await db.get(ScanJob, job_id)
    return await db.scalar(
        sa.select(ScanJob)
        .join(Website, ScanJob.website_id == Website.id)
        .where(ScanJob.id == job_id, Website.user_id == user_id)
    )


async def list_scan_jobs(
    db: AsyncSession,
    *,
    limit: int = 20,
    offset: int = 0,
    website_id: uuid.UUID | None = None,
    status: ScanStatus | None = None,
    profile: str | None = None,
    user_id: uuid.UUID | None = None,
    active_org_id: uuid.UUID | None = None,
) -> tuple[list[ScanJob], int]:
    from apps.api.services.tenant import apply_org_scope

    base = sa.select(ScanJob)
    count_base = sa.select(sa.func.count()).select_from(ScanJob)

    if user_id is not None or website_id is not None:
        base = base.join(Website, ScanJob.website_id == Website.id)
        count_base = count_base.join(Website, ScanJob.website_id == Website.id)

    if user_id is not None:
        base = base.where(Website.user_id == user_id)
        count_base = count_base.where(Website.user_id == user_id)

    if website_id is not None:
        base = base.where(ScanJob.website_id == website_id)
        count_base = count_base.where(ScanJob.website_id == website_id)

    if status is not None:
        base = base.where(ScanJob.status == status)
        count_base = count_base.where(ScanJob.status == status)
    if profile is not None:
        base = base.where(ScanJob.profile == profile)
        count_base = count_base.where(ScanJob.profile == profile)

    # Phase-4 tenancy: scope to the caller's active org when supplied.
    # Legacy NULL rows always pass — see services/tenant.py.
    base = apply_org_scope(base, ScanJob.org_id, active_org_id)
    count_base = apply_org_scope(count_base, ScanJob.org_id, active_org_id)

    total: int = (await db.scalar(count_base)) or 0
    rows = await db.scalars(
        base.order_by(ScanJob.created_at.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), total


async def cancel_scan_job(
    db: AsyncSession, job_id: uuid.UUID, user_id: uuid.UUID | None = None
) -> ScanJob | None:
    job = await get_scan_job(db, job_id, user_id)
    if job is None:
        return None
    if job.status not in _CANCELLABLE:
        raise InvalidStatusTransitionError(job.status, ScanStatus.CANCELLED)
    return await _apply_transition(db, job, ScanStatus.CANCELLED)


async def update_scan_job_status(
    db: AsyncSession,
    job_id: uuid.UUID,
    data: ScanJobStatusUpdate,
    user_id: uuid.UUID | None = None,
) -> ScanJob | None:
    job = await get_scan_job(db, job_id, user_id)
    if job is None:
        return None
    allowed = _VALID_TRANSITIONS[job.status]
    if data.status not in allowed:
        raise InvalidStatusTransitionError(job.status, data.status)
    return await _apply_transition(
        db, job, data.status, error_message=data.error_message
    )


async def _apply_transition(
    db: AsyncSession,
    job: ScanJob,
    new_status: ScanStatus,
    *,
    error_message: str | None = None,
) -> ScanJob:
    now = datetime.now(timezone.utc)
    job.status = new_status
    if new_status == ScanStatus.RUNNING and job.started_at is None:
        job.started_at = now
    if new_status in _TERMINAL:
        job.completed_at = now
    if error_message is not None:
        job.error_message = error_message
    await db.flush()
    await db.refresh(job)
    return job
