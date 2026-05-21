from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import NotificationSeverity, NotificationType
from apps.api.models.notification import Notification


async def create_notification(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    type: NotificationType,
    severity: NotificationSeverity,
    title: str,
    message: str,
    website_id: uuid.UUID | None = None,
    scan_job_id: uuid.UUID | None = None,
    scan_result_id: uuid.UUID | None = None,
    metadata: dict | None = None,
) -> Notification:
    n = Notification(
        user_id=user_id,
        website_id=website_id,
        scan_job_id=scan_job_id,
        scan_result_id=scan_result_id,
        type=type,
        severity=severity,
        title=title,
        message=message,
        extra_metadata=metadata,
    )
    db.add(n)
    await db.flush()
    await db.refresh(n)
    return n


async def generate_scan_notifications(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    website_id: uuid.UUID,
    scan_job_id: uuid.UUID,
    scan_result_id: uuid.UUID | None,
    scanner_status: str,
    severity_breakdown: dict | None,
    scanner_metadata: dict | None,
    website_url: str = "",
) -> list[Notification]:
    """Create all applicable notifications for a completed or failed scan."""
    created: list[Notification] = []
    meta_base = {"website_url": website_url}

    if scanner_status == "failed":
        created.append(
            await create_notification(
                db,
                user_id=user_id,
                website_id=website_id,
                scan_job_id=scan_job_id,
                type=NotificationType.SCAN_FAILED,
                severity=NotificationSeverity.HIGH,
                title="Scan failed",
                message=f"The scan for {website_url or scan_job_id} failed.",
                metadata=meta_base,
            )
        )
        return created

    # scan_completed
    created.append(
        await create_notification(
            db,
            user_id=user_id,
            website_id=website_id,
            scan_job_id=scan_job_id,
            scan_result_id=scan_result_id,
            type=NotificationType.SCAN_COMPLETED,
            severity=NotificationSeverity.INFO,
            title="Scan completed",
            message=f"Scan completed for {website_url or scan_job_id}.",
            metadata=meta_base,
        )
    )

    if severity_breakdown:
        critical_count: int = severity_breakdown.get("critical", 0)
        high_count: int = severity_breakdown.get("high", 0)

        if critical_count > 0:
            created.append(
                await create_notification(
                    db,
                    user_id=user_id,
                    website_id=website_id,
                    scan_job_id=scan_job_id,
                    scan_result_id=scan_result_id,
                    type=NotificationType.CRITICAL_FINDING,
                    severity=NotificationSeverity.CRITICAL,
                    title=f"{critical_count} critical finding(s) detected",
                    message=(
                        f"{critical_count} critical severity finding(s) found"
                        f" during scan of {website_url}."
                    ),
                    metadata={**meta_base, "critical_count": critical_count},
                )
            )

        if high_count > 0:
            created.append(
                await create_notification(
                    db,
                    user_id=user_id,
                    website_id=website_id,
                    scan_job_id=scan_job_id,
                    scan_result_id=scan_result_id,
                    type=NotificationType.HIGH_RISK_FINDING,
                    severity=NotificationSeverity.HIGH,
                    title=f"{high_count} high-risk finding(s) detected",
                    message=(
                        f"{high_count} high severity finding(s) found"
                        f" during scan of {website_url}."
                    ),
                    metadata={**meta_base, "high_count": high_count},
                )
            )

    wade_anomaly_count: int = (scanner_metadata or {}).get("wade_anomaly_count", 0)
    if wade_anomaly_count > 0:
        wade_severity = (
            NotificationSeverity.HIGH
            if wade_anomaly_count >= 3
            else NotificationSeverity.MEDIUM
        )
        created.append(
            await create_notification(
                db,
                user_id=user_id,
                website_id=website_id,
                scan_job_id=scan_job_id,
                scan_result_id=scan_result_id,
                type=NotificationType.WADE_ANOMALY,
                severity=wade_severity,
                title=f"{wade_anomaly_count} WADE anomaly/anomalies detected",
                message=(
                    f"WADE baseline comparison found {wade_anomaly_count}"
                    f" anomaly/anomalies for {website_url}."
                ),
                metadata={**meta_base, "wade_anomaly_count": wade_anomaly_count},
            )
        )

    return created


async def get_notification(
    db: AsyncSession, notification_id: uuid.UUID, user_id: uuid.UUID
) -> Notification | None:
    return await db.scalar(
        sa.select(Notification).where(
            Notification.id == notification_id, Notification.user_id == user_id
        )
    )


async def list_notifications(
    db: AsyncSession,
    user_id: uuid.UUID,
    *,
    is_read: bool | None = None,
    type: NotificationType | None = None,
    severity: NotificationSeverity | None = None,
    website_id: uuid.UUID | None = None,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[Notification], int]:
    base = sa.select(Notification).where(Notification.user_id == user_id)
    count_base = (
        sa.select(sa.func.count())
        .select_from(Notification)
        .where(Notification.user_id == user_id)
    )

    if is_read is not None:
        base = base.where(Notification.is_read == is_read)
        count_base = count_base.where(Notification.is_read == is_read)
    if type is not None:
        base = base.where(Notification.type == type)
        count_base = count_base.where(Notification.type == type)
    if severity is not None:
        base = base.where(Notification.severity == severity)
        count_base = count_base.where(Notification.severity == severity)
    if website_id is not None:
        base = base.where(Notification.website_id == website_id)
        count_base = count_base.where(Notification.website_id == website_id)

    total: int = (await db.scalar(count_base)) or 0
    rows = await db.scalars(
        base.order_by(Notification.created_at.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), total


async def get_unread_count(db: AsyncSession, user_id: uuid.UUID) -> int:
    result = await db.scalar(
        sa.select(sa.func.count())
        .select_from(Notification)
        .where(Notification.user_id == user_id, Notification.is_read.is_(False))
    )
    return result or 0


async def mark_read(
    db: AsyncSession, notification_id: uuid.UUID, user_id: uuid.UUID
) -> Notification | None:
    n = await get_notification(db, notification_id, user_id)
    if n is None:
        return None
    if not n.is_read:
        n.is_read = True
        n.read_at = datetime.now(timezone.utc)
        await db.flush()
        await db.refresh(n)
    return n


async def mark_all_read(db: AsyncSession, user_id: uuid.UUID) -> int:
    now = datetime.now(timezone.utc)
    result = await db.execute(
        sa.update(Notification)
        .where(Notification.user_id == user_id, Notification.is_read.is_(False))
        .values(is_read=True, read_at=now)
    )
    return result.rowcount


async def delete_notification(
    db: AsyncSession, notification_id: uuid.UUID, user_id: uuid.UUID
) -> bool:
    n = await get_notification(db, notification_id, user_id)
    if n is None:
        return False
    await db.delete(n)
    await db.flush()
    return True
