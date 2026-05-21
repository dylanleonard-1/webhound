"""Notification API and service tests."""
from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from apps.api.models.enums import NotificationSeverity, NotificationType
from apps.api.models.notification import Notification
from apps.api.models.website import Website
from apps.api.services.notifications import (
    create_notification,
    delete_notification,
    generate_scan_notifications,
    get_unread_count,
    list_notifications,
    mark_all_read,
    mark_read,
)

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_website(db: AsyncSession, user_id: uuid.UUID, url: str = "https://example.com") -> Website:
    w = Website(url=url, hostname=url.split("//")[1], scheme="https", user_id=user_id)
    db.add(w)
    await db.flush()
    return w


async def _create_notif(
    db: AsyncSession,
    user_id: uuid.UUID,
    *,
    type: NotificationType = NotificationType.SCAN_COMPLETED,
    severity: NotificationSeverity = NotificationSeverity.INFO,
    is_read: bool = False,
    website_id: uuid.UUID | None = None,
) -> Notification:
    n = await create_notification(
        db,
        user_id=user_id,
        type=type,
        severity=severity,
        title="Test notification",
        message="Test message.",
        website_id=website_id,
    )
    if is_read:
        n.is_read = True
        await db.flush()
    return n


# ---------------------------------------------------------------------------
# generate_scan_notifications — service-layer tests
# ---------------------------------------------------------------------------


async def test_generate_scan_completed_creates_info_notification(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id)
        job_id = uuid.uuid4()
        notifications = await generate_scan_notifications(
            db,
            user_id=_test_user.id,
            website_id=w.id,
            scan_job_id=job_id,
            scan_result_id=None,
            scanner_status="completed",
            severity_breakdown={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            scanner_metadata={},
            website_url=w.url,
        )
        await db.commit()

    types = [n.type for n in notifications]
    assert NotificationType.SCAN_COMPLETED in types
    completed = next(n for n in notifications if n.type == NotificationType.SCAN_COMPLETED)
    assert completed.severity == NotificationSeverity.INFO


async def test_generate_scan_failed_creates_high_notification(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://fail.example.com")
        notifications = await generate_scan_notifications(
            db,
            user_id=_test_user.id,
            website_id=w.id,
            scan_job_id=uuid.uuid4(),
            scan_result_id=None,
            scanner_status="failed",
            severity_breakdown=None,
            scanner_metadata=None,
            website_url=w.url,
        )
        await db.commit()

    assert len(notifications) == 1
    assert notifications[0].type == NotificationType.SCAN_FAILED
    assert notifications[0].severity == NotificationSeverity.HIGH


async def test_generate_critical_finding_notification(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://critical.example.com")
        notifications = await generate_scan_notifications(
            db,
            user_id=_test_user.id,
            website_id=w.id,
            scan_job_id=uuid.uuid4(),
            scan_result_id=uuid.uuid4(),
            scanner_status="completed",
            severity_breakdown={"critical": 2, "high": 0, "medium": 0, "low": 0, "info": 0},
            scanner_metadata={},
            website_url=w.url,
        )
        await db.commit()

    types = [n.type for n in notifications]
    assert NotificationType.CRITICAL_FINDING in types
    critical = next(n for n in notifications if n.type == NotificationType.CRITICAL_FINDING)
    assert critical.severity == NotificationSeverity.CRITICAL
    assert critical.extra_metadata["critical_count"] == 2


async def test_generate_high_finding_notification(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://high.example.com")
        notifications = await generate_scan_notifications(
            db,
            user_id=_test_user.id,
            website_id=w.id,
            scan_job_id=uuid.uuid4(),
            scan_result_id=uuid.uuid4(),
            scanner_status="completed",
            severity_breakdown={"critical": 0, "high": 3, "medium": 0, "low": 0, "info": 0},
            scanner_metadata={},
            website_url=w.url,
        )
        await db.commit()

    types = [n.type for n in notifications]
    assert NotificationType.HIGH_RISK_FINDING in types
    high = next(n for n in notifications if n.type == NotificationType.HIGH_RISK_FINDING)
    assert high.severity == NotificationSeverity.HIGH


async def test_generate_wade_anomaly_notification_high(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://wade.example.com")
        notifications = await generate_scan_notifications(
            db,
            user_id=_test_user.id,
            website_id=w.id,
            scan_job_id=uuid.uuid4(),
            scan_result_id=uuid.uuid4(),
            scanner_status="completed",
            severity_breakdown={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            scanner_metadata={"wade_anomaly_count": 5},
            website_url=w.url,
        )
        await db.commit()

    types = [n.type for n in notifications]
    assert NotificationType.WADE_ANOMALY in types
    wade = next(n for n in notifications if n.type == NotificationType.WADE_ANOMALY)
    assert wade.severity == NotificationSeverity.HIGH
    assert wade.extra_metadata["wade_anomaly_count"] == 5


async def test_generate_wade_anomaly_notification_medium(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://wade2.example.com")
        notifications = await generate_scan_notifications(
            db,
            user_id=_test_user.id,
            website_id=w.id,
            scan_job_id=uuid.uuid4(),
            scan_result_id=uuid.uuid4(),
            scanner_status="completed",
            severity_breakdown={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            scanner_metadata={"wade_anomaly_count": 1},
            website_url=w.url,
        )
        await db.commit()

    wade = next(n for n in notifications if n.type == NotificationType.WADE_ANOMALY)
    assert wade.severity == NotificationSeverity.MEDIUM


async def test_no_wade_notification_when_count_zero(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://nowade.example.com")
        notifications = await generate_scan_notifications(
            db,
            user_id=_test_user.id,
            website_id=w.id,
            scan_job_id=uuid.uuid4(),
            scan_result_id=uuid.uuid4(),
            scanner_status="completed",
            severity_breakdown={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            scanner_metadata={"wade_anomaly_count": 0},
            website_url=w.url,
        )

    types = [n.type for n in notifications]
    assert NotificationType.WADE_ANOMALY not in types


async def test_failed_scan_skips_finding_notifications(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://failonly.example.com")
        notifications = await generate_scan_notifications(
            db,
            user_id=_test_user.id,
            website_id=w.id,
            scan_job_id=uuid.uuid4(),
            scan_result_id=None,
            scanner_status="failed",
            severity_breakdown={"critical": 5, "high": 10},
            scanner_metadata={"wade_anomaly_count": 3},
            website_url=w.url,
        )

    assert len(notifications) == 1
    assert notifications[0].type == NotificationType.SCAN_FAILED


# ---------------------------------------------------------------------------
# API tests via HTTP client
# ---------------------------------------------------------------------------


async def test_list_notifications_empty(client):
    r = await client.get("/notifications")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["items"] == []


async def test_list_notifications_returns_own_only(client, db_engine, _test_user):
    from apps.api.models.user import User
    from apps.api.security import hash_password

    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async with factory() as db:
        other = User(email="other-notif@example.com", hashed_password=hash_password("pass1234"), is_active=True)
        db.add(other)
        await db.flush()
        # Create notification for other user
        await _create_notif(db, other.id)
        # Create notification for test user
        await _create_notif(db, _test_user.id)
        await db.commit()

    r = await client.get("/notifications")
    body = r.json()
    assert body["total"] == 1
    assert all(item["user_id"] == str(_test_user.id) for item in body["items"])


async def test_list_notifications_filter_is_read(client, db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await _create_notif(db, _test_user.id, is_read=False)
        await _create_notif(db, _test_user.id, is_read=True)
        await db.commit()

    r = await client.get("/notifications?is_read=false")
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["is_read"] is False

    r = await client.get("/notifications?is_read=true")
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["is_read"] is True


async def test_list_notifications_filter_type(client, db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await _create_notif(db, _test_user.id, type=NotificationType.SCAN_COMPLETED)
        await _create_notif(db, _test_user.id, type=NotificationType.SCAN_FAILED)
        await db.commit()

    r = await client.get("/notifications?type=scan_failed")
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["type"] == "scan_failed"


async def test_unread_count(client, db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await _create_notif(db, _test_user.id, is_read=False)
        await _create_notif(db, _test_user.id, is_read=False)
        await _create_notif(db, _test_user.id, is_read=True)
        await db.commit()

    r = await client.get("/notifications/unread-count")
    assert r.status_code == 200
    assert r.json()["count"] == 2


async def test_mark_notification_read(client, db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        n = await _create_notif(db, _test_user.id, is_read=False)
        notif_id = str(n.id)
        await db.commit()

    r = await client.patch(f"/notifications/{notif_id}/read")
    assert r.status_code == 200
    body = r.json()
    assert body["is_read"] is True
    assert body["read_at"] is not None


async def test_mark_notification_read_not_found(client):
    r = await client.patch(f"/notifications/{uuid.uuid4()}/read")
    assert r.status_code == 404


async def test_mark_all_read(client, db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await _create_notif(db, _test_user.id, is_read=False)
        await _create_notif(db, _test_user.id, is_read=False)
        await db.commit()

    r = await client.patch("/notifications/read-all")
    assert r.status_code == 200
    assert r.json()["count"] == 0

    r = await client.get("/notifications/unread-count")
    assert r.json()["count"] == 0


async def test_delete_notification_success(client, db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        n = await _create_notif(db, _test_user.id)
        notif_id = str(n.id)
        await db.commit()

    r = await client.delete(f"/notifications/{notif_id}")
    assert r.status_code == 204

    r = await client.get(f"/notifications/{notif_id}")
    assert r.status_code == 404


async def test_delete_notification_not_found(client):
    r = await client.delete(f"/notifications/{uuid.uuid4()}")
    assert r.status_code == 404


async def test_user_cannot_access_other_users_notification(client, db_engine, _test_user):
    from apps.api.models.user import User
    from apps.api.security import hash_password

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        other = User(email="other2-notif@example.com", hashed_password=hash_password("pass1234"), is_active=True)
        db.add(other)
        await db.flush()
        n = await _create_notif(db, other.id)
        notif_id = str(n.id)
        await db.commit()

    r = await client.get(f"/notifications/{notif_id}")
    assert r.status_code == 404

    r = await client.delete(f"/notifications/{notif_id}")
    assert r.status_code == 404

    r = await client.patch(f"/notifications/{notif_id}/read")
    assert r.status_code == 404


async def test_notifications_require_auth(db_engine):
    from apps.api.database import get_db
    from apps.api.main import app

    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def _override():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            assert (await c.get("/notifications")).status_code == 401
            assert (await c.get("/notifications/unread-count")).status_code == 401
            assert (await c.patch("/notifications/read-all")).status_code == 401
    finally:
        app.dependency_overrides.clear()
