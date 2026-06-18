"""Scan schedule API and scheduler logic tests."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from apps.api.models.enums import ScheduleFrequency, ScanProfile, ScanStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_schedule import ScanSchedule
from apps.api.models.website import Website
from apps.api.services.scan_schedules import (
    WebsiteNotFoundError,
    create_schedule,
    delete_schedule,
    dispatch_due_schedules,
    get_schedule,
    list_schedules,
    update_schedule,
)

pytestmark = pytest.mark.anyio

_FUTURE = datetime.now(timezone.utc) + timedelta(hours=1)
_PAST = datetime.now(timezone.utc) - timedelta(minutes=5)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_website(db: AsyncSession, user_id: uuid.UUID, url: str = "https://example.com") -> Website:
    w = Website(url=url, hostname=url.split("//")[1], scheme="https", user_id=user_id)
    db.add(w)
    await db.flush()
    return w


async def _make_schedule(
    db: AsyncSession,
    user_id: uuid.UUID,
    website_id: uuid.UUID,
    *,
    frequency: ScheduleFrequency = ScheduleFrequency.DAILY,
    is_enabled: bool = True,
    next_run_at: datetime | None = None,
) -> ScanSchedule:
    schedule = ScanSchedule(
        user_id=user_id,
        website_id=website_id,
        profile=ScanProfile.STANDARD,
        frequency=frequency,
        is_enabled=is_enabled,
        use_latest_baseline=True,
        save_baseline=True,
        next_run_at=next_run_at or _FUTURE,
    )
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)
    return schedule


# ---------------------------------------------------------------------------
# API tests via HTTP client
# ---------------------------------------------------------------------------


async def test_create_schedule_success(client, db_engine, _test_user):
    r = await client.post("/websites", json={"url": "https://sched-test.com"})
    assert r.status_code == 201
    website_id = r.json()["id"]

    r = await client.post(
        "/scan-schedules",
        json={
            "website_id": website_id,
            "profile": "standard",
            "frequency": "daily",
            "next_run_at": _FUTURE.isoformat(),
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert body["website_id"] == website_id
    assert body["frequency"] == "daily"
    assert body["profile"] == "standard"
    assert body["is_enabled"] is True


async def test_create_schedule_auto_next_run_at_not_required(client, db_engine, _test_user):
    r = await client.post("/websites", json={"url": "https://auto-next.com"})
    website_id = r.json()["id"]

    r = await client.post(
        "/scan-schedules",
        json={"website_id": website_id, "profile": "quick", "frequency": "weekly", "next_run_at": _FUTURE.isoformat()},
    )
    assert r.status_code == 201


async def test_create_schedule_rejects_unowned_website(client, db_engine):
    from apps.api.database import Base
    from apps.api.models.user import User
    from apps.api.security import hash_password

    engine = db_engine
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as db:
        other = User(email="other@example.com", hashed_password=hash_password("pass1234"), is_active=True)
        db.add(other)
        await db.flush()
        w = Website(url="https://other-site.com", hostname="other-site.com", scheme="https", user_id=other.id)
        db.add(w)
        await db.commit()
        await db.refresh(w)
        website_id = str(w.id)

    r = await client.post(
        "/scan-schedules",
        json={"website_id": website_id, "profile": "standard", "frequency": "daily", "next_run_at": _FUTURE.isoformat()},
    )
    assert r.status_code == 404


async def test_create_schedule_invalid_frequency(client, db_engine, _test_user):
    r = await client.post("/websites", json={"url": "https://invalid-freq.com"})
    website_id = r.json()["id"]
    r = await client.post(
        "/scan-schedules",
        json={"website_id": website_id, "profile": "standard", "frequency": "hourly", "next_run_at": _FUTURE.isoformat()},
    )
    assert r.status_code == 422


async def test_create_schedule_invalid_profile(client, db_engine, _test_user):
    r = await client.post("/websites", json={"url": "https://invalid-profile.com"})
    website_id = r.json()["id"]
    r = await client.post(
        "/scan-schedules",
        json={"website_id": website_id, "profile": "ultra", "frequency": "daily", "next_run_at": _FUTURE.isoformat()},
    )
    assert r.status_code == 422


async def test_list_schedules_returns_own_only(client, db_engine, _test_user):
    r = await client.post("/websites", json={"url": "https://list-test.com"})
    website_id = r.json()["id"]
    await client.post(
        "/scan-schedules",
        json={"website_id": website_id, "frequency": "weekly", "next_run_at": _FUTURE.isoformat()},
    )
    r = await client.get("/scan-schedules")
    assert r.status_code == 200
    body = r.json()
    assert "items" in body
    assert all(item["user_id"] == str(_test_user.id) for item in body["items"])


async def test_list_schedules_filter_by_website(client, db_engine, _test_user):
    r1 = await client.post("/websites", json={"url": "https://ws-a.com"})
    r2 = await client.post("/websites", json={"url": "https://ws-b.com"})
    wid_a = r1.json()["id"]
    wid_b = r2.json()["id"]
    await client.post("/scan-schedules", json={"website_id": wid_a, "frequency": "daily", "next_run_at": _FUTURE.isoformat()})
    await client.post("/scan-schedules", json={"website_id": wid_b, "frequency": "daily", "next_run_at": _FUTURE.isoformat()})

    r = await client.get(f"/scan-schedules?website_id={wid_a}")
    body = r.json()
    assert all(item["website_id"] == wid_a for item in body["items"])


async def test_get_schedule_success(client, db_engine, _test_user):
    r = await client.post("/websites", json={"url": "https://get-sched.com"})
    website_id = r.json()["id"]
    r = await client.post("/scan-schedules", json={"website_id": website_id, "frequency": "monthly", "next_run_at": _FUTURE.isoformat()})
    schedule_id = r.json()["id"]

    r = await client.get(f"/scan-schedules/{schedule_id}")
    assert r.status_code == 200
    assert r.json()["id"] == schedule_id


async def test_get_schedule_not_found(client):
    r = await client.get(f"/scan-schedules/{uuid.uuid4()}")
    assert r.status_code == 404


async def test_patch_schedule_profile(client, db_engine, _test_user):
    r = await client.post("/websites", json={"url": "https://patch-sched.com"})
    website_id = r.json()["id"]
    r = await client.post("/scan-schedules", json={"website_id": website_id, "frequency": "daily", "next_run_at": _FUTURE.isoformat()})
    schedule_id = r.json()["id"]

    r = await client.patch(f"/scan-schedules/{schedule_id}", json={"profile": "deep"})
    assert r.status_code == 200
    assert r.json()["profile"] == "deep"


async def test_patch_schedule_disable(client, db_engine, _test_user):
    r = await client.post("/websites", json={"url": "https://disable-sched.com"})
    website_id = r.json()["id"]
    r = await client.post("/scan-schedules", json={"website_id": website_id, "frequency": "daily", "next_run_at": _FUTURE.isoformat()})
    schedule_id = r.json()["id"]

    r = await client.patch(f"/scan-schedules/{schedule_id}", json={"is_enabled": False})
    assert r.status_code == 200
    assert r.json()["is_enabled"] is False


async def test_patch_schedule_not_found(client):
    r = await client.patch(f"/scan-schedules/{uuid.uuid4()}", json={"is_enabled": False})
    assert r.status_code == 404


async def test_delete_schedule_success(client, db_engine, _test_user):
    r = await client.post("/websites", json={"url": "https://del-sched.com"})
    website_id = r.json()["id"]
    r = await client.post("/scan-schedules", json={"website_id": website_id, "frequency": "daily", "next_run_at": _FUTURE.isoformat()})
    schedule_id = r.json()["id"]

    r = await client.delete(f"/scan-schedules/{schedule_id}")
    assert r.status_code == 204

    r = await client.get(f"/scan-schedules/{schedule_id}")
    assert r.status_code == 404


async def test_delete_schedule_not_found(client):
    r = await client.delete(f"/scan-schedules/{uuid.uuid4()}")
    assert r.status_code == 404


async def test_schedule_requires_auth(db_engine):
    from apps.api.database import get_db
    from apps.api.main import app

    engine = db_engine
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _override():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/scan-schedules")
            assert r.status_code == 401
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Service-layer / scheduler logic tests
# ---------------------------------------------------------------------------


async def test_dispatch_creates_scan_job(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://dispatch-test.com")
        await _make_schedule(db, _test_user.id, w.id, next_run_at=_PAST)
        await db.commit()

    async with factory() as db:
        now = datetime.now(timezone.utc)
        dispatched = await dispatch_due_schedules(db, now=now)
        await db.commit()

    # dispatch_due_schedules returns celery-dispatch dicts: {"job_id", "url", "profile"}.
    assert len(dispatched) == 1

    async with factory() as db:
        job = await db.get(ScanJob, uuid.UUID(dispatched[0]["job_id"]))
        assert job is not None
        assert job.status == ScanStatus.QUEUED


async def test_dispatch_updates_last_run_at(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://last-run-test.com")
        s = await _make_schedule(db, _test_user.id, w.id, next_run_at=_PAST)
        schedule_id = s.id
        await db.commit()

    async with factory() as db:
        now = datetime.now(timezone.utc)
        await dispatch_due_schedules(db, now=now)
        await db.commit()

    async with factory() as db:
        updated = await db.get(ScanSchedule, schedule_id)
        assert updated.last_run_at is not None


async def test_dispatch_advances_next_run_at_daily(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://advance-daily.com")
        s = await _make_schedule(db, _test_user.id, w.id, frequency=ScheduleFrequency.DAILY, next_run_at=_PAST)
        schedule_id = s.id
        await db.commit()

    now = datetime.now(timezone.utc)
    async with factory() as db:
        await dispatch_due_schedules(db, now=now)
        await db.commit()

    async with factory() as db:
        updated = await db.get(ScanSchedule, schedule_id)
        next_run = updated.next_run_at.replace(tzinfo=timezone.utc) if updated.next_run_at.tzinfo is None else updated.next_run_at
        delta = next_run - now
        assert delta.total_seconds() > 0
        assert delta.days >= 0


async def test_dispatch_advances_next_run_at_weekly(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://advance-weekly.com")
        s = await _make_schedule(db, _test_user.id, w.id, frequency=ScheduleFrequency.WEEKLY, next_run_at=_PAST)
        schedule_id = s.id
        await db.commit()

    now = datetime.now(timezone.utc)
    async with factory() as db:
        await dispatch_due_schedules(db, now=now)
        await db.commit()

    async with factory() as db:
        updated = await db.get(ScanSchedule, schedule_id)
        next_run = updated.next_run_at.replace(tzinfo=timezone.utc) if updated.next_run_at.tzinfo is None else updated.next_run_at
        delta = next_run - now
        assert delta.days >= 6


async def test_dispatch_skips_disabled_schedules(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://disabled-sched.com")
        await _make_schedule(db, _test_user.id, w.id, is_enabled=False, next_run_at=_PAST)
        await db.commit()

    async with factory() as db:
        job_ids = await dispatch_due_schedules(db, now=datetime.now(timezone.utc))
        await db.commit()

    assert len(job_ids) == 0


async def test_dispatch_skips_future_schedules(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = await _make_website(db, _test_user.id, "https://future-sched.com")
        await _make_schedule(db, _test_user.id, w.id, next_run_at=_FUTURE)
        await db.commit()

    async with factory() as db:
        job_ids = await dispatch_due_schedules(db, now=datetime.now(timezone.utc))

    assert len(job_ids) == 0


async def test_service_create_rejects_unowned_website(db_engine, _test_user):
    from apps.api.models.user import User
    from apps.api.security import hash_password
    from apps.api.schemas.scan_schedules import ScanScheduleCreate

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        other = User(email="other2@example.com", hashed_password=hash_password("pass1234"), is_active=True)
        db.add(other)
        await db.flush()
        w = Website(url="https://other2.com", hostname="other2.com", scheme="https", user_id=other.id)
        db.add(w)
        await db.commit()
        await db.refresh(w)
        website_id = w.id

    async with factory() as db:
        data = ScanScheduleCreate(
            website_id=website_id,
            profile=ScanProfile.STANDARD,
            frequency=ScheduleFrequency.DAILY,
            next_run_at=_FUTURE,
        )
        with pytest.raises(WebsiteNotFoundError):
            await create_schedule(db, data, user_id=_test_user.id)


async def test_service_delete_returns_false_for_missing(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        result = await delete_schedule(db, uuid.uuid4(), _test_user.id)
    assert result is False


async def test_service_get_returns_none_for_other_user(db_engine, _test_user):
    from apps.api.models.user import User
    from apps.api.security import hash_password

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        other = User(email="other3@example.com", hashed_password=hash_password("pass1234"), is_active=True)
        db.add(other)
        await db.flush()
        w = await _make_website(db, other.id, "https://other3.com")
        s = await _make_schedule(db, other.id, w.id)
        schedule_id = s.id
        await db.commit()

    async with factory() as db:
        result = await get_schedule(db, schedule_id, _test_user.id)
    assert result is None
