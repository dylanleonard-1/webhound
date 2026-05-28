"""SOC alert lifecycle: service dedup/auto-resolve and the /internal API."""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

import sqlalchemy as sa

from apps.api.database import get_db
from apps.api.main import app
from apps.api.models.alert import AlertComment
from apps.api.models.user import User
from apps.api.security import get_current_user, hash_password
from apps.api.services import alerts as alert_svc


async def _comments(db, alert_id):
    rows = await db.scalars(
        sa.select(AlertComment).where(AlertComment.alert_id == alert_id)
        .order_by(AlertComment.created_at)
    )
    return list(rows.all())

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Service layer — dedup, auto-resolve, recurrence re-open
# ---------------------------------------------------------------------------


async def test_upsert_creates_then_dedupes(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        a1, created1 = await alert_svc.upsert_alert(
            db, dedup_key="k1", source="scan_failure", severity="high", title="first",
        )
        assert created1 is True
        assert a1.occurrences == 1
        a2, created2 = await alert_svc.upsert_alert(
            db, dedup_key="k1", source="scan_failure", severity="critical", title="bumped",
        )
        assert created2 is False
        assert a2.id == a1.id
        assert a2.occurrences == 2
        assert a2.title == "bumped"          # latest title wins
        assert a2.severity == "critical"      # latest severity wins
        await db.commit()


async def test_auto_resolve_and_recurrence_reopens(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await alert_svc.upsert_alert(
            db, dedup_key="worker_down", source="worker_down",
            severity="critical", title="down",
        )
        assert await alert_svc.auto_resolve(db, "worker_down", note="recovered") is True
        # idempotent — second call finds nothing open.
        assert await alert_svc.auto_resolve(db, "worker_down", note="x") is False
        # condition recurs → re-open with a status_change comment.
        a, created = await alert_svc.upsert_alert(
            db, dedup_key="worker_down", source="worker_down",
            severity="critical", title="down again",
        )
        assert created is False
        assert a.status == "open"
        assert any("Re-opened" in c.body for c in await _comments(db, a.id))
        await db.commit()


async def test_acknowledge_then_resolve_records_timeline(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        alert, _ = await alert_svc.upsert_alert(
            db, dedup_key="k2", source="engine_reliability",
            severity="medium", title="t",
        )
        await alert_svc.acknowledge(db, alert, actor_email="me@x.com")
        await alert_svc.resolve(db, alert, actor_email="me@x.com")
        assert alert.status == "resolved"
        assert alert.acknowledged_by_email == "me@x.com"
        assert alert.resolved_by_email == "me@x.com"
        kinds = [c.kind for c in await _comments(db, alert.id)]
        assert "system" in kinds and kinds.count("status_change") == 2
        await db.commit()


# ---------------------------------------------------------------------------
# /internal/alerts API — RBAC happy path with an injected super_admin
# ---------------------------------------------------------------------------


@pytest.fixture
async def admin_client(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        admin = User(
            email="admin@webhoundsecurity.com",
            hashed_password=hash_password("testpassword123"),
            is_active=True, is_admin=True, admin_role="super_admin",
        )
        db.add(admin)
        await db.commit()
        await db.refresh(admin)

    async def _get_db():
        async with factory() as session:
            yield session

    async def _get_user():
        return admin

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_user] = _get_user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()


async def test_api_list_summary_detail_resolve(admin_client, db_engine):
    # Seed one alert directly through the service.
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        a, _ = await alert_svc.upsert_alert(
            db, dedup_key="api_k", source="scan_failure",
            severity="high", title="API alert", description="payload",
        )
        await db.commit()
        aid = str(a.id)

    r = await admin_client.get("/internal/alerts?status=open")
    assert r.status_code == 200
    assert r.json()["total"] >= 1

    s = await admin_client.get("/internal/alerts/summary")
    assert s.status_code == 200
    assert s.json()["open"] >= 1
    assert s.json()["by_severity"].get("high", 0) >= 1

    d = await admin_client.get(f"/internal/alerts/{aid}")
    assert d.status_code == 200
    body = d.json()
    assert body["title"] == "API alert"
    assert body["status"] == "open"

    rr = await admin_client.post(f"/internal/alerts/{aid}/resolve")
    assert rr.status_code == 200

    d2 = await admin_client.get(f"/internal/alerts/{aid}")
    assert d2.json()["status"] == "resolved"
    # The system + status_change timeline entries were recorded.
    assert any(c["kind"] == "status_change" for c in d2.json()["comments"])


async def test_api_comment_and_reject_empty(admin_client, db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        a, _ = await alert_svc.upsert_alert(
            db, dedup_key="cmt_k", source="engine_reliability",
            severity="medium", title="t",
        )
        await db.commit()
        aid = str(a.id)

    empty = await admin_client.post(f"/internal/alerts/{aid}/comment", json={"body": "   "})
    assert empty.status_code == 422

    ok = await admin_client.post(f"/internal/alerts/{aid}/comment", json={"body": "looking into this"})
    assert ok.status_code == 200

    d = await admin_client.get(f"/internal/alerts/{aid}")
    assert any(c["kind"] == "comment" and "looking into this" in c["body"]
               for c in d.json()["comments"])


async def test_api_forbidden_for_non_admin(db_engine):
    # Customer with admin_role=none — get 403 even though authenticated.
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        user = User(
            email="customer@x.com",
            hashed_password=hash_password("testpassword123"),
            is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    async def _get_db():
        async with factory() as session:
            yield session

    async def _get_user():
        return user

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_user] = _get_user
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/internal/alerts")
            assert r.status_code == 403
    finally:
        app.dependency_overrides.clear()
