"""Support ticket lifecycle + RBAC."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.database import get_db
from apps.api.main import app
from apps.api.models.enums import PlanTier
from apps.api.models.support_ticket import SupportTicket
from apps.api.models.user import User
from apps.api.security import get_current_user, hash_password
from apps.api.services import support as support_svc

pytestmark = pytest.mark.anyio


async def _user(db, *, email="cust@x.com", plan=PlanTier.FREE) -> User:
    u = User(email=email, hashed_password=hash_password("testpassword123"),
             is_active=True, plan=plan)
    db.add(u); await db.commit(); await db.refresh(u)
    return u


# ---------------------------------------------------------------------------
# Service: creation + SLA + lifecycle
# ---------------------------------------------------------------------------


async def test_create_sets_sla_from_plan_tier(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        free = await _user(db, email="free@x.com", plan=PlanTier.FREE)
        shield = await _user(db, email="sh@x.com", plan=PlanTier.SHIELD)
        before = datetime.now(timezone.utc)

        t_free = await support_svc.create_ticket(db, user=free, subject="x")
        t_sh = await support_svc.create_ticket(db, user=shield, subject="y")
        await db.commit()

        assert t_free.sla_due_at is not None and t_sh.sla_due_at is not None
        # Shield (24h) is sooner than free (7d).
        assert t_sh.sla_due_at < t_free.sla_due_at
        # Sanity: free is at least ~6 days out (allow clock jitter).
        assert (t_free.sla_due_at - before) > timedelta(days=6, hours=20)
        # Numbers increment.
        assert t_sh.number == t_free.number + 1


async def test_create_validates_inputs(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        with pytest.raises(ValueError):
            await support_svc.create_ticket(db, user=u, subject="x", category="bogus")
        with pytest.raises(ValueError):
            await support_svc.create_ticket(db, user=u, subject="x", priority="omg")


async def test_status_and_priority_changes_record_timeline(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        t = await support_svc.create_ticket(db, user=u, subject="x")
        await support_svc.change_status(db, t, "in_progress", actor_email="me@x.com")
        await support_svc.change_priority(db, t, "high", actor_email="me@x.com")
        await support_svc.change_status(db, t, "resolved", actor_email="me@x.com")
        await db.commit()

        events = await support_svc.list_events(db, t.id)
        kinds = [e["kind"] for e in events]
        assert kinds.count("status_change") == 2
        assert "priority_change" in kinds
        assert t.resolved_at is not None


async def test_reopening_clears_terminal_timestamps(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        t = await support_svc.create_ticket(db, user=u, subject="x")
        await support_svc.change_status(db, t, "resolved", actor_email="me@x.com")
        await db.commit()
        assert t.resolved_at is not None

        await support_svc.change_status(db, t, "in_progress", actor_email="me@x.com")
        await db.commit()
        assert t.resolved_at is None
        assert t.closed_at is None


async def test_first_public_comment_stamps_first_response_at(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        t = await support_svc.create_ticket(db, user=u, subject="x")
        assert t.first_response_at is None
        # Internal note doesn't count.
        await support_svc.add_event(db, t, kind="comment", body="checking",
                                    visibility="internal", author_email="me@x.com")
        assert t.first_response_at is None
        # Public comment does.
        await support_svc.add_event(db, t, kind="comment", body="hi customer",
                                    visibility="public", author_email="me@x.com")
        await db.commit()
        assert t.first_response_at is not None


async def test_is_breached_only_for_active_tickets(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db, plan=PlanTier.ENTERPRISE)
        t = await support_svc.create_ticket(db, user=u, subject="x")
        # Pull SLA into the past — simulates a breach without waiting hours.
        t.sla_due_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await db.commit()
        await db.refresh(t)
        assert support_svc.is_breached(t) is True

        await support_svc.change_status(db, t, "resolved", actor_email="me@x.com")
        await db.commit()
        await db.refresh(t)
        assert support_svc.is_breached(t) is False


async def test_search_breached_only_filters(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db, plan=PlanTier.ENTERPRISE)
        fresh = await support_svc.create_ticket(db, user=u, subject="fresh")
        breached = await support_svc.create_ticket(db, user=u, subject="bad")
        breached.sla_due_at = datetime.now(timezone.utc) - timedelta(hours=2)
        await db.commit()

        items, total = await support_svc.search(db, breached_only=True)
        ids = {t.id for t in items}
        assert breached.id in ids
        assert fresh.id not in ids
        assert total == 1


# ---------------------------------------------------------------------------
# API + RBAC
# ---------------------------------------------------------------------------


@pytest.fixture
async def staff_client(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        actor = User(
            email="ops@webhoundsecurity.com",
            hashed_password=hash_password("testpassword123"),
            is_active=True, is_admin=True, admin_role="super_admin",
        )
        target = User(
            email="cust@x.com",
            hashed_password=hash_password("testpassword123"),
            is_active=True, plan=PlanTier.PRO,
        )
        db.add_all([actor, target])
        await db.commit()
        await db.refresh(actor)
        await db.refresh(target)

    role = {"value": "super_admin"}

    async def _get_db():
        async with factory() as s:
            yield s

    async def _get_user():
        actor.admin_role = role["value"]
        return actor

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_user] = _get_user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c, target.id, role
    app.dependency_overrides.clear()


async def test_api_create_list_summary_detail(staff_client):
    client, target_id, _role = staff_client

    r = await client.post("/internal/tickets", json={
        "user_id": str(target_id), "subject": "Fix XSS on /search", "priority": "high",
    })
    assert r.status_code == 200
    ticket_id = r.json()["id"]

    lst = await client.get("/internal/tickets?status=open")
    assert lst.status_code == 200
    assert lst.json()["total"] == 1

    s = await client.get("/internal/tickets/summary")
    assert s.json()["open"] == 1

    d = await client.get(f"/internal/tickets/{ticket_id}")
    assert d.status_code == 200
    assert d.json()["subject"] == "Fix XSS on /search"
    # The system "ticket opened" event lands as an internal-visibility entry.
    assert any(e["kind"] == "system" for e in d.json()["events"])


async def test_api_full_lifecycle(staff_client):
    client, target_id, _role = staff_client
    r = await client.post("/internal/tickets", json={"user_id": str(target_id), "subject": "Y"})
    tid = r.json()["id"]

    await client.post(f"/internal/tickets/{tid}/status", json={"status": "in_progress"})
    await client.post(f"/internal/tickets/{tid}/priority", json={"priority": "urgent"})
    await client.post(f"/internal/tickets/{tid}/comment", json={"body": "looking into it", "visibility": "public"})
    await client.post(f"/internal/tickets/{tid}/comment", json={"body": "tech note", "visibility": "internal"})
    await client.post(f"/internal/tickets/{tid}/status", json={"status": "resolved"})

    d = (await client.get(f"/internal/tickets/{tid}")).json()
    assert d["status"] == "resolved"
    assert d["priority"] == "urgent"
    assert d["first_response_at"] is not None
    # Both comment visibilities are present.
    visibilities = {e["visibility"] for e in d["events"] if e["kind"] == "comment"}
    assert visibilities == {"public", "internal"}


async def test_api_rejects_invalid_inputs(staff_client):
    client, target_id, _role = staff_client
    r = await client.post("/internal/tickets", json={"user_id": str(target_id), "subject": "X", "category": "bogus"})
    assert r.status_code == 422
    # Missing source_scan blocks verify-rescan.
    r2 = await client.post("/internal/tickets", json={"user_id": str(target_id), "subject": "X"})
    tid = r2.json()["id"]
    r3 = await client.post(f"/internal/tickets/{tid}/verify-rescan", json={"profile": "standard"})
    assert r3.status_code == 422


async def test_api_read_only_can_view_not_mutate(staff_client):
    client, target_id, role = staff_client
    # Seed as super_admin.
    r = await client.post("/internal/tickets", json={"user_id": str(target_id), "subject": "Z"})
    tid = r.json()["id"]

    # Downgrade.
    role["value"] = "read_only"
    assert (await client.get("/internal/tickets")).status_code == 200
    assert (await client.get(f"/internal/tickets/{tid}")).status_code == 200
    assert (await client.post(f"/internal/tickets/{tid}/status", json={"status": "closed"})).status_code == 403
    assert (await client.post("/internal/tickets", json={"subject": "blocked"})).status_code == 403
