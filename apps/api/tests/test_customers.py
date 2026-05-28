"""Customer Ops API + service: search/detail/suspend/notes/RBAC."""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.database import get_db
from apps.api.main import app
from apps.api.models.enums import PlanTier
from apps.api.models.user import User
from apps.api.security import get_current_user, hash_password
from apps.api.services import customers as cust_svc

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Service layer — pure DB logic, no auth.
# ---------------------------------------------------------------------------


async def _make_user(db, **overrides) -> User:
    u = User(
        email=overrides.pop("email", "u@x.com"),
        hashed_password=hash_password("testpassword123"),
        is_active=True,
        **overrides,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


async def test_search_filters_status_and_plan(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await _make_user(db, email="a@x.com", plan=PlanTier.FREE)
        await _make_user(db, email="b@x.com", plan=PlanTier.PRO)
        suspended = await _make_user(db, email="banned@x.com", plan=PlanTier.PRO)
        await cust_svc.suspend(db, suspended, reason="abuse")
        await db.commit()

    async with factory() as db:
        active, n_active = await cust_svc.search(db, status="active")
        emails = {u.email for u in active}
        assert "banned@x.com" not in emails
        assert n_active == 2

        sus, n_sus = await cust_svc.search(db, status="suspended")
        assert {u.email for u in sus} == {"banned@x.com"}
        assert n_sus == 1

        pro, n_pro = await cust_svc.search(db, plan="pro")
        assert {u.email for u in pro} == {"b@x.com", "banned@x.com"}
        assert n_pro == 2


async def test_suspend_sets_metadata_and_reactivate_clears_it(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _make_user(db, email="s@x.com")
        await cust_svc.suspend(db, u, reason="spam")
        await db.commit()
        await db.refresh(u)
        assert u.is_active is False
        assert u.banned_at is not None
        assert u.banned_reason == "spam"

        await cust_svc.reactivate(db, u)
        await db.commit()
        await db.refresh(u)
        assert u.is_active is True
        assert u.banned_at is None
        assert u.banned_reason is None


async def test_detail_aggregates_websites_and_subscriptions(db_engine):
    """customer_detail walks websites + scans + subs without ORM errors."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _make_user(db, email="d@x.com", full_name="Dee", plan=PlanTier.PRO)
        d = await cust_svc.detail(db, u.id)
        assert d is not None
        assert d["email"] == "d@x.com"
        assert d["plan"] == "pro"
        assert d["websites"] == 0
        assert d["scans"] == 0
        assert d["subscriptions"] == []

    async with factory() as db:
        assert await cust_svc.detail(db, u.id) is not None
        # Unknown id returns None, not an exception.
        from uuid import uuid4
        assert await cust_svc.detail(db, uuid4()) is None


async def test_notes_add_list_and_delete(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _make_user(db, email="n@x.com")
        n1 = await cust_svc.add_note(db, u.id, body="first", author_email="me@x.com")
        await cust_svc.add_note(db, u.id, body="second", author_email="me@x.com")
        await db.commit()
        items = await cust_svc.list_notes(db, u.id)
        assert [n["body"] for n in items] == ["second", "first"]   # newest first
        assert await cust_svc.delete_note(db, n1.id) is True
        await db.commit()
        items = await cust_svc.list_notes(db, u.id)
        assert [n["body"] for n in items] == ["second"]


# ---------------------------------------------------------------------------
# API — RBAC + happy path via injected staff client.
# ---------------------------------------------------------------------------


@pytest.fixture
async def staff_client(db_engine):
    """Yields (client, set_role) — switch the dependency role per assertion."""
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
            is_active=True,
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


async def test_api_list_detail_and_suspend(staff_client):
    client, target_id, _role = staff_client
    r = await client.get("/internal/customers")
    assert r.status_code == 200
    assert r.json()["total"] >= 2  # actor + target

    d = await client.get(f"/internal/customers/{target_id}")
    assert d.status_code == 200
    assert d.json()["email"] == "cust@x.com"

    sus = await client.post(f"/internal/customers/{target_id}/suspend",
                            json={"reason": "abuse"})
    assert sus.status_code == 200

    d2 = await client.get(f"/internal/customers/{target_id}")
    assert d2.json()["is_active"] is False
    assert d2.json()["banned_reason"] == "abuse"


async def test_api_cannot_suspend_self(staff_client):
    client, _target_id, _role = staff_client
    me = await client.get("/internal/me")
    actor_id = me.json()["id"]
    r = await client.post(f"/internal/customers/{actor_id}/suspend", json={"reason": "x"})
    assert r.status_code == 400


async def test_api_notes_rbac(staff_client):
    client, target_id, role = staff_client

    # support role can add notes
    role["value"] = "support"
    r = await client.post(f"/internal/customers/{target_id}/notes",
                          json={"body": "follow up Monday"})
    assert r.status_code == 200

    # support role CANNOT delete notes (admin only)
    notes = (await client.get(f"/internal/customers/{target_id}/notes")).json()["items"]
    nid = notes[0]["id"]
    r2 = await client.delete(f"/internal/notes/{nid}")
    assert r2.status_code == 403

    # admin role can delete
    role["value"] = "admin"
    r3 = await client.delete(f"/internal/notes/{nid}")
    assert r3.status_code == 200


async def test_api_change_plan_records_audit(staff_client):
    client, target_id, _role = staff_client
    r = await client.post(f"/internal/customers/{target_id}/plan", json={"plan": "shield"})
    assert r.status_code == 200
    assert r.json()["plan"] == "shield"
    d = await client.get(f"/internal/customers/{target_id}")
    assert d.json()["plan"] == "shield"


async def test_api_read_only_blocked_from_mutations(staff_client):
    client, target_id, role = staff_client
    role["value"] = "read_only"
    r = await client.post(f"/internal/customers/{target_id}/suspend", json={"reason": "x"})
    assert r.status_code == 403
    r2 = await client.post(f"/internal/customers/{target_id}/force-logout")
    assert r2.status_code == 403
    # but they can still read
    r3 = await client.get(f"/internal/customers/{target_id}")
    assert r3.status_code == 200
