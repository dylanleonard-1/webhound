"""Phase 7: team role management, deploys history, infra metrics + RBAC."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.database import get_db
from apps.api.main import app
from apps.api.models.deployment import Deployment
from apps.api.models.infrastructure_sample import InfrastructureSample
from apps.api.models.user import User
from apps.api.security import get_current_user, hash_password
from apps.api.services import deployments as deploy_svc
from apps.api.services import infra_metrics as infra_svc
from apps.api.services import team as team_svc

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Team service
# ---------------------------------------------------------------------------


async def test_change_admin_role_validates_and_flips_is_admin(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = User(email="t@x.com", hashed_password=hash_password("x"),
                 is_active=True)
        db.add(u); await db.commit(); await db.refresh(u)

        await team_svc.change_admin_role(db, u, "support")
        await db.commit()
        await db.refresh(u)
        assert u.admin_role == "support"
        assert u.is_admin is True

        await team_svc.change_admin_role(db, u, "none")
        await db.commit()
        await db.refresh(u)
        assert u.admin_role == "none"
        assert u.is_admin is False

        with pytest.raises(ValueError):
            await team_svc.change_admin_role(db, u, "bogus")


async def test_list_staff_returns_only_non_none_roles(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        db.add_all([
            User(email="cust@x.com", hashed_password=hash_password("x"),
                 is_active=True, admin_role="none"),
            User(email="ops@x.com", hashed_password=hash_password("x"),
                 is_active=True, admin_role="analyst"),
            User(email="owner@x.com", hashed_password=hash_password("x"),
                 is_active=True, admin_role="super_admin", is_admin=True),
        ])
        await db.commit()
        staff = await team_svc.list_staff(db)
        emails = {s["email"] for s in staff}
        assert emails == {"ops@x.com", "owner@x.com"}


async def test_recent_logins_filters_by_window(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        now = datetime.now(timezone.utc)
        recent = User(email="r@x.com", hashed_password=hash_password("x"),
                      is_active=True, last_login_at=now - timedelta(hours=1))
        old = User(email="o@x.com", hashed_password=hash_password("x"),
                   is_active=True, last_login_at=now - timedelta(days=10))
        never = User(email="n@x.com", hashed_password=hash_password("x"),
                     is_active=True)
        db.add_all([recent, old, never])
        await db.commit()

        rows = await team_svc.recent_logins(db, hours=72)
        emails = [r["email"] for r in rows]
        assert "r@x.com" in emails
        assert "o@x.com" not in emails
        assert "n@x.com" not in emails


# ---------------------------------------------------------------------------
# Deploys service
# ---------------------------------------------------------------------------


async def test_record_deploy_validates_inputs(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        with pytest.raises(ValueError):
            await deploy_svc.record(db, service="bogus", sha="abcdef1234",
                                    actor_email="me@x.com")
        with pytest.raises(ValueError):
            await deploy_svc.record(db, service="api", sha="abc",
                                    actor_email="me@x.com")
        with pytest.raises(ValueError):
            await deploy_svc.record(db, service="api", sha="abcdef1234",
                                    status="bogus", actor_email="me@x.com")


async def test_record_and_list_deploys(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await deploy_svc.record(db, service="api", sha="abc1234567",
                                status="succeeded", actor_email="me@x.com", note="release v1")
        await deploy_svc.record(db, service="worker", sha="def1234567",
                                status="failed", actor_email="me@x.com")
        await db.commit()
        rows = await deploy_svc.list_recent(db, limit=10)
        assert len(rows) == 2
        api_only = await deploy_svc.list_recent(db, service="api")
        assert len(api_only) == 1
        assert api_only[0]["sha"] == "abc1234567"
        assert api_only[0]["status"] == "succeeded"


def test_current_sha_reads_env(monkeypatch):
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "feed1234abcd")
    assert deploy_svc.current_sha() == "feed1234abcd"
    monkeypatch.delenv("RAILWAY_GIT_COMMIT_SHA", raising=False)
    assert deploy_svc.current_sha() is None


# ---------------------------------------------------------------------------
# Infra metrics service
# ---------------------------------------------------------------------------


async def test_infra_history_returns_recent_samples_in_order(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        for queue_depth in (5, 3, 1):
            await infra_svc.store_sample(
                db, queue_depth=queue_depth, worker_alive=True,
                worker_heartbeat_age_s=10.0, redis_used_memory_mb=12.5,
                active_scans=queue_depth,
            )
        await db.commit()
        rows = await infra_svc.history(db, hours=24)
        depths = [r["queue_depth"] for r in rows]
        # Sorted by taken_at ascending — order preserved.
        assert depths == [5, 3, 1]


# ---------------------------------------------------------------------------
# API + RBAC
# ---------------------------------------------------------------------------


@pytest.fixture
async def staff_client(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        actor = User(
            email="owner@webhoundsecurity.com",
            hashed_password=hash_password("testpassword123"),
            is_active=True, is_admin=True, admin_role="super_admin",
        )
        target = User(
            email="staff@x.com",
            hashed_password=hash_password("testpassword123"),
            is_active=True, admin_role="support",
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


async def test_api_team_lists_only_staff_accounts(staff_client):
    client, _target_id, _role = staff_client
    r = await client.get("/internal/team")
    assert r.status_code == 200
    emails = {s["email"] for s in r.json()["staff"]}
    assert "owner@webhoundsecurity.com" in emails
    assert "staff@x.com" in emails


async def test_api_role_change_blocked_for_self_and_non_super_admin(staff_client):
    client, target_id, role = staff_client
    me = await client.get("/internal/me")
    actor_id = me.json()["id"]

    # Cannot change own role.
    r = await client.post(f"/internal/team/{actor_id}/role", json={"role": "admin"})
    assert r.status_code == 400

    # Downgrade actor — only super_admin can change roles.
    role["value"] = "admin"
    r2 = await client.post(f"/internal/team/{target_id}/role", json={"role": "developer"})
    assert r2.status_code == 403

    # Restore + verify happy path + validation 422.
    role["value"] = "super_admin"
    r3 = await client.post(f"/internal/team/{target_id}/role", json={"role": "developer"})
    assert r3.status_code == 200
    r4 = await client.post(f"/internal/team/{target_id}/role", json={"role": "bogus"})
    assert r4.status_code == 422


async def test_api_record_deploys(staff_client):
    client, _target_id, role = staff_client

    r = await client.post("/internal/deploys", json={"service": "api", "sha": "deadbeef00", "status": "succeeded"})
    assert r.status_code == 200

    lst = await client.get("/internal/deploys")
    assert lst.status_code == 200
    assert any(d["sha"] == "deadbeef00" for d in lst.json()["items"])

    # ADMIN can record; READ_ONLY cannot.
    role["value"] = "read_only"
    r2 = await client.post("/internal/deploys", json={"service": "api", "sha": "abc1234567"})
    assert r2.status_code == 403


async def test_api_maintenance_toggle_super_admin_only(staff_client):
    client, _target_id, role = staff_client

    s = await client.get("/internal/maintenance")
    assert s.status_code == 200
    assert s.json()["active"] in (True, False)

    role["value"] = "admin"
    r = await client.post("/internal/maintenance", json={"active": True, "reason": "x"})
    assert r.status_code == 403

    role["value"] = "super_admin"
    # Engage+disengage are best-effort on Redis; the endpoint succeeds regardless.
    r2 = await client.post("/internal/maintenance", json={"active": True, "reason": "deploy"})
    assert r2.status_code == 200
    r3 = await client.post("/internal/maintenance", json={"active": False})
    assert r3.status_code == 200
