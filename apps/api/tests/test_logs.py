"""Phase 8: Log Explorer + Audit search/export + RBAC."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.database import get_db
from apps.api.internal.audit import record_action
from apps.api.main import app
from apps.api.models.user import User
from apps.api.security import get_current_user, hash_password
from apps.api.services import logs as log_svc

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Logs service
# ---------------------------------------------------------------------------


async def test_record_normalizes_severity_and_caps_message(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        # An unknown severity falls back to "info" rather than raising.
        r1 = await log_svc.record(db, source="api", severity="bogus", message="hello")
        assert r1.severity == "info"
        # Long messages are clipped so a runaway traceback can't blow up rows.
        r2 = await log_svc.record(db, source="api", severity="error",
                                  message="x" * 20000)
        assert len(r2.message) == 8000


async def test_search_logs_threshold_returns_only_at_or_above(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        for sev in ("debug", "info", "warning", "error", "critical"):
            await log_svc.record(db, source="api", severity=sev, message=f"m {sev}")
        await db.commit()
        rows, total = await log_svc.search_logs(db, severity_at_least="warning")
        assert total == 3
        assert {r.severity for r in rows} == {"warning", "error", "critical"}


async def test_search_logs_filters_combine(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await log_svc.record(db, source="api", severity="info",
                             message="user signed up", request_id="req-1")
        await log_svc.record(db, source="worker", severity="error",
                             message="scan failed for example.com", request_id="req-2")
        await log_svc.record(db, source="api", severity="error",
                             message="db timeout", request_id="req-2")
        await db.commit()

        rows, total = await log_svc.search_logs(db, source="api")
        assert total == 2
        rows, total = await log_svc.search_logs(db, q="scan failed")
        assert total == 1 and rows[0].source == "worker"
        rows, total = await log_svc.search_logs(db, request_id="req-2")
        assert total == 2


async def test_logs_csv_export_includes_header(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await log_svc.record(db, source="api", severity="info",
                             message="hi,there\nmultiline")
        await db.commit()
        rows, _ = await log_svc.search_logs(db, limit=5)
        body = log_svc.logs_to_csv(rows)
        lines = body.splitlines()
        assert lines[0].startswith("timestamp,source,severity")
        # Newlines in the message are flattened so the CSV row stays on one line.
        assert "hi,there multiline" in body
        # Exactly one data line.
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# Audit search
# ---------------------------------------------------------------------------


async def test_search_audit_filters(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        admin = User(email="a@x.com", hashed_password=hash_password("x"),
                     is_active=True, is_admin=True, admin_role="super_admin")
        db.add(admin); await db.commit(); await db.refresh(admin)
        await record_action(db, actor=admin, action="customer.suspend",
                            target_type="user", target_id="u-1")
        await record_action(db, actor=admin, action="ticket.create",
                            target_type="ticket", target_id="t-1")
        await record_action(db, actor=admin, action="customer.suspend",
                            target_type="user", target_id="u-2")
        await db.commit()

        rows, total = await log_svc.search_audit(db, action="customer.suspend")
        assert total == 2
        rows, total = await log_svc.search_audit(db, target_id="u-1")
        assert total == 1 and rows[0].action == "customer.suspend"
        rows, total = await log_svc.search_audit(db, q="ticket")
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
        db.add(actor); await db.commit(); await db.refresh(actor)
        # Seed a couple of rows so the API has something to return.
        await log_svc.record(db, source="api", severity="warning",
                             message="hot path slow")
        await log_svc.record(db, source="worker", severity="info",
                             message="scan finished")
        await record_action(db, actor=actor, action="phase8.test",
                            target_type="thing", target_id="abc")
        await db.commit()

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
        yield c, role
    app.dependency_overrides.clear()


async def test_api_logs_search_and_filter(staff_client):
    client, _role = staff_client
    r = await client.get("/internal/logs")
    assert r.status_code == 200
    assert r.json()["total"] >= 2

    r2 = await client.get("/internal/logs?severity_at_least=warning")
    assert r2.json()["total"] == 1
    assert r2.json()["items"][0]["severity"] == "warning"


async def test_api_logs_csv_export(staff_client):
    client, _role = staff_client
    r = await client.get("/internal/logs.csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert r.text.startswith("timestamp,source,severity")
    # Header + at least one data row.
    assert len(r.text.splitlines()) >= 2


async def test_api_audit_search_and_csv(staff_client):
    client, _role = staff_client
    r = await client.get("/internal/audit?action=phase8.test")
    assert r.status_code == 200
    assert r.json()["total"] == 1

    csv = await client.get("/internal/audit.csv")
    assert csv.status_code == 200
    assert csv.headers["content-type"].startswith("text/csv")


async def test_api_blocked_for_customer(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = User(email="cust@x.com", hashed_password=hash_password("x"), is_active=True)
        db.add(u); await db.commit(); await db.refresh(u)

    async def _get_db():
        async with factory() as s:
            yield s

    async def _get_user():
        return u

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_user] = _get_user
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            assert (await c.get("/internal/logs")).status_code == 403
            assert (await c.get("/internal/audit")).status_code == 403
            assert (await c.get("/internal/logs.csv")).status_code == 403
    finally:
        app.dependency_overrides.clear()
