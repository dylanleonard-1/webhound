"""Phase 10: incidents (correlation + lifecycle + MTTR + RBAC) + engine state."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.database import get_db
from apps.api.main import app
from apps.api.models.incident import Incident, IncidentEvent
from apps.api.models.user import User
from apps.api.security import get_current_user, hash_password
from apps.api.services import alerts as alert_svc
from apps.api.services import engines as engines_svc
from apps.api.services import incidents as inc_svc

pytestmark = pytest.mark.anyio


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Engine state machine + registry
# ---------------------------------------------------------------------------


def test_compute_state_thresholds():
    # Maintenance trumps everything.
    assert engines_svc.compute_state(runs=100, failed=0, maintenance_mode=True) == "maintenance"
    # Below the minimum-runs floor we keep saying healthy.
    assert engines_svc.compute_state(runs=2, failed=2, maintenance_mode=False) == "healthy"
    # Crossing each threshold flips the state up.
    assert engines_svc.compute_state(runs=100, failed=5, maintenance_mode=False) == "healthy"
    assert engines_svc.compute_state(runs=100, failed=20, maintenance_mode=False) == "degraded"
    assert engines_svc.compute_state(runs=100, failed=50, maintenance_mode=False) == "unstable"
    assert engines_svc.compute_state(runs=100, failed=80, maintenance_mode=False) == "critical"


async def test_engine_registry_get_or_create_and_maintenance(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        row1 = await engines_svc.get_or_create_registry(db, "sensitive_paths")
        row2 = await engines_svc.get_or_create_registry(db, "sensitive_paths")
        assert row1.id == row2.id
        assert row1.maintenance_mode is False

        await engines_svc.set_maintenance(db, "sensitive_paths", on=True,
                                          actor_email="me@x.com")
        await db.commit()
        await db.refresh(row1)
        assert row1.maintenance_mode is True
        assert row1.updated_by_email == "me@x.com"

        await engines_svc.set_maintenance(db, "sensitive_paths", on=False,
                                          actor_email="me@x.com")
        await db.commit()
        await db.refresh(row1)
        assert row1.maintenance_mode is False
        # Clearing maintenance also clears the auto_disabled_at flag.
        assert row1.auto_disabled_at is None


async def test_engine_registry_threshold_clamps(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await engines_svc.set_auto_disable_threshold(db, "engine_x",
                                                    failure_pct=150,
                                                    actor_email="me@x.com")
        row = await engines_svc.get_registry(db, "engine_x")
        assert row is not None
        assert row.auto_disable_at_failure_pct == 100
        await engines_svc.set_auto_disable_threshold(db, "engine_x",
                                                    failure_pct=-20,
                                                    actor_email="me@x.com")
        await db.refresh(row)
        assert row.auto_disable_at_failure_pct == 0
        # None clears the threshold.
        await engines_svc.set_auto_disable_threshold(db, "engine_x",
                                                    failure_pct=None,
                                                    actor_email="me@x.com")
        await db.refresh(row)
        assert row.auto_disable_at_failure_pct is None


# ---------------------------------------------------------------------------
# Incident correlation
# ---------------------------------------------------------------------------


async def test_alert_upsert_opens_incident_then_attaches(db_engine):
    """First alert creates an incident; second alert with the same target
    attaches to it (alert_count bumps, no second incident)."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        a1, c1 = await alert_svc.upsert_alert(
            db, dedup_key="engine_reliability:sensitive_paths",
            source="engine_reliability", severity="high",
            title="Engine 'sensitive_paths' failing 81.8%",
            target_type="engine", target_id="sensitive_paths",
        )
        assert c1 is True
        # Same alert recurs — should bump occurrences and NOT create a 2nd incident.
        a2, c2 = await alert_svc.upsert_alert(
            db, dedup_key="engine_reliability:sensitive_paths",
            source="engine_reliability", severity="high",
            title="Engine 'sensitive_paths' failing 81.8%",
            target_type="engine", target_id="sensitive_paths",
        )
        assert c2 is False and a2.id == a1.id
        await db.commit()

        incidents, total = await inc_svc.search(db)
        assert total == 1
        inc = incidents[0]
        # alert_count counts both the open (1) and the re-fire (2nd correlation).
        assert inc.alert_count == 2
        assert inc.correlation_key == "engine_reliability:engine:sensitive_paths"
        # And the timeline reflects the attach.
        events = await inc_svc.list_events(db, inc.id)
        assert any(e["kind"] == "alert_attached" for e in events)


async def test_severity_escalation_records_event_and_bumps(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await alert_svc.upsert_alert(
            db, dedup_key="worker_down", source="worker_down", severity="medium",
            title="Worker stale",
        )
        # A higher-severity recurrence escalates the incident.
        await alert_svc.upsert_alert(
            db, dedup_key="worker_down", source="worker_down", severity="critical",
            title="Worker stale (critical)",
        )
        await db.commit()
        items, _ = await inc_svc.search(db)
        assert len(items) == 1
        assert items[0].severity == "critical"
        events = await inc_svc.list_events(db, items[0].id)
        # An explicit "severity escalated" system event lands in the timeline.
        assert any("escalated" in e["body"] for e in events)


# ---------------------------------------------------------------------------
# Lifecycle + MTTR
# ---------------------------------------------------------------------------


async def test_change_status_computes_mttr_on_resolve(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await alert_svc.upsert_alert(
            db, dedup_key="k", source="scan_failure", severity="high",
            title="Scan failed",
        )
        await db.commit()
        items, _ = await inc_svc.search(db)
        i = items[0]

        await inc_svc.change_status(db, i, "acknowledged", actor_email="me@x.com")
        await inc_svc.change_status(db, i, "investigating", actor_email="me@x.com")
        await inc_svc.change_status(db, i, "mitigated", actor_email="me@x.com")
        await inc_svc.change_status(db, i, "resolved", actor_email="me@x.com")
        await db.commit()
        await db.refresh(i)
        assert i.status == "resolved"
        assert i.acknowledged_at is not None
        assert i.acknowledged_by_email == "me@x.com"
        assert i.mitigated_at is not None
        assert i.resolved_at is not None
        # MTTR is the wall-clock seconds from first_seen → resolved.
        assert i.mttr_seconds is not None and i.mttr_seconds >= 0


async def test_reopen_clears_terminal_fields(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await alert_svc.upsert_alert(
            db, dedup_key="k2", source="scan_failure", severity="high",
            title="Y",
        )
        await db.commit()
        items, _ = await inc_svc.search(db)
        i = items[0]
        await inc_svc.change_status(db, i, "resolved", actor_email="me@x.com")
        await db.commit()
        await db.refresh(i)
        assert i.resolved_at is not None
        await inc_svc.change_status(db, i, "investigating", actor_email="me@x.com")
        await db.commit()
        await db.refresh(i)
        assert i.resolved_at is None
        assert i.mttr_seconds is None


async def test_summary_picks_top_by_severity(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await alert_svc.upsert_alert(db, dedup_key="low_k", source="x",
                                     severity="low", title="Low one")
        await alert_svc.upsert_alert(db, dedup_key="hi_k", source="y",
                                     severity="critical", title="Critical one")
        await db.commit()
        s = await inc_svc.summary(db)
        assert s["active"] == 2
        assert s["top"]["severity"] == "critical"


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
        # Seed an incident through the alert correlator.
        await alert_svc.upsert_alert(
            db, dedup_key="api_k", source="scan_failure", severity="high",
            title="Phase-10 API seed",
        )
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


async def test_api_list_summary_detail(staff_client):
    client, _role = staff_client
    r = await client.get("/internal/incidents")
    assert r.status_code == 200
    assert r.json()["total"] >= 1

    s = await client.get("/internal/incidents/summary")
    body = s.json()
    assert body["active"] >= 1
    assert body["top"] is not None
    assert body["top"]["title"] == "Phase-10 API seed"

    iid = r.json()["items"][0]["id"]
    d = await client.get(f"/internal/incidents/{iid}")
    assert d.status_code == 200
    assert "events" in d.json()


async def test_api_status_transitions_and_validation(staff_client):
    client, _role = staff_client
    iid = (await client.get("/internal/incidents")).json()["items"][0]["id"]
    bad = await client.post(f"/internal/incidents/{iid}/status", json={"status": "bogus"})
    assert bad.status_code == 422
    ok = await client.post(f"/internal/incidents/{iid}/status", json={"status": "acknowledged"})
    assert ok.status_code == 200


async def test_api_read_only_blocked(staff_client):
    client, role = staff_client
    iid = (await client.get("/internal/incidents")).json()["items"][0]["id"]
    role["value"] = "read_only"
    r = await client.post(f"/internal/incidents/{iid}/status", json={"status": "investigating"})
    assert r.status_code == 403
    # Reads still allowed.
    assert (await client.get(f"/internal/incidents/{iid}")).status_code == 200
