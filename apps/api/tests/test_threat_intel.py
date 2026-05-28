"""Phase 9A: threat intelligence indicator lifecycle + fraud integration + RBAC."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.database import get_db
from apps.api.main import app
from apps.api.models.abuse import IPDeviceFingerprint
from apps.api.models.user import User
from apps.api.security import get_current_user, hash_password
from apps.api.services import fraud as fraud_svc
from apps.api.services import threat_intel as ti_svc

pytestmark = pytest.mark.anyio


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Service: upsert/normalize/match/import/expire
# ---------------------------------------------------------------------------


async def test_upsert_validates_and_normalizes(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        with pytest.raises(ValueError):
            await ti_svc.upsert_indicator(db, kind="bogus", value="x", source="manual")
        with pytest.raises(ValueError):
            await ti_svc.upsert_indicator(db, kind="ip", value="1.1.1.1",
                                          source="manual", severity="WTF")

        # Domain values are lowercased + trailing-dot stripped — dedup hits the
        # same row even though the input differs.
        r1, c1 = await ti_svc.upsert_indicator(db, kind="domain",
                                               value="Evil.Example.COM.", source="manual")
        r2, c2 = await ti_svc.upsert_indicator(db, kind="domain",
                                               value="evil.example.com", source="manual")
        assert c1 is True and c2 is False
        assert r2.id == r1.id
        assert r2.value == "evil.example.com"


async def test_upsert_clamps_confidence(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        r, _ = await ti_svc.upsert_indicator(db, kind="ip", value="9.9.9.9",
                                             source="manual", confidence=999)
        assert r.confidence == 100
        r2, _ = await ti_svc.upsert_indicator(db, kind="ip", value="9.9.9.9",
                                              source="manual", confidence=-5)
        assert r2.confidence == 0


async def test_match_excludes_expired(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await ti_svc.upsert_indicator(
            db, kind="ip", value="2.2.2.2", source="manual",
            expires_at=_now() - timedelta(hours=1),   # already expired
        )
        await ti_svc.upsert_indicator(db, kind="ip", value="3.3.3.3", source="manual")
        await db.commit()
        assert await ti_svc.match(db, kind="ip", value="2.2.2.2") == []
        hits = await ti_svc.match(db, kind="ip", value="3.3.3.3")
        assert len(hits) == 1


async def test_import_feed_counts_created_updated_skipped(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        counts = await ti_svc.import_feed(
            db, source="feed-x",
            rows=[
                {"kind": "ip", "value": "4.4.4.4"},
                {"kind": "ip", "value": "5.5.5.5"},
                {"kind": "ip", "value": ""},        # skipped — empty value
                {"kind": "WAT", "value": "x"},      # skipped — bad kind
                {"kind": "ip", "value": "4.4.4.4"}, # updates the first row
            ],
            expires_in_days=7,
        )
        assert counts == {"created": 2, "updated": 1, "skipped": 2}


async def test_expire_stale_deletes_only_past_ttl(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        await ti_svc.upsert_indicator(db, kind="ip", value="6.6.6.6",
                                      source="manual",
                                      expires_at=_now() - timedelta(days=1))
        await ti_svc.upsert_indicator(db, kind="ip", value="7.7.7.7",
                                      source="manual",
                                      expires_at=_now() + timedelta(days=30))
        await ti_svc.upsert_indicator(db, kind="ip", value="8.8.8.8",
                                      source="manual", expires_at=None)
        await db.commit()
        deleted = await ti_svc.expire_stale(db)
        assert deleted == 1


# ---------------------------------------------------------------------------
# Fraud integration: a known-bad IP in a user's fingerprints lights up the
# new "threat_intel_ip" signal in the scoring engine.
# ---------------------------------------------------------------------------


async def test_threat_intel_ip_signal_triggers_in_fraud_evaluator(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = User(email="vic@x.com", hashed_password=hash_password("x"), is_active=True)
        db.add(u); await db.commit(); await db.refresh(u)
        now = _now()
        db.add(IPDeviceFingerprint(
            user_id=u.id, ip_address="66.66.66.66", user_agent="UA",
            first_seen_at=now, last_seen_at=now, occurrences=1,
        ))
        await ti_svc.upsert_indicator(db, kind="ip", value="66.66.66.66",
                                      source="alienvault", severity="high")
        await db.commit()

        score = await fraud_svc.evaluate_user(db, u.id, email=u.email)
        assert "threat_intel_ip" in score["reasons"]
        # The new signal weight (35) alone is enough to clear the flag threshold.
        assert score["score"] >= fraud_svc.FLAG_THRESHOLD
        assert score["detail"]["threat_intel_ip"]["hits"][0]["source"] == "alienvault"


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


async def test_api_full_lifecycle(staff_client):
    client, _role = staff_client

    r = await client.post("/internal/threat-intel/indicators", json={
        "kind": "ip", "value": "10.20.30.40", "source": "manual",
        "severity": "high", "confidence": 90,
    })
    assert r.status_code == 200
    ind_id = r.json()["id"]

    lst = await client.get("/internal/threat-intel/indicators")
    assert lst.status_code == 200
    assert lst.json()["total"] == 1

    m = await client.get("/internal/threat-intel/indicators/match?kind=ip&value=10.20.30.40")
    assert m.status_code == 200
    assert m.json()["count"] == 1

    m2 = await client.get("/internal/threat-intel/indicators/match?kind=ip&value=99.99.99.99")
    assert m2.json()["count"] == 0

    imp = await client.post("/internal/threat-intel/import", json={
        "source": "feed-y",
        "rows": [{"kind": "ip", "value": "11.11.11.11"},
                 {"kind": "domain", "value": "evil.test"}],
    })
    assert imp.status_code == 200
    assert imp.json()["created"] == 2

    d = await client.delete(f"/internal/threat-intel/indicators/{ind_id}")
    assert d.status_code == 200


async def test_api_rbac_matrix(staff_client):
    client, role = staff_client

    # Seed as admin so we have one row.
    r = await client.post("/internal/threat-intel/indicators", json={
        "kind": "ip", "value": "12.12.12.12",
    })
    ind_id = r.json()["id"]

    # READ_ONLY can list/match but not add/delete/import.
    role["value"] = "read_only"
    assert (await client.get("/internal/threat-intel/indicators")).status_code == 200
    assert (await client.get(
        "/internal/threat-intel/indicators/match?kind=ip&value=12.12.12.12"
    )).status_code == 200
    assert (await client.post("/internal/threat-intel/indicators",
                              json={"kind": "ip", "value": "x"})).status_code == 403
    assert (await client.delete(f"/internal/threat-intel/indicators/{ind_id}")).status_code == 403
    assert (await client.post("/internal/threat-intel/import",
                              json={"source": "x", "rows": []})).status_code == 403

    # ANALYST can add but not delete or bulk import.
    role["value"] = "analyst"
    assert (await client.post("/internal/threat-intel/indicators",
                              json={"kind": "ip", "value": "13.13.13.13"})).status_code == 200
    assert (await client.delete(f"/internal/threat-intel/indicators/{ind_id}")).status_code == 403
    assert (await client.post("/internal/threat-intel/import",
                              json={"source": "x", "rows": []})).status_code == 403

    # ADMIN can do everything.
    role["value"] = "admin"
    assert (await client.post("/internal/threat-intel/import",
                              json={"source": "z", "rows": [{"kind": "ip", "value": "1.1.1.1"}]})).status_code == 200
    assert (await client.delete(f"/internal/threat-intel/indicators/{ind_id}")).status_code == 200
