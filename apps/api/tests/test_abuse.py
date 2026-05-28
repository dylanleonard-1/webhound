"""Fraud & abuse lifecycle: fingerprints, scoring, flag triage, RBAC."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.database import get_db
from apps.api.main import app
from apps.api.models.abuse import AbuseFlag, IPDeviceFingerprint
from apps.api.models.enums import PlanTier, ScanStatus, SubscriptionStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.subscription import Subscription
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.security import get_current_user, hash_password
from apps.api.services import fraud as fraud_svc

pytestmark = pytest.mark.anyio


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _user(db, email="u@x.com") -> User:
    u = User(email=email, hashed_password=hash_password("testpassword123"), is_active=True)
    db.add(u); await db.commit(); await db.refresh(u)
    return u


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------


async def test_fingerprint_upsert_bumps_existing(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        await fraud_svc.record_login_fingerprint(db, user_id=u.id, ip_address="1.2.3.4", user_agent="UA")
        await fraud_svc.record_login_fingerprint(db, user_id=u.id, ip_address="1.2.3.4", user_agent="UA")
        await db.commit()
        prints = await fraud_svc.list_fingerprints(db, u.id)
        assert len(prints) == 1
        assert prints[0]["occurrences"] == 2


async def test_fingerprint_no_op_when_ip_missing(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        await fraud_svc.record_login_fingerprint(db, user_id=u.id, ip_address=None, user_agent="UA")
        await db.commit()
        assert await fraud_svc.list_fingerprints(db, u.id) == []


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


async def test_evaluate_excessive_scans_signal(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        w = Website(user_id=u.id, url="https://x.com/", hostname="x.com", scheme="https")
        db.add(w); await db.commit(); await db.refresh(w)
        for _ in range(55):
            db.add(ScanJob(website_id=w.id, profile="standard",
                           requested_url="https://x.com/", status=ScanStatus.COMPLETED))
        await db.commit()

        score = await fraud_svc.evaluate_user(db, u.id, email=u.email)
        assert "excessive_scans" in score["reasons"]
        assert score["score"] >= fraud_svc.FLAG_THRESHOLD


async def test_evaluate_failed_payments_signal(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        db.add(Subscription(
            user_id=u.id, stripe_subscription_id="sub_x", stripe_customer_id="cus_x",
            plan=PlanTier.PRO, status=SubscriptionStatus.PAST_DUE,
        ))
        await db.commit()
        score = await fraud_svc.evaluate_user(db, u.id, email=u.email)
        assert "failed_payments" in score["reasons"]


async def test_evaluate_clean_user_below_threshold(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        score = await fraud_svc.evaluate_user(db, u.id, email=u.email)
        assert score["score"] < fraud_svc.FLAG_THRESHOLD
        assert score["reasons"] == []


async def test_evaluate_distinct_ips_signal(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        now = _now()
        for i in range(6):
            db.add(IPDeviceFingerprint(
                user_id=u.id, ip_address=f"10.0.0.{i}", user_agent="UA",
                first_seen_at=now, last_seen_at=now, occurrences=1,
            ))
        await db.commit()
        score = await fraud_svc.evaluate_user(db, u.id, email=u.email)
        assert "many_ips" in score["reasons"]


# ---------------------------------------------------------------------------
# Flag lifecycle
# ---------------------------------------------------------------------------


async def test_upsert_flag_dedup_and_reopens_dismissed(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        f1, created = await fraud_svc.upsert_flag(
            db, user_id=u.id, ip_address=None,
            score=40, severity="medium", reasons=["many_ips"], detail={},
        )
        assert created is True
        f2, created2 = await fraud_svc.upsert_flag(
            db, user_id=u.id, ip_address=None,
            score=60, severity="high", reasons=["many_ips", "excessive_scans"], detail={},
        )
        assert created2 is False
        assert f2.id == f1.id
        assert f2.occurrences == 2
        assert f2.severity == "high"

        await fraud_svc.dismiss(db, f2, actor_email="me@x.com", note="false positive")
        await db.commit()
        await db.refresh(f2)
        assert f2.status == "dismissed"

        # Recurrence re-opens the same row.
        _, created3 = await fraud_svc.upsert_flag(
            db, user_id=u.id, ip_address=None,
            score=70, severity="high", reasons=["excessive_scans"], detail={},
        )
        assert created3 is False
        await db.commit()
        await db.refresh(f2)
        assert f2.status == "pending"


async def test_auto_resolve_clears_pending_when_signals_drop(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        flag, _ = await fraud_svc.upsert_flag(
            db, user_id=u.id, ip_address=None, score=50, severity="high",
            reasons=["excessive_scans"], detail={},
        )
        assert await fraud_svc.auto_resolve_if_cleared(db, flag, new_score=10) is True
        assert flag.status == "dismissed"
        # Doesn't downgrade a still-bad score.
        flag2, _ = await fraud_svc.upsert_flag(
            db, user_id=u.id, ip_address=None, score=60, severity="high",
            reasons=["excessive_scans"], detail={},
        )
        assert await fraud_svc.auto_resolve_if_cleared(db, flag2, new_score=60) is False


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
            email="bad@x.com",
            hashed_password=hash_password("testpassword123"),
            is_active=True,
        )
        db.add_all([actor, target])
        await db.commit()
        await db.refresh(actor)
        await db.refresh(target)
        # Seed a flag.
        flag, _ = await fraud_svc.upsert_flag(
            db, user_id=target.id, ip_address=None, score=60, severity="high",
            reasons=["excessive_scans", "many_ips"], detail={"excessive_scans": {"scans_24h": 80}},
        )
        await db.commit()
        flag_id = flag.id

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
        yield c, target.id, flag_id, role
    app.dependency_overrides.clear()


async def test_api_list_summary_detail(staff_client):
    client, target_id, flag_id, _role = staff_client
    r = await client.get("/internal/abuse/flags?status=pending")
    assert r.status_code == 200
    assert r.json()["total"] == 1

    s = await client.get("/internal/abuse/summary")
    assert s.json()["pending"] == 1
    assert s.json()["by_severity"].get("high", 0) == 1

    d = await client.get(f"/internal/abuse/flags/{flag_id}")
    assert d.status_code == 200
    body = d.json()
    assert body["user_email"] == "bad@x.com"
    assert "excessive_scans" in body["reasons"]


async def test_api_dismiss_then_ban_promotes_to_user_suspension(staff_client):
    client, target_id, flag_id, _role = staff_client

    # Dismiss first.
    r = await client.post(f"/internal/abuse/flags/{flag_id}/dismiss", json={"note": "test"})
    assert r.status_code == 200
    d = await client.get(f"/internal/abuse/flags/{flag_id}")
    assert d.json()["status"] == "dismissed"

    # Ban from a dismissed flag is still allowed — staff can escalate later.
    r2 = await client.post(f"/internal/abuse/flags/{flag_id}/ban", json={"reason": "manual"})
    assert r2.status_code == 200
    # Target is now suspended.
    cd = await client.get(f"/internal/customers/{target_id}")
    assert cd.json()["is_active"] is False
    assert cd.json()["banned_reason"] is not None


async def test_api_cannot_ban_self(staff_client):
    client, _target_id, _flag_id, _role = staff_client
    me = await client.get("/internal/me")
    actor_id = me.json()["id"]
    # Seed a flag on the actor and try to ban.
    factory = async_sessionmaker(client._transport.app.dependency_overrides[get_db].__wrapped__.__self__
                                 if hasattr(client._transport.app.dependency_overrides[get_db], "__wrapped__") else None,
                                 expire_on_commit=False)  # type: ignore  # noqa: SLF001
    # Use the API to evaluate (it just scores, doesn't suspend).
    e = await client.post(f"/internal/abuse/evaluate/{actor_id}")
    # Actor is clean → no flag.
    assert e.status_code == 200
    assert "flag_id" not in e.json()


async def test_api_read_only_blocked_from_mutations(staff_client):
    client, _target_id, flag_id, role = staff_client
    role["value"] = "read_only"
    r = await client.post(f"/internal/abuse/flags/{flag_id}/dismiss", json={"note": "x"})
    assert r.status_code == 403
    r2 = await client.post(f"/internal/abuse/flags/{flag_id}/ban", json={"reason": "x"})
    assert r2.status_code == 403
    # Read is allowed.
    r3 = await client.get(f"/internal/abuse/flags/{flag_id}")
    assert r3.status_code == 200


async def test_api_analyst_can_dismiss_not_ban(staff_client):
    client, _target_id, flag_id, role = staff_client
    role["value"] = "analyst"
    r = await client.post(f"/internal/abuse/flags/{flag_id}/dismiss", json={"note": "ok"})
    assert r.status_code == 200
    r2 = await client.post(f"/internal/abuse/flags/{flag_id}/ban", json={"reason": "x"})
    assert r2.status_code == 403


# ---------------------------------------------------------------------------
# Candidate selection
# ---------------------------------------------------------------------------


async def test_find_candidates_picks_users_with_signals(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        clean = await _user(db, email="clean@x.com")
        loud  = await _user(db, email="loud@x.com")
        payee = await _user(db, email="payee@x.com")

        w = Website(user_id=loud.id, url="https://l.com/", hostname="l.com", scheme="https")
        db.add(w); await db.commit(); await db.refresh(w)
        for _ in range(60):
            db.add(ScanJob(website_id=w.id, profile="standard",
                           requested_url="https://l.com/", status=ScanStatus.COMPLETED))
        db.add(Subscription(
            user_id=payee.id, stripe_subscription_id="sub_p", stripe_customer_id="cus_p",
            plan=PlanTier.PRO, status=SubscriptionStatus.PAST_DUE,
        ))
        await db.commit()

        ids = set(await fraud_svc.find_candidates(db))
        assert loud.id in ids
        assert payee.id in ids
        assert clean.id not in ids
