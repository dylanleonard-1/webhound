# WebHound — apps/api/tests/test_notification_delivery.py
# FIX 6 — outbound email delivery for customer notifications.
#
# Self-contained: builds its own in-memory engine and does NOT import the
# FastAPI app, so it runs under `pytest --noconftest` without the app-import
# hang. Run:
#   .venv-api/Scripts/python -m pytest apps/api/tests/test_notification_delivery.py \
#       --noconftest -p no:cacheprovider -q

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import apps.api.models  # noqa: F401 — register models with Base.metadata
from apps.api.database import Base
from apps.api.models.enums import NotificationSeverity, NotificationType
from apps.api.models.notification import Notification
from apps.api.services import notification_delivery as nd
from apps.api.services.notification_delivery import EmailStatus

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _settings(**over):
    base = dict(
        notifications_enabled=True,
        resend_api_key="re_test",
        smtp_fallback_enabled=False,
        smtp_host="",
        frontend_url="http://localhost:3000",
    )
    base.update(over)
    return SimpleNamespace(**base)


async def _mk_notification(db, *, ntype=NotificationType.CRITICAL_FINDING,
                           user_id=None, website_id=None,
                           severity=NotificationSeverity.CRITICAL, **over):
    n = Notification(
        user_id=user_id or uuid.uuid4(),
        website_id=website_id,
        type=ntype,
        severity=severity,
        title="1 critical finding detected",
        message="A critical finding was found.",
        **over,
    )
    db.add(n)
    await db.flush()
    return n


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_eligible_types():
    assert nd.is_email_eligible(NotificationType.SCAN_FAILED)
    assert nd.is_email_eligible(NotificationType.CRITICAL_FINDING)
    assert nd.is_email_eligible(NotificationType.HIGH_RISK_FINDING)
    assert nd.is_email_eligible(NotificationType.WADE_ANOMALY)
    # in-app only — no email
    assert not nd.is_email_eligible(NotificationType.SCAN_COMPLETED)
    assert not nd.is_email_eligible(NotificationType.SCHEDULE_FAILED)


def test_provider_configured():
    assert nd.provider_configured(_settings(resend_api_key="re_x")) is True
    assert nd.provider_configured(
        _settings(resend_api_key="", smtp_fallback_enabled=True, smtp_host="mail")
    ) is True
    assert nd.provider_configured(
        _settings(resend_api_key="", smtp_fallback_enabled=False, smtp_host="")
    ) is False


def test_eligible_for_email_off_when_flag_disabled():
    ns = [SimpleNamespace(type=NotificationType.CRITICAL_FINDING)]
    assert nd.eligible_for_email(ns, settings=_settings(notifications_enabled=False)) == []
    assert nd.eligible_for_email(ns, settings=_settings(resend_api_key="", smtp_host="")) == []


def test_dedup_key_stable():
    uid, wid = uuid.uuid4(), uuid.uuid4()
    k1 = nd.compute_dedup_key(uid, NotificationType.CRITICAL_FINDING, wid)
    k2 = nd.compute_dedup_key(uid, NotificationType.CRITICAL_FINDING, wid)
    assert k1 == k2 and "critical_finding" in k1


# ---------------------------------------------------------------------------
# attempt_delivery — DB-backed
# ---------------------------------------------------------------------------

async def test_send_success_marks_sent(factory):
    sent = []
    async with factory() as db:
        n = await _mk_notification(db)
        status = await nd.attempt_delivery(
            db, n.id, "user@example.com", settings=_settings(),
            send=lambda *a: sent.append(a),
        )
        assert status == EmailStatus.SENT
        assert n.email_status == EmailStatus.SENT
        assert n.email_sent_at is not None
        assert len(sent) == 1


async def test_feature_off_marks_skipped_not_sent(factory):
    async with factory() as db:
        n = await _mk_notification(db)
        status = await nd.attempt_delivery(
            db, n.id, "user@example.com",
            settings=_settings(notifications_enabled=False),
            send=lambda *a: pytest.fail("should not send when feature off"),
        )
        assert status == EmailStatus.SKIPPED
        assert n.email_status == EmailStatus.SKIPPED


async def test_ineligible_type_skipped(factory):
    async with factory() as db:
        n = await _mk_notification(db, ntype=NotificationType.SCAN_COMPLETED,
                                   severity=NotificationSeverity.INFO)
        status = await nd.attempt_delivery(
            db, n.id, "user@example.com", settings=_settings(),
            send=lambda *a: pytest.fail("scan_completed must not email"),
        )
        assert status == EmailStatus.SKIPPED


async def test_duplicate_suppressed(factory):
    uid, wid = uuid.uuid4(), uuid.uuid4()
    async with factory() as db:
        # An already-sent email for the same (user, type, website) just now.
        prior = await _mk_notification(db, user_id=uid, website_id=wid)
        prior.email_status = EmailStatus.SENT
        prior.email_sent_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        await db.flush()

        n = await _mk_notification(db, user_id=uid, website_id=wid)
        status = await nd.attempt_delivery(
            db, n.id, "user@example.com", settings=_settings(),
            send=lambda *a: pytest.fail("duplicate must be suppressed"),
        )
        assert status == EmailStatus.SUPPRESSED
        assert n.email_status == EmailStatus.SUPPRESSED


async def test_failure_final_marks_failed(factory):
    def _boom(*a):
        raise RuntimeError("provider down")

    async with factory() as db:
        n = await _mk_notification(db)
        status = await nd.attempt_delivery(
            db, n.id, "user@example.com", settings=_settings(),
            is_final_attempt=True, send=_boom,
        )
        assert status == EmailStatus.FAILED
        assert n.email_status == EmailStatus.FAILED
        assert n.email_attempts == 1
        assert "provider down" in (n.email_last_error or "")


async def test_failure_non_final_raises_retryable(factory):
    def _boom(*a):
        raise RuntimeError("transient")

    async with factory() as db:
        n = await _mk_notification(db)
        with pytest.raises(nd.RetryableDeliveryError):
            await nd.attempt_delivery(
                db, n.id, "user@example.com", settings=_settings(),
                is_final_attempt=False, send=_boom,
            )
        assert n.email_status == EmailStatus.PENDING


async def test_already_sent_is_idempotent(factory):
    async with factory() as db:
        n = await _mk_notification(db)
        n.email_status = EmailStatus.SENT
        await db.flush()
        status = await nd.attempt_delivery(
            db, n.id, "user@example.com", settings=_settings(),
            send=lambda *a: pytest.fail("must not re-send an already-sent notification"),
        )
        assert status == EmailStatus.SENT
