# WebHound — apps/api/tests/test_public_scan.py
# Slice 4.A — guest /public/scan flow tests.
#
# Verifies the URL → guest-Website → ScanJob → token path without
# actually hitting Celery (the run_scan import is patched out so
# tests don't need a broker). Confirms the architecture-rule
# invariants:
#   * the public flow reuses the existing ScanJob + Website tables
#     (no parallel models)
#   * lookups are token-scoped
#   * IP rate limit is enforced per the G4 spec (3/IP/day)
#   * malformed input raises plain-English 400s

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.models.enums import ScanProfile, ScanStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.website import Website
from apps.api.services.public_scan import (
    ClaimError,
    PublicScanError,
    _normalise_url,
    claim_guest_scan,
    create_guest_scan,
    get_guest_scan_status,
)

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------


def test_normalise_url_adds_https() -> None:
    assert _normalise_url("acme-cafe.com") == "https://acme-cafe.com"


def test_normalise_url_keeps_https() -> None:
    assert _normalise_url("https://Acme.example/Foo") == "https://acme.example/Foo"


def test_normalise_url_rejects_empty() -> None:
    with pytest.raises(PublicScanError):
        _normalise_url("")


def test_normalise_url_rejects_invalid_hostname() -> None:
    with pytest.raises(PublicScanError):
        _normalise_url("not-a-domain")


def test_normalise_url_rejects_localhost() -> None:
    with pytest.raises(PublicScanError):
        _normalise_url("http://localhost:8000/")
    with pytest.raises(PublicScanError):
        _normalise_url("http://127.0.0.1/")


# ---------------------------------------------------------------------------
# create_guest_scan + get_guest_scan_status
# ---------------------------------------------------------------------------


def _fake_celery_task() -> MagicMock:
    task = MagicMock()
    task.id = "test-task-id"
    return task


@pytest.mark.asyncio
async def test_create_guest_scan_creates_website_and_job(db_engine) -> None:
    """Guest scan creates a Website with user_id=None and a
    ScanJob with guest_token set — same tables authenticated
    scans use, with the discriminator in two columns."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        with patch(
            "apps.api.services.public_scan.check_rate",
            new=_unlimited_rate_check(),
        ), patch(
            "worker.scan_tasks.run_scan",
            new=MagicMock(delay=MagicMock(return_value=_fake_celery_task())),
        ):
            payload = await create_guest_scan(
                db, raw_url="acme-cafe.com", client_ip="203.0.113.5",
            )
    assert payload["status"] == "queued"
    assert payload["target_url"] == "https://acme-cafe.com"
    assert payload["profile"] == ScanProfile.QUICK.value
    assert uuid.UUID(payload["guest_token"])
    # Sanity-check the DB shape.
    async with factory() as db:
        job = await db.scalar(sa.select(ScanJob))
        assert job is not None
        assert job.guest_token is not None
        assert job.profile == ScanProfile.QUICK
        assert job.save_baseline is False
        site = await db.get(Website, job.website_id)
        assert site is not None
        assert site.user_id is None        # guest pattern
        assert site.hostname == "acme-cafe.com"


@pytest.mark.asyncio
async def test_create_guest_scan_rejects_when_rate_limited(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        with patch(
            "apps.api.services.public_scan.check_rate",
            new=_denied_rate_check(),
        ):
            with pytest.raises(PublicScanError) as exc:
                await create_guest_scan(
                    db, raw_url="acme-cafe.com",
                    client_ip="203.0.113.5",
                )
    assert "3 scans" in str(exc.value)


@pytest.mark.asyncio
async def test_get_guest_scan_status_returns_none_for_unknown(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        out = await get_guest_scan_status(db, uuid.uuid4())
        assert out is None


@pytest.mark.asyncio
async def test_get_guest_scan_status_returns_queued_state(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        with patch(
            "apps.api.services.public_scan.check_rate",
            new=_unlimited_rate_check(),
        ), patch(
            "worker.scan_tasks.run_scan",
            new=MagicMock(delay=MagicMock(return_value=_fake_celery_task())),
        ):
            payload = await create_guest_scan(
                db, raw_url="acme-cafe.com", client_ip="203.0.113.5",
            )
    token = uuid.UUID(payload["guest_token"])
    async with factory() as db:
        out = await get_guest_scan_status(db, token)
        assert out is not None
        assert out["status"] == "queued"
        assert out["target_url"] == "https://acme-cafe.com"
        # No result yet because the scan hasn't completed.
        assert out["result"] is None


# ---------------------------------------------------------------------------
# Helpers — fake rate-limit decisions so we don't need Redis.
# ---------------------------------------------------------------------------


def _unlimited_rate_check():
    from apps.api.rate_limit import RateDecision

    async def _ok(key, *, limit, window_seconds):
        return RateDecision(allowed=True, remaining=limit - 1, reset_seconds=0)
    return _ok


def _denied_rate_check():
    from apps.api.rate_limit import RateDecision

    async def _no(key, *, limit, window_seconds):
        return RateDecision(allowed=False, remaining=0, reset_seconds=window_seconds)
    return _no


# ---------------------------------------------------------------------------
# Slice 4.C — claim
# ---------------------------------------------------------------------------


async def _make_user(db) -> tuple[uuid.UUID, str]:
    from apps.api.models.enums import PlanTier
    from apps.api.models.user import User
    from apps.api.security import hash_password

    u = User(
        email=f"u-{uuid.uuid4()}@x.test",
        hashed_password=hash_password("pw"),
        is_active=True, plan=PlanTier.FREE,
    )
    db.add(u)
    await db.flush()
    return u.id, u.email


async def _seed_guest_scan(db) -> uuid.UUID:
    with patch(
        "apps.api.services.public_scan.check_rate",
        new=_unlimited_rate_check(),
    ), patch(
        "worker.scan_tasks.run_scan",
        new=MagicMock(delay=MagicMock(return_value=_fake_celery_task())),
    ):
        payload = await create_guest_scan(
            db, raw_url="acme-cafe.com", client_ip="203.0.113.5",
        )
    return uuid.UUID(payload["guest_token"])


@pytest.mark.asyncio
async def test_claim_attaches_website_to_user(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        user_id, _ = await _make_user(db)
        token = await _seed_guest_scan(db)
        out = await claim_guest_scan(db, guest_token=token, user_id=user_id)
        assert out["status"] == "queued"
        site = await db.scalar(sa.select(Website).limit(1))
        assert site is not None
        assert site.user_id == user_id


@pytest.mark.asyncio
async def test_claim_is_idempotent_for_same_user(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        user_id, _ = await _make_user(db)
        token = await _seed_guest_scan(db)
        await claim_guest_scan(db, guest_token=token, user_id=user_id)
        # Second claim by same user: succeeds, no-op.
        out = await claim_guest_scan(db, guest_token=token, user_id=user_id)
        assert out["status"] == "queued"


@pytest.mark.asyncio
async def test_claim_unknown_token_raises(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        user_id, _ = await _make_user(db)
        with pytest.raises(ClaimError):
            await claim_guest_scan(
                db, guest_token=uuid.uuid4(), user_id=user_id,
            )


@pytest.mark.asyncio
async def test_claim_rejects_different_user(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u1, _ = await _make_user(db)
        u2, _ = await _make_user(db)
        token = await _seed_guest_scan(db)
        await claim_guest_scan(db, guest_token=token, user_id=u1)
        with pytest.raises(ClaimError):
            await claim_guest_scan(db, guest_token=token, user_id=u2)
