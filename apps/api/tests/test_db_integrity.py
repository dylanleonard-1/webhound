"""Database integrity: cascade deletes, unique constraints, and ownership isolation."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import apps.api.models  # noqa: F401
from apps.api.database import Base
from apps.api.models.baseline import BaselineRecord
from apps.api.models.enums import (
    NotificationSeverity,
    NotificationType,
    ScanProfile,
    ScanStatus,
    VerificationStatus,
)
from apps.api.models.finding import FindingRecord
from apps.api.models.notification import Notification
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.user import User
from apps.api.models.website import Website

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="module")
async def db_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def session(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as s:
        yield s
        await s.rollback()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user() -> User:
    return User(email=f"u{uuid.uuid4().hex[:8]}@example.com", is_active=True)


def _website(url: str | None = None, user_id=None) -> Website:
    url = url or f"https://{uuid.uuid4().hex[:8]}.example.com"
    hostname = url.split("//", 1)[1].rstrip("/")
    return Website(
        url=url,
        hostname=hostname,
        scheme="https",
        verification_status=VerificationStatus.UNVERIFIED,
        user_id=user_id,
    )


def _scan_job(website_id) -> ScanJob:
    return ScanJob(
        website_id=website_id,
        status=ScanStatus.QUEUED,
        profile=ScanProfile.STANDARD,
        requested_url="https://example.com",
    )


def _scan_result(scan_job_id) -> ScanResultRecord:
    return ScanResultRecord(
        scan_job_id=scan_job_id,
        risk_score=50,
        risk_level="medium",
        pages_crawled=1,
        total_findings=0,
        actionable_findings=0,
        severity_breakdown={},
    )


def _notification(user_id) -> Notification:
    return Notification(
        user_id=user_id,
        type=NotificationType.SCAN_COMPLETED,
        severity=NotificationSeverity.INFO,
        title="Scan complete",
        message="Your scan finished.",
    )


# ---------------------------------------------------------------------------
# Cascade delete tests
# ---------------------------------------------------------------------------


async def test_delete_user_cascades_to_websites(session: AsyncSession):
    user = _user()
    session.add(user)
    await session.flush()

    website = _website(user_id=user.id)
    session.add(website)
    await session.flush()
    website_id = website.id

    await session.delete(user)
    await session.flush()

    assert await session.get(Website, website_id) is None


async def test_delete_website_cascades_to_scan_jobs(session: AsyncSession):
    website = _website()
    session.add(website)
    await session.flush()

    job = _scan_job(website.id)
    session.add(job)
    await session.flush()
    job_id = job.id

    await session.delete(website)
    await session.flush()

    assert await session.get(ScanJob, job_id) is None


async def test_delete_website_cascades_to_baselines(session: AsyncSession):
    website = _website()
    session.add(website)
    await session.flush()

    baseline = BaselineRecord(
        website_id=website.id,
        baseline_id="bl_cascade",
        baseline_version=1,
        baseline_json={},
    )
    session.add(baseline)
    await session.flush()
    baseline_id = baseline.id

    await session.delete(website)
    await session.flush()

    assert await session.get(BaselineRecord, baseline_id) is None


async def test_delete_user_cascades_to_notifications(session: AsyncSession):
    user = _user()
    session.add(user)
    await session.flush()

    notif = _notification(user.id)
    session.add(notif)
    await session.flush()
    notif_id = notif.id

    await session.delete(user)
    await session.flush()

    assert await session.get(Notification, notif_id) is None


async def test_delete_scan_result_cascades_to_findings(session: AsyncSession):
    website = _website()
    session.add(website)
    await session.flush()

    job = _scan_job(website.id)
    session.add(job)
    await session.flush()

    result = _scan_result(job.id)
    session.add(result)
    await session.flush()

    finding = FindingRecord(
        scan_result_id=result.id,
        title="Test Finding",
        severity="low",
        category="header",
        scanner_engine="test",
    )
    session.add(finding)
    await session.flush()
    finding_id = finding.id

    await session.delete(result)
    await session.flush()

    assert await session.get(FindingRecord, finding_id) is None


async def test_full_cascade_chain_user_website_job(session: AsyncSession):
    user = _user()
    session.add(user)
    await session.flush()

    website = _website(user_id=user.id)
    session.add(website)
    await session.flush()

    job = _scan_job(website.id)
    session.add(job)
    await session.flush()
    website_id, job_id = website.id, job.id

    await session.delete(user)
    await session.flush()

    assert await session.get(Website, website_id) is None
    assert await session.get(ScanJob, job_id) is None


# ---------------------------------------------------------------------------
# Unique constraint tests
# ---------------------------------------------------------------------------


async def test_duplicate_website_url_rejected(session: AsyncSession):
    url = f"https://dup-{uuid.uuid4().hex[:8]}.com"
    session.add(_website(url=url))
    await session.flush()
    session.add(_website(url=url))
    with pytest.raises(IntegrityError):
        await session.flush()


async def test_duplicate_baseline_version_rejected(session: AsyncSession):
    website = _website()
    session.add(website)
    await session.flush()

    session.add(BaselineRecord(website_id=website.id, baseline_id="a", baseline_version=1, baseline_json={}))
    await session.flush()
    session.add(BaselineRecord(website_id=website.id, baseline_id="b", baseline_version=1, baseline_json={}))
    with pytest.raises(IntegrityError):
        await session.flush()


async def test_one_scan_result_per_scan_job(session: AsyncSession):
    website = _website()
    session.add(website)
    await session.flush()

    job = _scan_job(website.id)
    session.add(job)
    await session.flush()

    session.add(_scan_result(job.id))
    await session.flush()
    session.add(_scan_result(job.id))
    with pytest.raises(IntegrityError):
        await session.flush()


async def test_different_websites_can_share_baseline_version(session: AsyncSession):
    w1 = _website()
    w2 = _website()
    session.add_all([w1, w2])
    await session.flush()

    bl1 = BaselineRecord(website_id=w1.id, baseline_id="v1", baseline_version=1, baseline_json={})
    bl2 = BaselineRecord(website_id=w2.id, baseline_id="v1", baseline_version=1, baseline_json={})
    session.add_all([bl1, bl2])
    await session.flush()  # no IntegrityError — constraint is (website_id, version)


# ---------------------------------------------------------------------------
# Notification ownership isolation
# ---------------------------------------------------------------------------


async def test_notifications_isolated_per_user(session: AsyncSession):
    user_a = _user()
    user_b = _user()
    session.add_all([user_a, user_b])
    await session.flush()

    n_a = _notification(user_a.id)
    n_b = _notification(user_b.id)
    session.add_all([n_a, n_b])
    await session.flush()

    await session.refresh(user_a, ["notifications"])
    await session.refresh(user_b, ["notifications"])

    ids_a = {n.id for n in user_a.notifications}
    ids_b = {n.id for n in user_b.notifications}

    assert n_a.id in ids_a
    assert n_b.id not in ids_a
    assert n_b.id in ids_b
    assert n_a.id not in ids_b


# ---------------------------------------------------------------------------
# Migration syntax
# ---------------------------------------------------------------------------


def test_migration_0005_valid_python():
    import ast
    import os

    path = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "migrations",
            "versions",
            "0005_indexes_constraints_cascade.py",
        )
    )
    with open(path) as fh:
        source = fh.read()
    tree = ast.parse(source)
    fn_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assert "upgrade" in fn_names
    assert "downgrade" in fn_names
