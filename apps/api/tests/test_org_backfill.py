# WebHound — apps/api/tests/test_org_backfill.py
# Phase-4 slice 3: scan job / schedule org_id inheritance + drift audit.

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.models.enums import (
    PlanTier, ScanProfile, ScheduleFrequency, VerificationStatus,
)
from apps.api.models.org import Org, OrgMembership
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_schedule import ScanSchedule
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.schemas.scan_jobs import ScanJobCreate
from apps.api.schemas.scan_schedules import ScanScheduleCreate
from apps.api.security import hash_password
from apps.api.services.orgs import audit_org_id_drift
from apps.api.services.scan_jobs import create_scan_job
from apps.api.services.scan_schedules import create_schedule


pytestmark = pytest.mark.anyio


async def _user(db, email: str = "u@x.test") -> User:
    u = User(email=email, hashed_password=hash_password("pw"),
             is_active=True, plan=PlanTier.FREE)
    db.add(u)
    await db.flush()
    return u


async def _website(db, *, user_id, org_id=None,
                    hostname="target.example") -> Website:
    w = Website(
        user_id=user_id, url=f"https://{hostname}/",
        hostname=hostname, scheme="https",
        verification_status=VerificationStatus.VERIFIED,
        org_id=org_id,
    )
    db.add(w)
    await db.flush()
    return w


@pytest.mark.asyncio
async def test_create_scan_job_inherits_org_from_website(db_engine) -> None:
    """A new scan job born under a website that has org_id must inherit it."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        org = Org(slug="acme", name="Acme", plan_tier=PlanTier.FREE)
        db.add(org)
        await db.flush()
        site = await _website(db, user_id=u.id, org_id=org.id)
        await db.commit()
        job = await create_scan_job(
            db, ScanJobCreate(
                website_id=site.id, profile=ScanProfile.STANDARD,
                use_latest_baseline=False, save_baseline=True,
            ),
            user_id=u.id,
        )
        await db.commit()
        assert job.org_id == org.id


@pytest.mark.asyncio
async def test_create_scan_job_org_id_none_when_website_unscoped(db_engine) -> None:
    """A legacy website (org_id NULL) still produces NULL-org_id jobs.
    Backwards-compat invariant — operators haven't completed cutover."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        site = await _website(db, user_id=u.id, org_id=None)
        await db.commit()
        job = await create_scan_job(
            db, ScanJobCreate(
                website_id=site.id, profile=ScanProfile.STANDARD,
                use_latest_baseline=False, save_baseline=True,
            ),
            user_id=u.id,
        )
        await db.commit()
        assert job.org_id is None


@pytest.mark.asyncio
async def test_create_schedule_inherits_org_from_website(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        org = Org(slug="acme", name="Acme", plan_tier=PlanTier.FREE)
        db.add(org)
        await db.flush()
        site = await _website(db, user_id=u.id, org_id=org.id)
        await db.commit()
        sch = await create_schedule(
            db,
            ScanScheduleCreate(
                website_id=site.id,
                profile=ScanProfile.STANDARD,
                frequency=ScheduleFrequency.DAILY,
                is_enabled=True,
                use_latest_baseline=True,
                save_baseline=True,
                next_run_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ),
            user_id=u.id,
        )
        await db.commit()
        assert sch.org_id == org.id


@pytest.mark.asyncio
async def test_audit_org_id_drift_clean(db_engine) -> None:
    """A fresh DB has zero drift."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        report = await audit_org_id_drift(db)
        assert report == {
            "websites_missing_org_with_owner": 0,
            "scan_jobs_org_mismatch": 0,
            "scan_jobs_missing_org_with_website_org": 0,
            "scan_schedules_missing_org_with_website_org": 0,
        }


@pytest.mark.asyncio
async def test_audit_org_id_drift_detects_mismatch(db_engine) -> None:
    """Manually create a scan job whose org_id doesn't match its
    website's — the audit must flag it. This is the integrity check
    that catches future code paths that forget to inherit."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        u = await _user(db)
        org_a = Org(slug="orga", name="A", plan_tier=PlanTier.FREE)
        org_b = Org(slug="orgb", name="B", plan_tier=PlanTier.FREE)
        db.add_all([org_a, org_b])
        await db.flush()
        site = await _website(db, user_id=u.id, org_id=org_a.id)
        # Manually inserted scan job with the WRONG org_id.
        bad_job = ScanJob(
            website_id=site.id, requested_url="https://x/",
            org_id=org_b.id,
        )
        db.add(bad_job)
        await db.commit()
    async with factory() as db:
        report = await audit_org_id_drift(db)
        assert report["scan_jobs_org_mismatch"] == 1
