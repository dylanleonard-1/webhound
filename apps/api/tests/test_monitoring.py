# WebHound — apps/api/tests/test_monitoring.py
# Phase-4 continuous-monitoring hook tests.
#
# Validates: handle_scan_completion produces a baseline ScanDelta on the
# first scan, computes a real delta on the second scan, dispatches a
# drift alert when severity ≥ MEDIUM, and stays a no-op when the
# current scan job has no result.

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.models.alert import Alert
from apps.api.models.enums import (
    DriftSeverity,
    PlanTier,
    ScanStatus,
    VerificationStatus,
)
from apps.api.models.scan_delta import ScanDelta
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.security import hash_password
from apps.api.services.monitoring import handle_scan_completion


pytestmark = pytest.mark.anyio


async def _bootstrap(db) -> tuple[User, Website]:
    user = User(email=f"u-{uuid.uuid4()}@x.test",
                hashed_password=hash_password("pw"),
                is_active=True, plan=PlanTier.FREE)
    db.add(user)
    await db.flush()
    site = Website(
        user_id=user.id, url="https://target.example/",
        hostname="target.example", scheme="https",
        verification_status=VerificationStatus.VERIFIED,
    )
    db.add(site)
    await db.flush()
    return user, site


async def _make_completed_scan(
    db, website_id: uuid.UUID, *, metadata: dict, risk_score: int = 50,
    severity_breakdown: dict | None = None,
) -> ScanJob:
    job = ScanJob(
        website_id=website_id,
        status=ScanStatus.COMPLETED,
        requested_url="https://target.example/",
        completed_at=datetime.now(timezone.utc),
    )
    db.add(job)
    await db.flush()
    result = ScanResultRecord(
        scan_job_id=job.id,
        risk_score=risk_score,
        risk_level="low",
        pages_crawled=3,
        total_findings=0,
        actionable_findings=0,
        severity_breakdown=severity_breakdown or {},
        scanner_metadata=metadata,
    )
    db.add(result)
    await db.flush()
    return job


@pytest.mark.asyncio
async def test_first_scan_produces_baseline_delta_no_alert(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        _, site = await _bootstrap(db)
        job = await _make_completed_scan(
            db, site.id,
            metadata={"external_domains": ["cdn.example.com"]},
        )
        await db.commit()
    async with factory() as db:
        delta = await handle_scan_completion(
            db, scan_job_id=job.id, website_id=site.id,
        )
        await db.commit()
        assert delta is not None
        assert delta.drift_severity == DriftSeverity.NONE
        # No alerts on baseline.
        alert_count = await db.scalar(sa.select(sa.func.count(Alert.id)))
        assert alert_count == 0


@pytest.mark.asyncio
async def test_second_scan_with_new_domains_creates_delta_row(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        _, site = await _bootstrap(db)
        await _make_completed_scan(
            db, site.id,
            metadata={"external_domains": ["a.example.com"]},
        )
        job2 = await _make_completed_scan(
            db, site.id,
            metadata={"external_domains": [
                "a.example.com", "b.example.com",
            ]},
        )
        await db.commit()
    async with factory() as db:
        delta = await handle_scan_completion(
            db, scan_job_id=job2.id, website_id=site.id,
        )
        await db.commit()
        assert delta is not None
        # LOW for 1 new domain — see compute_delta heuristic.
        assert delta.drift_severity == DriftSeverity.LOW
        # No alert for LOW (anti-fatigue rule).
        alert_count = await db.scalar(sa.select(sa.func.count(Alert.id)))
        assert alert_count == 0
        # But a ScanDelta row IS persisted.
        delta_count = await db.scalar(sa.select(sa.func.count(ScanDelta.id)))
        assert delta_count == 1


@pytest.mark.asyncio
async def test_tls_drift_dispatches_critical_alert(db_engine) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        _, site = await _bootstrap(db)
        await _make_completed_scan(
            db, site.id,
            metadata={"tls_summary": {"min_tls_version": "TLSv1.2"}},
        )
        job2 = await _make_completed_scan(
            db, site.id,
            metadata={"tls_summary": {"min_tls_version": "TLSv1.0"}},
        )
        await db.commit()
    async with factory() as db:
        delta = await handle_scan_completion(
            db, scan_job_id=job2.id, website_id=site.id,
        )
        await db.commit()
        assert delta.drift_severity == DriftSeverity.CRITICAL
        # Exactly one alert was raised.
        alerts = (await db.execute(sa.select(Alert))).scalars().all()
        assert len(alerts) == 1
        a = alerts[0]
        assert a.severity == "critical"
        assert a.source == "monitoring"
        assert a.dedup_key == f"monitoring:drift:{site.id}"
        assert a.target_id == str(site.id)
        assert a.detail.get("changed_tls") is True


@pytest.mark.asyncio
async def test_repeat_drift_dedups_via_upsert(db_engine) -> None:
    """Two consecutive critical-drift scans must produce ONE alert with
    occurrences=2, not two distinct alerts. This is the anti-fatigue
    guarantee for the recurring-drift case."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        _, site = await _bootstrap(db)
        await _make_completed_scan(
            db, site.id,
            metadata={"tls_summary": {"min_tls_version": "TLSv1.2"}},
        )
        job2 = await _make_completed_scan(
            db, site.id,
            metadata={"tls_summary": {"min_tls_version": "TLSv1.0"}},
        )
        await db.commit()
    async with factory() as db:
        await handle_scan_completion(
            db, scan_job_id=job2.id, website_id=site.id,
        )
        await db.commit()
    async with factory() as db:
        job3 = await _make_completed_scan(
            db, site.id,
            metadata={"tls_summary": {"min_tls_version": "TLSv1.1"}},
        )
        await db.commit()
    async with factory() as db:
        await handle_scan_completion(
            db, scan_job_id=job3.id, website_id=site.id,
        )
        await db.commit()
        # Still exactly one alert row, occurrences should be 2.
        alerts = (await db.execute(sa.select(Alert))).scalars().all()
        assert len(alerts) == 1
        assert alerts[0].occurrences == 2


@pytest.mark.asyncio
async def test_handle_scan_completion_swallows_errors(db_engine) -> None:
    """Even if no result row exists yet (mid-flight), the hook returns
    None and never raises — the scan is allowed to keep its COMPLETED
    status."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        _, site = await _bootstrap(db)
        job = ScanJob(
            website_id=site.id, status=ScanStatus.COMPLETED,
            requested_url="https://target.example/",
            completed_at=datetime.now(timezone.utc),
        )
        db.add(job)
        await db.commit()
    async with factory() as db:
        # No ScanResultRecord exists — return must be None, no raise.
        delta = await handle_scan_completion(
            db, scan_job_id=job.id, website_id=site.id,
        )
        assert delta is None
