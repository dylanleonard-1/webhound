"""Database-level model tests using async SQLite in-memory."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import apps.api.models  # noqa: F401 — registers all models
from apps.api.database import Base
from apps.api.models.baseline import BaselineRecord
from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.enums import (
    ReportFormat,
    ScanProfile,
    ScanStatus,
    VerificationMethod,
    VerificationStatus,
)
from apps.api.models.finding import FindingRecord
from apps.api.models.grouped_finding import GroupedFindingRecord
from apps.api.models.report import ReportRecord
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.user import User
from apps.api.models.website import DomainVerification, Website

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


async def _create_user(session: AsyncSession) -> User:
    user = User(email=f"u{uuid.uuid4().hex[:6]}@example.com", is_active=True)
    session.add(user)
    await session.flush()
    return user


async def _create_website(session: AsyncSession, user: User | None = None) -> Website:
    w = Website(
        url="https://example.com",
        hostname="example.com",
        scheme="https",
        verification_status=VerificationStatus.UNVERIFIED,
        user_id=user.id if user else None,
    )
    session.add(w)
    await session.flush()
    return w


async def _create_scan_job(session: AsyncSession, website: Website) -> ScanJob:
    job = ScanJob(
        website_id=website.id,
        status=ScanStatus.QUEUED,
        profile=ScanProfile.STANDARD,
        requested_url="https://example.com",
    )
    session.add(job)
    await session.flush()
    return job


async def _create_scan_result(
    session: AsyncSession, job: ScanJob
) -> ScanResultRecord:
    r = ScanResultRecord(
        scan_job_id=job.id,
        risk_score=85,
        risk_level="low",
        pages_crawled=1,
        total_findings=0,
        actionable_findings=0,
        severity_breakdown={},
    )
    session.add(r)
    await session.flush()
    return r


# ---------------------------------------------------------------------------
# Basic persistence
# ---------------------------------------------------------------------------


async def test_user_roundtrip(session):
    user = await _create_user(session)
    fetched = await session.get(User, user.id)
    assert fetched is not None
    assert fetched.email == user.email


async def test_website_roundtrip(session):
    w = await _create_website(session)
    fetched = await session.get(Website, w.id)
    assert fetched is not None
    assert fetched.hostname == "example.com"


async def test_scan_job_roundtrip(session):
    w = await _create_website(session)
    job = await _create_scan_job(session, w)
    fetched = await session.get(ScanJob, job.id)
    assert fetched is not None
    assert fetched.status == ScanStatus.QUEUED


async def test_scan_result_roundtrip(session):
    w = await _create_website(session)
    job = await _create_scan_job(session, w)
    result = await _create_scan_result(session, job)
    fetched = await session.get(ScanResultRecord, result.id)
    assert fetched is not None
    assert fetched.risk_score == 85


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------


async def test_user_website_relationship(session):
    user = await _create_user(session)
    w = await _create_website(session, user)
    await session.refresh(user, ["websites"])
    assert any(ws.id == w.id for ws in user.websites)


async def test_website_scan_job_relationship(session):
    w = await _create_website(session)
    job = await _create_scan_job(session, w)
    await session.refresh(w, ["scan_jobs"])
    assert any(j.id == job.id for j in w.scan_jobs)


async def test_scan_job_result_relationship(session):
    w = await _create_website(session)
    job = await _create_scan_job(session, w)
    result = await _create_scan_result(session, job)
    await session.refresh(job, ["result"])
    assert job.result is not None
    assert job.result.id == result.id


async def test_scan_result_findings_relationship(session):
    w = await _create_website(session)
    job = await _create_scan_job(session, w)
    result = await _create_scan_result(session, job)
    finding = FindingRecord(
        scan_result_id=result.id,
        title="Missing HSTS",
        severity="medium",
        category="security_header",
        scanner_engine="security_headers",
    )
    session.add(finding)
    await session.flush()
    await session.refresh(result, ["findings"])
    assert len(result.findings) == 1
    assert result.findings[0].title == "Missing HSTS"


async def test_scan_result_grouped_findings_relationship(session):
    w = await _create_website(session)
    job = await _create_scan_job(session, w)
    result = await _create_scan_result(session, job)
    gf = GroupedFindingRecord(
        scan_result_id=result.id,
        title="Missing HSTS (grouped)",
        severity="medium",
        category="security_header",
        scanner_engine="security_headers",
        affected_url_count=2,
        evidence_count=2,
    )
    session.add(gf)
    await session.flush()
    await session.refresh(result, ["grouped_findings"])
    assert len(result.grouped_findings) == 1


async def test_engine_diagnostic_relationship(session):
    w = await _create_website(session)
    job = await _create_scan_job(session, w)
    result = await _create_scan_result(session, job)
    diag = EngineDiagnosticRecord(
        scan_result_id=result.id,
        engine_name="csp_engine",
        status="ok",
        findings_count=0,
    )
    session.add(diag)
    await session.flush()
    await session.refresh(result, ["engine_diagnostics"])
    assert len(result.engine_diagnostics) == 1


async def test_baseline_relationship(session):
    w = await _create_website(session)
    bl = BaselineRecord(
        website_id=w.id,
        baseline_id="bl_001",
        baseline_version=1,
        baseline_json={"findings": []},
    )
    session.add(bl)
    await session.flush()
    await session.refresh(w, ["baselines"])
    assert len(w.baselines) == 1
    assert w.baselines[0].baseline_id == "bl_001"


async def test_report_relationship(session):
    w = await _create_website(session)
    job = await _create_scan_job(session, w)
    result = await _create_scan_result(session, job)
    report = ReportRecord(
        scan_result_id=result.id,
        format=ReportFormat.JSON,
        content_json={"summary": "ok"},
    )
    session.add(report)
    await session.flush()
    await session.refresh(result, ["reports"])
    assert len(result.reports) == 1
    assert result.reports[0].format == ReportFormat.JSON


async def test_domain_verification_relationship(session):
    w = await _create_website(session)
    dv = DomainVerification(
        website_id=w.id,
        method=VerificationMethod.DNS_TXT,
        token="verify-token-abc",
        status=VerificationStatus.PENDING,
    )
    session.add(dv)
    await session.flush()
    await session.refresh(w, ["domain_verifications"])
    assert len(w.domain_verifications) == 1
    assert w.domain_verifications[0].token == "verify-token-abc"


# ---------------------------------------------------------------------------
# Cascade deletes
# ---------------------------------------------------------------------------


async def test_website_cascade_deletes_scan_jobs(session):
    w = await _create_website(session)
    job = await _create_scan_job(session, w)
    job_id = job.id
    await session.delete(w)
    await session.flush()
    deleted = await session.get(ScanJob, job_id)
    assert deleted is None


async def test_scan_result_cascade_deletes_findings(session):
    w = await _create_website(session)
    job = await _create_scan_job(session, w)
    result = await _create_scan_result(session, job)
    finding = FindingRecord(
        scan_result_id=result.id,
        title="X",
        severity="low",
        category="header",
        scanner_engine="test",
    )
    session.add(finding)
    await session.flush()
    finding_id = finding.id
    await session.delete(result)
    await session.flush()
    deleted = await session.get(FindingRecord, finding_id)
    assert deleted is None


# ---------------------------------------------------------------------------
# Migration import
# ---------------------------------------------------------------------------


def test_migration_file_is_valid_python():
    import ast
    import os
    path = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "migrations",
            "versions",
            "0001_initial_schema.py",
        )
    )
    with open(path) as fh:
        source = fh.read()
    tree = ast.parse(source)
    fn_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assert "upgrade" in fn_names
    assert "downgrade" in fn_names
