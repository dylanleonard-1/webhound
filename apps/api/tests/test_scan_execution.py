"""Scan execution tests — Celery task integration with mocked scanner."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import apps.api.models  # noqa: F401
from apps.api.database import Base
from apps.api.models.enums import ScanStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.services.result_persistence import persist_scan_result

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest.fixture
def mock_scan_result():
    """Build a minimal ScanResult-like object as the scanner would return."""
    severity_breakdown = MagicMock()
    severity_breakdown.model_dump.return_value = {
        "critical": 0, "high": 1, "medium": 2, "low": 0, "info": 3,
    }

    finding = MagicMock()
    finding.id = uuid.uuid4()
    finding.title = "Missing Content-Security-Policy"
    finding.severity = MagicMock()
    finding.severity.value = "high"
    finding.category = MagicMock()
    finding.category.value = "security_header"
    finding.scanner_engine = "security_headers"
    finding.confidence = 1.0
    finding.description = "CSP header not present."
    finding.remediation = "Add a Content-Security-Policy header."
    finding.evidence = []
    finding.framework = MagicMock()
    finding.framework.model_dump.return_value = {}

    grouped = MagicMock()
    grouped.title = "Missing Content-Security-Policy"
    grouped.severity = MagicMock()
    grouped.severity.value = "high"
    grouped.category = MagicMock()
    grouped.category.value = "security_header"
    grouped.scanner_engine = "security_headers"
    grouped.affected_url_count = 5
    grouped.affected_urls = ["https://example.com/", "https://example.com/about"]
    grouped.evidence_count = 5
    grouped.confidence = 1.0
    grouped.description = "Content-Security-Policy header is missing, allowing XSS and injection attacks."
    grouped.remediation = "Add Content-Security-Policy."
    grouped.framework = MagicMock()
    grouped.framework.model_dump.return_value = {}
    grouped.finding_ids = [str(finding.id)]

    diag = MagicMock()
    diag.name = "security_headers"
    diag.category = "headers"
    diag.status = MagicMock()
    diag.status.value = "findings"
    diag.findings_count = 5
    diag.severity_counts = {"critical": 0, "high": 5, "medium": 0, "low": 0, "info": 0}
    diag.duration_ms = 42.0
    diag.skipped_reason = None
    diag.error_message = None

    result = MagicMock()
    result.id = uuid.uuid4()
    result.status = MagicMock()
    result.status.value = "completed"
    result.findings = [finding]
    result.active_findings = [finding]
    result.grouped_findings = [grouped]
    result.engine_diagnostics = [diag]
    result.severity_breakdown = severity_breakdown
    result.urls_crawled = 10
    result.duration_seconds = 3.14
    result.errors = []
    result.metadata = {
        "risk_score": 70,
        "risk_level": "medium",
        "external_domains": ["cdn.example.com"],
    }
    return result


@pytest.fixture
async def scan_job(db_session: AsyncSession):
    """Create a queued scan job in the test database."""
    from apps.api.models.website import Website

    website = Website(
        url="https://example.com",
        hostname="example.com",
        scheme="https",
    )
    db_session.add(website)
    await db_session.flush()

    job = ScanJob(
        website_id=website.id,
        profile="standard",
        requested_url="https://example.com",
        status=ScanStatus.QUEUED,
    )
    db_session.add(job)
    await db_session.flush()
    await db_session.refresh(job)
    return job


# ---------------------------------------------------------------------------
# result_persistence tests
# ---------------------------------------------------------------------------


async def test_persist_scan_result_creates_record(db_session, scan_job, mock_scan_result):
    record = await persist_scan_result(db_session, scan_job.id, mock_scan_result)
    assert isinstance(record, ScanResultRecord)
    assert record.scan_job_id == scan_job.id


async def test_persist_scan_result_risk_score(db_session, scan_job, mock_scan_result):
    record = await persist_scan_result(db_session, scan_job.id, mock_scan_result)
    assert record.risk_score == 70
    assert record.risk_level == "medium"


async def test_persist_scan_result_pages_crawled(db_session, scan_job, mock_scan_result):
    record = await persist_scan_result(db_session, scan_job.id, mock_scan_result)
    assert record.pages_crawled == 10


async def test_persist_scan_result_finding_counts(db_session, scan_job, mock_scan_result):
    record = await persist_scan_result(db_session, scan_job.id, mock_scan_result)
    assert record.total_findings == 1
    assert record.actionable_findings == 1


async def test_persist_scan_result_severity_breakdown(db_session, scan_job, mock_scan_result):
    record = await persist_scan_result(db_session, scan_job.id, mock_scan_result)
    assert record.severity_breakdown["high"] == 1


async def test_persist_scan_result_scanner_metadata(db_session, scan_job, mock_scan_result):
    record = await persist_scan_result(db_session, scan_job.id, mock_scan_result)
    # risk_score/risk_level should be top-level, not duplicated in scanner_metadata
    assert "risk_score" not in (record.scanner_metadata or {})
    assert "external_domains" in (record.scanner_metadata or {})


async def test_persist_scan_result_creates_finding_records(db_session, scan_job, mock_scan_result):
    record = await persist_scan_result(db_session, scan_job.id, mock_scan_result)
    await db_session.refresh(record, ["findings"])
    assert len(record.findings) == 1
    assert record.findings[0].title == "Missing Content-Security-Policy"
    assert record.findings[0].severity == "high"


async def test_persist_scan_result_creates_grouped_findings(db_session, scan_job, mock_scan_result):
    record = await persist_scan_result(db_session, scan_job.id, mock_scan_result)
    await db_session.refresh(record, ["grouped_findings"])
    assert len(record.grouped_findings) == 1
    assert record.grouped_findings[0].affected_url_count == 5


async def test_persist_scan_result_creates_engine_diagnostics(db_session, scan_job, mock_scan_result):
    record = await persist_scan_result(db_session, scan_job.id, mock_scan_result)
    await db_session.refresh(record, ["engine_diagnostics"])
    assert len(record.engine_diagnostics) == 1
    assert record.engine_diagnostics[0].engine_name == "security_headers"
    assert record.engine_diagnostics[0].duration_ms == 42.0


# ---------------------------------------------------------------------------
# run_scan Celery task — mocked scanner
# ---------------------------------------------------------------------------


async def test_run_scan_task_transitions_to_running_then_completed(
    db_engine, mock_scan_result
):
    from apps.api.models.website import Website
    from worker.scan_tasks import _execute

    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async with factory() as db:
        website = Website(url="https://example.com", hostname="example.com", scheme="https")
        db.add(website)
        await db.flush()
        job = ScanJob(
            website_id=website.id,
            profile="standard",
            requested_url="https://example.com",
            status=ScanStatus.QUEUED,
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        job_id = str(job.id)

    mock_scan_result.status.value = "completed"
    mock_scanner = AsyncMock()
    mock_scanner.scan.return_value = mock_scan_result

    with (
        patch("worker.scan_tasks.Scanner", return_value=mock_scanner),
        patch("worker.scan_tasks.Target"),
        patch("worker.scan_tasks.get_profile") as mock_profile,
    ):
        mock_profile.return_value.to_scan_options.return_value = MagicMock()
        result = await _execute(
            job_id, "https://example.com", "standard", _session_factory=factory
        )

    assert result["job_id"] == job_id
    assert result["risk_score"] == 70

    async with factory() as db:
        updated_job = await db.get(ScanJob, uuid.UUID(job_id))
        assert updated_job.status == ScanStatus.COMPLETED


async def test_run_scan_task_marks_failed_on_scanner_failure(db_engine, mock_scan_result):
    from apps.api.models.website import Website
    from worker.scan_tasks import _execute

    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async with factory() as db:
        website = Website(url="https://fail.example.com", hostname="fail.example.com", scheme="https")
        db.add(website)
        await db.flush()
        job = ScanJob(
            website_id=website.id,
            profile="standard",
            requested_url="https://fail.example.com",
            status=ScanStatus.QUEUED,
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        job_id = str(job.id)

    mock_scan_result.status.value = "failed"
    error_obj = MagicMock()
    error_obj.message = "connection refused"
    mock_scan_result.errors = [error_obj]
    mock_scanner = AsyncMock()
    mock_scanner.scan.return_value = mock_scan_result

    with (
        patch("worker.scan_tasks.Scanner", return_value=mock_scanner),
        patch("worker.scan_tasks.Target"),
        patch("worker.scan_tasks.get_profile") as mock_profile,
    ):
        mock_profile.return_value.to_scan_options.return_value = MagicMock()
        await _execute(
            job_id, "https://fail.example.com", "standard", _session_factory=factory
        )

    async with factory() as db:
        updated_job = await db.get(ScanJob, uuid.UUID(job_id))
        assert updated_job.status == ScanStatus.FAILED
        assert updated_job.error_message == "connection refused"


async def test_run_scan_task_skips_non_queued_job(db_engine):
    from apps.api.models.website import Website

    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async with factory() as db:
        website = Website(url="https://skip.example.com", hostname="skip.example.com", scheme="https")
        db.add(website)
        await db.flush()
        job = ScanJob(
            website_id=website.id,
            profile="standard",
            requested_url="https://skip.example.com",
            status=ScanStatus.RUNNING,
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        job_id = str(job.id)

    from worker.scan_tasks import _execute

    result = await _execute(
        job_id, "https://skip.example.com", "standard", _session_factory=factory
    )

    assert result.get("skipped") is True


async def test_run_scan_task_raises_on_missing_job(db_engine):
    from worker.scan_tasks import _execute

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    missing_id = str(uuid.uuid4())

    with pytest.raises(RuntimeError, match="scan job not found"):
        await _execute(
            missing_id, "https://example.com", "standard", _session_factory=factory
        )


# ---------------------------------------------------------------------------
# POST /scan-jobs enqueue behaviour
# ---------------------------------------------------------------------------


async def test_create_scan_job_enqueues_celery_task(_mock_celery_task, db_engine, _test_user):
    """POST /scan-jobs should call run_scan.delay once."""
    from httpx import ASGITransport, AsyncClient

    from apps.api.database import get_db
    from apps.api.main import app
    from apps.api.security import get_current_user

    engine = db_engine
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _override():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override
    app.dependency_overrides[get_current_user] = lambda: _test_user
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            r = await c.post("/websites", json={"url": "https://example.com"})
            assert r.status_code == 201
            website_id = r.json()["id"]

            r = await c.post(
                "/scan-jobs", json={"website_id": website_id, "profile": "quick"}
            )
            assert r.status_code == 201
    finally:
        app.dependency_overrides.clear()

    _mock_celery_task.delay.assert_called_once()
    call_args = _mock_celery_task.delay.call_args
    assert call_args.args[1].startswith("https://example.com")
    assert call_args.args[2] == "quick"


async def test_create_scan_job_stores_celery_task_id(_mock_celery_task, db_engine, _test_user):
    """celery_task_id should be set in the response when enqueue succeeds."""
    from httpx import ASGITransport, AsyncClient

    from apps.api.database import get_db
    from apps.api.main import app
    from apps.api.security import get_current_user

    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def _override():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override
    app.dependency_overrides[get_current_user] = lambda: _test_user
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            r = await c.post("/websites", json={"url": "https://celery-id.example.com"})
            website_id = r.json()["id"]
            r = await c.post("/scan-jobs", json={"website_id": website_id})
            body = r.json()
    finally:
        app.dependency_overrides.clear()

    assert body["celery_task_id"] == "test-celery-task-id"
