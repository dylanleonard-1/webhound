# WebHound — apps/api/tests/test_admin_scan.py
# Internal/admin on-demand scan runner (services/admin_scan.py). Verifies the
# ownership/allowlist gate, profile handling (incl. baseline alias), audit
# requirements, and the telemetry read-back view. Hermetic (SQLite + the
# conftest's mocked broker/redis).

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.models.enums import ScanProfile, ScanStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.services import admin_scan
from apps.api.services.admin_scan import (
    AdminScanError,
    read_scan_telemetry,
    run_admin_scan,
)


@pytest.fixture
async def db(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest.fixture(autouse=True)
def _patch_broker(monkeypatch):
    """Patch the worker task the service enqueues so no real broker is hit."""
    mock = MagicMock()
    mock.delay.return_value = MagicMock(id="test-task-id")
    import worker.scan_tasks as wst
    monkeypatch.setattr(wst, "run_scan", mock)
    return mock


@pytest.fixture(autouse=True)
def _allowlist(monkeypatch):
    monkeypatch.setenv("WEBHOUND_INTERNAL_SCAN_ALLOWLIST", "webhoundsecurity.com")


# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_allowlisted_host_runs_deep(db, _patch_broker):
    out = await run_admin_scan(
        db, url="https://webhoundsecurity.com", profile="deep",
        reason="verify browser telemetry", triggered_by="internal-dev")
    await db.commit()
    assert out["profile"] == "deep"
    assert out["status"] == "queued"
    assert out["job_id"] == out["scan_id"]
    job = await db.get(ScanJob, __import__("uuid").UUID(out["job_id"]))
    assert job.profile == ScanProfile.DEEP
    assert job.status == ScanStatus.QUEUED
    _patch_broker.delay.assert_called_once()


@pytest.mark.anyio
async def test_non_allowlisted_rejected_without_test_mode(db):
    with pytest.raises(AdminScanError):
        await run_admin_scan(
            db, url="https://not-ours-example.com", profile="deep",
            reason="x", triggered_by="dev")


@pytest.mark.anyio
async def test_non_allowlisted_allowed_in_test_mode(db):
    out = await run_admin_scan(
        db, url="https://not-ours-example.com", profile="standard",
        reason="pentest engagement", triggered_by="dev",
        internal_test_mode=True)
    await db.commit()
    assert out["profile"] == "standard"


@pytest.mark.anyio
async def test_baseline_alias_maps_to_deep_with_save(db):
    out = await run_admin_scan(
        db, url="https://webhoundsecurity.com", profile="baseline",
        reason="establish baseline", triggered_by="dev")
    await db.commit()
    assert out["profile"] == "deep"
    job = await db.get(ScanJob, __import__("uuid").UUID(out["job_id"]))
    assert job.save_baseline is True


@pytest.mark.anyio
async def test_reason_and_triggered_by_required(db):
    with pytest.raises(AdminScanError):
        await run_admin_scan(db, url="https://webhoundsecurity.com",
                             profile="deep", reason="", triggered_by="dev")
    with pytest.raises(AdminScanError):
        await run_admin_scan(db, url="https://webhoundsecurity.com",
                             profile="deep", reason="x", triggered_by="")


@pytest.mark.anyio
async def test_unknown_profile_rejected(db):
    with pytest.raises(AdminScanError):
        await run_admin_scan(db, url="https://webhoundsecurity.com",
                             profile="ultra", reason="x", triggered_by="dev")


@pytest.mark.anyio
async def test_read_scan_telemetry_view(db):
    out = await run_admin_scan(
        db, url="https://webhoundsecurity.com", profile="deep",
        reason="verify", triggered_by="dev")
    await db.commit()
    job_id = out["job_id"]
    # Simulate the worker having persisted a result with telemetry + browser_pass.
    rec = ScanResultRecord(
        scan_job_id=__import__("uuid").UUID(job_id),
        scan_id="scanner-internal-id",
        risk_score=24, risk_level="low", duration_seconds=120.0,
        pages_crawled=1, total_findings=10, actionable_findings=10,
        severity_breakdown={"critical": 0, "high": 0, "medium": 5, "low": 5, "info": 0},
        scanner_metadata={
            "telemetry": {
                "level": "engines",
                "event_type_counts": {
                    "profile.loaded": 1, "browser.started": 1,
                    "browser.finished": 1, "scan.finished": 1},
                "handoffs": {
                    "after_browser_discovery": {
                        "deferred": False, "rendered_link_count": 3,
                        "artifact_count": 7}},
            },
            "browser_pass": {
                "deferred": False, "browser_pages_rendered": 1,
                "rendered_links_found": 3, "artifact_count": 7},
        })
    db.add(rec)
    await db.commit()

    view = await read_scan_telemetry(db, job_id)
    c = view["checks"]
    assert c["telemetry_present"] is True
    assert c["profile_loaded_fired"] is True
    assert c["profile_is"] == "deep"
    assert c["browser_enabled_expected"] is True
    assert c["browser_started_fired"] is True
    assert c["browser_finished_fired"] is True
    assert c["after_browser_discovery_present"] is True
    assert view["browser_pass_agrees"] is True
    assert view["coverage"]["pages_crawled"] == 1
    assert view["coverage"]["rendered_links_found"] == 3
