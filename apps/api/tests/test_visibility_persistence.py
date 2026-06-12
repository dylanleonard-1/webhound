# WebHound — apps/api/tests/test_visibility_persistence.py
# Phase 12 tests: the guarded visibility-report persistence into the dedicated
# tables. Uses an in-memory async SQLite DB built from the model metadata.

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apps.api.database import Base
import apps.api.models  # noqa: F401 — register all models
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.visibility_report import (
    DiscoveredUrlRecord,
    VisibilityReportRecord,
)
from apps.api.services.result_persistence import _persist_visibility_report


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


_REPORT = {
    "domain": "example.com",
    "crawl_mode": "visibility",
    "pages_found": 12,
    "pages_crawled": 10,
    "visibility_score": 78,
    "js_routes": 3,
    "site_graph_generated": True,
    "forms": {"count": 4},
    "api": {"count": 6},
    "assets": {"count": 20},
    "third_party": {"count": 5},
    "limitations": ["Crawl truncated at the page budget — 2 URL(s)."],
    "discovered_urls": [
        {"url": "https://example.com/", "normalized": "https://example.com/",
         "discovered_via": "seed", "sources": ["seed"], "tags": [],
         "depth": 0, "parent": None, "status": "crawled", "skip_reason": None,
         "in_scope": True, "status_code": 200, "content_type": "text/html"},
        {"url": "https://example.com/admin", "normalized": "https://example.com/admin",
         "discovered_via": "sitemap", "sources": ["sitemap"], "tags": [],
         "depth": 1, "parent": "https://example.com/", "status": "skipped",
         "skip_reason": "disallowed by robots.txt", "in_scope": True,
         "status_code": None, "content_type": None},
    ],
}


async def _seed_scan_result(session: AsyncSession) -> ScanResultRecord:
    # FK enforcement is off in SQLite by default, so a random scan_job_id is
    # sufficient to exercise the visibility persistence in isolation.
    rec = ScanResultRecord(
        scan_job_id=uuid.uuid4(), risk_score=10, risk_level="low",
        severity_breakdown={}, scanner_metadata={},
    )
    session.add(rec)
    await session.flush()
    return rec


@pytest.mark.asyncio
async def test_persists_report_and_urls(session):
    rec = await _seed_scan_result(session)
    await _persist_visibility_report(
        session, rec.id, {"visibility_report": _REPORT}
    )
    await session.flush()

    vr = (await session.execute(
        select(VisibilityReportRecord).where(
            VisibilityReportRecord.scan_result_id == rec.id)
    )).scalar_one()
    assert vr.domain == "example.com"
    assert vr.pages_found == 12
    assert vr.pages_crawled == 10
    assert vr.visibility_score == 78
    assert vr.forms_count == 4
    assert vr.api_count == 6
    assert vr.js_routes_count == 3
    assert vr.third_party_count == 5
    assert vr.site_graph_generated is True

    urls = (await session.execute(
        select(DiscoveredUrlRecord).where(
            DiscoveredUrlRecord.visibility_report_id == vr.id)
    )).scalars().all()
    assert len(urls) == 2
    skipped = [u for u in urls if u.status == "skipped"]
    assert skipped and skipped[0].skip_reason == "disallowed by robots.txt"


@pytest.mark.asyncio
async def test_no_report_is_noop(session):
    rec = await _seed_scan_result(session)
    await _persist_visibility_report(session, rec.id, {})  # no visibility_report
    await session.flush()
    count = (await session.execute(select(VisibilityReportRecord))).scalars().all()
    assert count == []
