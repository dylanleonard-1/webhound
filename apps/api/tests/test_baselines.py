"""Baseline and WADE API tests — list, detail, delete, WADE summary, WADE history."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.models.baseline import BaselineRecord
from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.enums import ScanStatus
from apps.api.models.grouped_finding import GroupedFindingRecord
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.website import Website

pytestmark = pytest.mark.anyio


async def _make_website(
    db_engine, url: str = "https://example.com", user_id: uuid.UUID | None = None
) -> uuid.UUID:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = Website(
            url=url,
            hostname=url.split("//")[1].rstrip("/"),
            scheme="https",
            user_id=user_id,
        )
        db.add(w)
        await db.commit()
        await db.refresh(w)
        return w.id


async def _make_baseline(
    db_engine,
    website_id: uuid.UUID,
    *,
    version: int = 1,
    baseline_id: str | None = None,
) -> uuid.UUID:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        b = BaselineRecord(
            website_id=website_id,
            baseline_id=baseline_id or str(uuid.uuid4()),
            baseline_version=version,
            baseline_json={"status": "ready", "sample_count": 10, "version": version},
        )
        db.add(b)
        await db.commit()
        await db.refresh(b)
        return b.id


async def _make_scan_result(
    db_engine,
    website_id: uuid.UUID,
    *,
    with_wade: bool = True,
    anomaly_count: int = 2,
    risk_score: int = 65,
    risk_level: str = "medium",
) -> dict:
    """Create ScanJob + ScanResultRecord (+ optional WADE sub-records)."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        job = ScanJob(
            website_id=website_id,
            profile="standard",
            requested_url="https://example.com",
            status=ScanStatus.COMPLETED,
        )
        db.add(job)
        await db.flush()

        sr = ScanResultRecord(
            scan_job_id=job.id,
            scan_id=str(uuid.uuid4()),
            risk_score=risk_score,
            risk_level=risk_level,
            duration_seconds=2.5,
            pages_crawled=8,
            total_findings=anomaly_count + 1,
            actionable_findings=anomaly_count + 1,
            severity_breakdown={"critical": 0, "high": anomaly_count, "medium": 0, "low": 0, "info": 0},
            scanner_metadata={
                "wade_baseline_generated": True,
                "wade_baseline_version": "baseline-abc-123",
                "wade_compared_to_previous": with_wade and anomaly_count > 0,
                "wade_anomaly_count": anomaly_count if with_wade else 0,
                "crawl_duration_seconds": 1.0,
            },
        )
        db.add(sr)
        await db.flush()

        if with_wade and anomaly_count > 0:
            db.add(GroupedFindingRecord(
                scan_result_id=sr.id,
                title="Unexpected response header change",
                severity="high",
                category="anomaly_detection",
                scanner_engine="wade",
                affected_url_count=3,
                affected_urls=["https://example.com/", "https://example.com/about"],
                evidence_count=3,
                confidence=0.85,
                remediation="Investigate header changes.",
                framework={},
                finding_ids=[],
            ))
            if anomaly_count > 1:
                db.add(GroupedFindingRecord(
                    scan_result_id=sr.id,
                    title="Content length deviation",
                    severity="medium",
                    category="anomaly_detection",
                    scanner_engine="wade",
                    affected_url_count=1,
                    affected_urls=["https://example.com/page"],
                    evidence_count=1,
                    confidence=0.7,
                    remediation=None,
                    framework={},
                    finding_ids=[],
                ))

            db.add(EngineDiagnosticRecord(
                scan_result_id=sr.id,
                engine_name="wade",
                category="anomaly_detection",
                status="findings",
                findings_count=anomaly_count,
                severity_counts={"critical": 0, "high": anomaly_count, "medium": 0, "low": 0, "info": 0},
                duration_ms=55.0,
            ))
        elif with_wade:
            # baseline generated but no comparison (first scan)
            db.add(EngineDiagnosticRecord(
                scan_result_id=sr.id,
                engine_name="wade",
                category="anomaly_detection",
                status="skipped",
                findings_count=0,
                severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                duration_ms=12.0,
                skipped_reason="no previous baseline supplied",
            ))

        await db.commit()
        return {"scan_result_id": str(sr.id), "scan_job_id": str(job.id)}


# ---------------------------------------------------------------------------
# GET /websites/{website_id}/baselines
# ---------------------------------------------------------------------------


async def test_list_baselines_empty(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    r = await client.get(f"/websites/{wid}/baselines")
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == []
    assert body["total"] == 0
    assert body["limit"] == 20
    assert body["offset"] == 0


async def test_list_baselines_website_not_found(client):
    r = await client.get("/websites/00000000-0000-0000-0000-000000000000/baselines")
    assert r.status_code == 404


async def test_list_baselines_returns_created(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    await _make_baseline(db_engine, wid)
    r = await client.get(f"/websites/{wid}/baselines")
    body = r.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1


async def test_list_baselines_response_fields(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    await _make_baseline(db_engine, wid, version=3)
    item = (await client.get(f"/websites/{wid}/baselines")).json()["items"][0]
    assert "id" in item
    assert item["website_id"] == str(wid)
    assert "baseline_id" in item
    assert item["baseline_version"] == 3
    assert "created_at" in item
    assert item["scan_result_id"] is None
    assert item["scan_job_id"] is None


async def test_list_baselines_ordered_newest_first(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    await _make_baseline(db_engine, wid, version=1)
    await _make_baseline(db_engine, wid, version=2)
    items = (await client.get(f"/websites/{wid}/baselines")).json()["items"]
    versions = [i["baseline_version"] for i in items]
    # newest (version 2) should come first
    assert versions[0] >= versions[-1]


async def test_list_baselines_pagination(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    for v in range(5):
        await _make_baseline(db_engine, wid, version=v + 1)
    r = await client.get(f"/websites/{wid}/baselines?limit=2&offset=1")
    body = r.json()
    assert body["total"] == 5
    assert len(body["items"]) == 2


async def test_list_baselines_only_returns_own_website(client, db_engine, _test_user):
    wid1 = await _make_website(db_engine, "https://site1.com", user_id=_test_user.id)
    wid2 = await _make_website(db_engine, "https://site2.com", user_id=_test_user.id)
    await _make_baseline(db_engine, wid1)
    await _make_baseline(db_engine, wid2)
    r = await client.get(f"/websites/{wid1}/baselines")
    assert r.json()["total"] == 1


# ---------------------------------------------------------------------------
# GET /websites/{website_id}/baselines/latest
# ---------------------------------------------------------------------------


async def test_get_latest_baseline_success(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    await _make_baseline(db_engine, wid, version=1)
    bid = await _make_baseline(db_engine, wid, version=2)
    r = await client.get(f"/websites/{wid}/baselines/latest")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == str(bid)
    assert body["baseline_version"] == 2


async def test_get_latest_baseline_not_found(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    r = await client.get(f"/websites/{wid}/baselines/latest")
    assert r.status_code == 404


async def test_get_latest_baseline_includes_json(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    await _make_baseline(db_engine, wid)
    body = (await client.get(f"/websites/{wid}/baselines/latest")).json()
    assert "baseline_json" in body
    assert body["baseline_json"]["status"] == "ready"


async def test_get_latest_baseline_website_not_found(client):
    r = await client.get(
        "/websites/00000000-0000-0000-0000-000000000000/baselines/latest"
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# GET /baselines/{baseline_record_id}
# ---------------------------------------------------------------------------


async def test_get_baseline_success(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    bid = await _make_baseline(db_engine, wid, version=5)
    r = await client.get(f"/baselines/{bid}")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == str(bid)
    assert body["website_id"] == str(wid)
    assert body["baseline_version"] == 5
    assert "baseline_json" in body


async def test_get_baseline_not_found(client):
    r = await client.get("/baselines/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


async def test_get_baseline_invalid_uuid(client):
    r = await client.get("/baselines/not-a-uuid")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# DELETE /baselines/{baseline_record_id}
# ---------------------------------------------------------------------------


async def test_delete_baseline_success(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    bid = await _make_baseline(db_engine, wid)
    r = await client.delete(f"/baselines/{bid}")
    assert r.status_code == 204

    # Confirm gone
    r2 = await client.get(f"/baselines/{bid}")
    assert r2.status_code == 404


async def test_delete_baseline_not_found(client):
    r = await client.delete("/baselines/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


async def test_delete_baseline_does_not_affect_website(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    bid = await _make_baseline(db_engine, wid)
    await client.delete(f"/baselines/{bid}")
    # Website still accessible
    r = await client.get(f"/websites/{wid}")
    assert r.status_code == 200


async def test_delete_baseline_does_not_cascade_to_scan_results(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    ids = await _make_scan_result(db_engine, wid)
    bid = await _make_baseline(db_engine, wid)
    await client.delete(f"/baselines/{bid}")
    # Scan result still accessible
    r = await client.get(f"/scan-results/{ids['scan_result_id']}")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# GET /scan-results/{scan_result_id}/wade
# ---------------------------------------------------------------------------


async def test_get_wade_summary_success(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    ids = await _make_scan_result(db_engine, wid, with_wade=True, anomaly_count=2)
    r = await client.get(f"/scan-results/{ids['scan_result_id']}/wade")
    assert r.status_code == 200
    body = r.json()
    assert body["scan_result_id"] == ids["scan_result_id"]


async def test_get_wade_summary_not_found(client):
    r = await client.get(
        "/scan-results/00000000-0000-0000-0000-000000000000/wade"
    )
    assert r.status_code == 404


async def test_get_wade_summary_baseline_generated(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    ids = await _make_scan_result(db_engine, wid, with_wade=True, anomaly_count=2)
    body = (await client.get(f"/scan-results/{ids['scan_result_id']}/wade")).json()
    assert body["baseline_generated"] is True
    assert body["baseline_version"] == "baseline-abc-123"


async def test_get_wade_summary_compared_to_previous(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    ids = await _make_scan_result(db_engine, wid, with_wade=True, anomaly_count=2)
    body = (await client.get(f"/scan-results/{ids['scan_result_id']}/wade")).json()
    assert body["compared_to_previous_baseline"] is True
    assert body["anomaly_count"] == 2


async def test_get_wade_summary_includes_findings(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    ids = await _make_scan_result(db_engine, wid, with_wade=True, anomaly_count=2)
    body = (await client.get(f"/scan-results/{ids['scan_result_id']}/wade")).json()
    assert len(body["wade_findings"]) == 2
    titles = [f["title"] for f in body["wade_findings"]]
    assert "Unexpected response header change" in titles


async def test_get_wade_summary_includes_diagnostic(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    ids = await _make_scan_result(db_engine, wid, with_wade=True, anomaly_count=2)
    body = (await client.get(f"/scan-results/{ids['scan_result_id']}/wade")).json()
    assert body["wade_diagnostic"] is not None
    assert body["wade_diagnostic"]["status"] == "findings"
    assert body["wade_diagnostic"]["findings_count"] == 2


async def test_get_wade_summary_skipped_state(client, db_engine, _test_user):
    """First scan: baseline generated but no previous to compare against."""
    wid = await _make_website(db_engine, user_id=_test_user.id)
    ids = await _make_scan_result(db_engine, wid, with_wade=True, anomaly_count=0)
    body = (await client.get(f"/scan-results/{ids['scan_result_id']}/wade")).json()
    assert body["baseline_generated"] is True
    assert body["compared_to_previous_baseline"] is False
    assert body["anomaly_count"] == 0
    assert body["wade_findings"] == []
    assert body["wade_diagnostic"]["status"] == "skipped"
    assert body["wade_diagnostic"]["skipped_reason"] is not None


async def test_get_wade_summary_no_wade_metadata(client, db_engine, _test_user):
    """Scan result with no WADE metadata returns safe defaults."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        w = Website(url="https://nowade.com", hostname="nowade.com", scheme="https", user_id=_test_user.id)
        db.add(w)
        await db.flush()
        job = ScanJob(
            website_id=w.id,
            profile="quick",
            requested_url="https://nowade.com",
            status=ScanStatus.COMPLETED,
        )
        db.add(job)
        await db.flush()
        sr = ScanResultRecord(
            scan_job_id=job.id,
            risk_score=85,
            risk_level="low",
            pages_crawled=3,
            total_findings=0,
            actionable_findings=0,
            severity_breakdown={},
            scanner_metadata=None,
        )
        db.add(sr)
        await db.commit()
        sr_id = str(sr.id)

    body = (await client.get(f"/scan-results/{sr_id}/wade")).json()
    assert body["baseline_generated"] is False
    assert body["compared_to_previous_baseline"] is False
    assert body["anomaly_count"] == 0
    assert body["wade_findings"] == []
    assert body["wade_diagnostic"] is None


# ---------------------------------------------------------------------------
# GET /websites/{website_id}/wade/history
# ---------------------------------------------------------------------------


async def test_wade_history_empty(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    r = await client.get(f"/websites/{wid}/wade/history")
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == []
    assert body["total"] == 0


async def test_wade_history_website_not_found(client):
    r = await client.get(
        "/websites/00000000-0000-0000-0000-000000000000/wade/history"
    )
    assert r.status_code == 404


async def test_wade_history_returns_results(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    await _make_scan_result(db_engine, wid, anomaly_count=2)
    r = await client.get(f"/websites/{wid}/wade/history")
    body = r.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1


async def test_wade_history_response_fields(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    ids = await _make_scan_result(db_engine, wid, anomaly_count=2)
    item = (await client.get(f"/websites/{wid}/wade/history")).json()["items"][0]
    assert item["scan_result_id"] == ids["scan_result_id"]
    assert item["scan_job_id"] == ids["scan_job_id"]
    assert "created_at" in item
    assert item["anomaly_count"] == 2
    assert item["risk_score"] == 65
    assert item["risk_level"] == "medium"
    assert isinstance(item["top_anomaly_titles"], list)


async def test_wade_history_top_anomaly_titles(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    await _make_scan_result(db_engine, wid, anomaly_count=2)
    item = (await client.get(f"/websites/{wid}/wade/history")).json()["items"][0]
    assert "Unexpected response header change" in item["top_anomaly_titles"]


async def test_wade_history_no_anomalies_empty_titles(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    await _make_scan_result(db_engine, wid, anomaly_count=0)
    item = (await client.get(f"/websites/{wid}/wade/history")).json()["items"][0]
    assert item["top_anomaly_titles"] == []


async def test_wade_history_ordered_newest_first(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    await _make_scan_result(db_engine, wid, anomaly_count=1, risk_score=60)
    await _make_scan_result(db_engine, wid, anomaly_count=3, risk_score=40)
    items = (await client.get(f"/websites/{wid}/wade/history")).json()["items"]
    dates = [item["created_at"] for item in items]
    assert dates == sorted(dates, reverse=True)


async def test_wade_history_pagination(client, db_engine, _test_user):
    wid = await _make_website(db_engine, user_id=_test_user.id)
    for _ in range(4):
        await _make_scan_result(db_engine, wid)
    r = await client.get(f"/websites/{wid}/wade/history?limit=2&offset=1")
    body = r.json()
    assert body["total"] == 4
    assert len(body["items"]) == 2


async def test_wade_history_only_own_website(client, db_engine, _test_user):
    wid1 = await _make_website(db_engine, "https://wh1.com", user_id=_test_user.id)
    wid2 = await _make_website(db_engine, "https://wh2.com", user_id=_test_user.id)
    await _make_scan_result(db_engine, wid1)
    await _make_scan_result(db_engine, wid1)
    await _make_scan_result(db_engine, wid2)
    r = await client.get(f"/websites/{wid1}/wade/history")
    assert r.json()["total"] == 2
