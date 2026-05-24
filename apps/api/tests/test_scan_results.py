"""Scan results API tests — list, detail, sub-resources, filters."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.enums import ReportFormat, ScanStatus
from apps.api.models.finding import FindingRecord
from apps.api.models.grouped_finding import GroupedFindingRecord
from apps.api.models.report import ReportRecord
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.website import Website

pytestmark = pytest.mark.anyio


async def _seed(
    db_engine,
    *,
    url: str = "https://example.com",
    risk_score: int = 70,
    risk_level: str = "medium",
    with_findings: bool = True,
    user_id: uuid.UUID | None = None,
) -> dict:
    """Insert a complete ScanResult chain into the DB; return IDs."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        website = Website(url=url, hostname=url.split("//")[1].rstrip("/"), scheme="https", user_id=user_id)
        db.add(website)
        await db.flush()

        job = ScanJob(
            website_id=website.id,
            profile="standard",
            requested_url=url,
            status=ScanStatus.COMPLETED,
        )
        db.add(job)
        await db.flush()

        sr = ScanResultRecord(
            scan_job_id=job.id,
            scan_id=str(uuid.uuid4()),
            risk_score=risk_score,
            risk_level=risk_level,
            duration_seconds=3.14,
            pages_crawled=10,
            total_findings=2,
            actionable_findings=2,
            severity_breakdown={"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
            scanner_metadata={
                "external_domains": ["cdn.example.com"],
                "crawl_duration_seconds": 1.23,
            },
        )
        db.add(sr)
        await db.flush()

        if with_findings:
            db.add(FindingRecord(
                scan_result_id=sr.id,
                title="Missing CSP",
                severity="high",
                category="security_header",
                scanner_engine="security_headers",
                affected_url=f"{url}/page1",
                confidence=1.0,
                description="Content-Security-Policy missing.",
                remediation="Add CSP header.",
                evidence=[],
                framework={},
            ))
            db.add(FindingRecord(
                scan_result_id=sr.id,
                title="Insecure Cookie",
                severity="medium",
                category="cookie",
                scanner_engine="cookie_scanner",
                affected_url=f"{url}/page2",
                confidence=0.9,
                description="Cookie lacks Secure flag.",
                remediation="Set Secure flag.",
                evidence=[],
                framework={},
            ))

            db.add(GroupedFindingRecord(
                scan_result_id=sr.id,
                title="Missing CSP",
                severity="high",
                category="security_header",
                scanner_engine="security_headers",
                affected_url_count=5,
                affected_urls=[f"{url}/page{i}" for i in range(5)],
                evidence_count=5,
                confidence=1.0,
                remediation="Add CSP header.",
                framework={},
                finding_ids=[],
            ))
            db.add(GroupedFindingRecord(
                scan_result_id=sr.id,
                title="Insecure Cookie",
                severity="medium",
                category="cookie",
                scanner_engine="cookie_scanner",
                affected_url_count=2,
                affected_urls=[f"{url}/page1", f"{url}/page2"],
                evidence_count=2,
                confidence=0.9,
                remediation="Set Secure flag.",
                framework={},
                finding_ids=[],
            ))

            db.add(EngineDiagnosticRecord(
                scan_result_id=sr.id,
                engine_name="security_headers",
                category="headers",
                status="findings",
                findings_count=5,
                severity_counts={"critical": 0, "high": 5, "medium": 0, "low": 0, "info": 0},
                duration_ms=42.0,
            ))
            db.add(EngineDiagnosticRecord(
                scan_result_id=sr.id,
                engine_name="tls_checker",
                category="tls_dns",
                status="passed",
                findings_count=0,
                severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                duration_ms=120.5,
            ))

            db.add(ReportRecord(
                scan_result_id=sr.id,
                format=ReportFormat.JSON,
                content_json={"summary": "ok"},
            ))

        await db.commit()
        return {
            "website_id": str(website.id),
            "scan_job_id": str(job.id),
            "scan_result_id": str(sr.id),
        }


@pytest.fixture
async def seeded(client, db_engine, _test_user):
    return await _seed(db_engine, user_id=_test_user.id)


# ---------------------------------------------------------------------------
# GET /scan-results — list
# ---------------------------------------------------------------------------


async def test_list_scan_results_empty(client):
    r = await client.get("/scan-results")
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == []
    assert body["total"] == 0
    assert body["limit"] == 20
    assert body["offset"] == 0


async def test_list_scan_results_returns_created(client, seeded):
    r = await client.get("/scan-results")
    body = r.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1


async def test_list_scan_results_includes_website_info(client, seeded):
    r = await client.get("/scan-results")
    item = r.json()["items"][0]
    assert item["website_id"] == seeded["website_id"]
    assert item["hostname"] == "example.com"
    assert item["requested_url"].startswith("https://example.com")


async def test_list_scan_results_response_fields(client, seeded):
    item = (await client.get("/scan-results")).json()["items"][0]
    assert "id" in item
    assert "scan_job_id" in item
    assert item["risk_score"] == 70
    assert item["risk_level"] == "medium"
    assert item["pages_crawled"] == 10
    assert item["total_findings"] == 2
    assert item["actionable_findings"] == 2
    assert "severity_breakdown" in item
    assert "created_at" in item


async def test_list_scan_results_filter_by_website_id(client, db_engine, seeded, _test_user):
    ids2 = await _seed(db_engine, url="https://other.com", user_id=_test_user.id)
    r = await client.get(f"/scan-results?website_id={seeded['website_id']}")
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["website_id"] == seeded["website_id"]


async def test_list_scan_results_filter_by_scan_job_id(client, db_engine, seeded, _test_user):
    await _seed(db_engine, url="https://other2.com", user_id=_test_user.id)
    r = await client.get(f"/scan-results?scan_job_id={seeded['scan_job_id']}")
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["scan_job_id"] == seeded["scan_job_id"]


async def test_list_scan_results_filter_by_risk_level(client, db_engine, seeded, _test_user):
    await _seed(db_engine, url="https://safe.com", risk_score=90, risk_level="low", user_id=_test_user.id)
    r = await client.get("/scan-results?risk_level=medium")
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["risk_level"] == "medium"


async def test_list_scan_results_filter_invalid_risk_level(client, seeded):
    r = await client.get("/scan-results?risk_level=unknown")
    assert r.status_code == 422


async def test_list_scan_results_filter_by_min_risk_score(client, db_engine, seeded, _test_user):
    await _seed(db_engine, url="https://risky.com", risk_score=30, risk_level="high", user_id=_test_user.id)
    r = await client.get("/scan-results?min_risk_score=60")
    body = r.json()
    assert all(item["risk_score"] >= 60 for item in body["items"])


async def test_list_scan_results_filter_by_max_risk_score(client, db_engine, seeded, _test_user):
    await _seed(db_engine, url="https://risky2.com", risk_score=30, risk_level="high", user_id=_test_user.id)
    r = await client.get("/scan-results?max_risk_score=50")
    body = r.json()
    assert all(item["risk_score"] <= 50 for item in body["items"])


async def test_list_scan_results_pagination(client, db_engine, seeded, _test_user):
    await _seed(db_engine, url="https://site2.com", user_id=_test_user.id)
    await _seed(db_engine, url="https://site3.com", user_id=_test_user.id)
    r = await client.get("/scan-results?limit=2&offset=1")
    body = r.json()
    assert body["total"] == 3
    assert len(body["items"]) == 2


async def test_list_scan_results_ordered_newest_first(client, db_engine, seeded, _test_user):
    await _seed(db_engine, url="https://site-b.com", user_id=_test_user.id)
    r = await client.get("/scan-results")
    items = r.json()["items"]
    # created_at should be non-increasing
    dates = [item["created_at"] for item in items]
    assert dates == sorted(dates, reverse=True)


# ---------------------------------------------------------------------------
# GET /scan-results/{id}
# ---------------------------------------------------------------------------


async def test_get_scan_result_detail(client, seeded):
    r = await client.get(f"/scan-results/{seeded['scan_result_id']}")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == seeded["scan_result_id"]
    assert body["risk_score"] == 70


async def test_get_scan_result_detail_not_found(client):
    r = await client.get("/scan-results/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


async def test_get_scan_result_detail_invalid_uuid(client):
    r = await client.get("/scan-results/not-a-uuid")
    assert r.status_code == 422


async def test_get_scan_result_detail_includes_scan_job(client, seeded):
    body = (await client.get(f"/scan-results/{seeded['scan_result_id']}")).json()
    assert "scan_job" in body
    assert body["scan_job"]["id"] == seeded["scan_job_id"]
    assert body["scan_job"]["website_id"] == seeded["website_id"]
    assert body["scan_job"]["profile"] == "standard"


async def test_get_scan_result_detail_includes_website(client, seeded):
    body = (await client.get(f"/scan-results/{seeded['scan_result_id']}")).json()
    assert "website" in body
    assert body["website"]["id"] == seeded["website_id"]
    assert body["website"]["hostname"] == "example.com"


async def test_get_scan_result_detail_includes_metadata(client, seeded):
    body = (await client.get(f"/scan-results/{seeded['scan_result_id']}")).json()
    assert body["scanner_metadata"] is not None
    assert "external_domains" in body["scanner_metadata"]


async def test_get_scan_result_detail_duration_and_pages(client, seeded):
    body = (await client.get(f"/scan-results/{seeded['scan_result_id']}")).json()
    assert body["duration_seconds"] == pytest.approx(3.14)
    assert body["pages_crawled"] == 10


# ---------------------------------------------------------------------------
# GET /scan-results/{id}/grouped-findings
# ---------------------------------------------------------------------------


async def test_list_grouped_findings(client, seeded):
    r = await client.get(f"/scan-results/{seeded['scan_result_id']}/grouped-findings")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    assert len(body["items"]) == 2


async def test_list_grouped_findings_not_found(client):
    r = await client.get(
        "/scan-results/00000000-0000-0000-0000-000000000000/grouped-findings"
    )
    assert r.status_code == 404


async def test_list_grouped_findings_response_fields(client, seeded):
    item = (
        await client.get(
            f"/scan-results/{seeded['scan_result_id']}/grouped-findings"
        )
    ).json()["items"][0]
    assert "title" in item
    assert "severity" in item
    assert "affected_url_count" in item
    assert "evidence_count" in item
    assert "confidence" in item


async def test_list_grouped_findings_ordered_severity_first(client, seeded):
    items = (
        await client.get(
            f"/scan-results/{seeded['scan_result_id']}/grouped-findings"
        )
    ).json()["items"]
    severities = [i["severity"] for i in items]
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranks = [severity_rank.get(s, 5) for s in severities]
    assert ranks == sorted(ranks)


async def test_list_grouped_findings_filter_by_severity(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/grouped-findings?severity=high"
    )
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["severity"] == "high"


async def test_list_grouped_findings_filter_by_category(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/grouped-findings?category=cookie"
    )
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["category"] == "cookie"


async def test_list_grouped_findings_filter_by_engine(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/grouped-findings"
        "?scanner_engine=security_headers"
    )
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["scanner_engine"] == "security_headers"


async def test_list_grouped_findings_filter_by_min_confidence(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/grouped-findings?min_confidence=0.95"
    )
    body = r.json()
    # Only the finding with confidence=1.0 passes (0.9 < 0.95)
    assert body["total"] == 1
    assert body["items"][0]["confidence"] >= 0.95


async def test_list_grouped_findings_pagination(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/grouped-findings?limit=1&offset=0"
    )
    body = r.json()
    assert body["total"] == 2
    assert len(body["items"]) == 1


# ---------------------------------------------------------------------------
# GET /scan-results/{id}/findings
# ---------------------------------------------------------------------------


async def test_list_findings(client, seeded):
    r = await client.get(f"/scan-results/{seeded['scan_result_id']}/findings")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2


async def test_list_findings_not_found(client):
    r = await client.get(
        "/scan-results/00000000-0000-0000-0000-000000000000/findings"
    )
    assert r.status_code == 404


async def test_list_findings_response_fields(client, seeded):
    item = (
        await client.get(f"/scan-results/{seeded['scan_result_id']}/findings")
    ).json()["items"][0]
    assert "title" in item
    assert "severity" in item
    assert "category" in item
    assert "scanner_engine" in item
    assert "affected_url" in item
    assert "confidence" in item


async def test_list_findings_filter_by_severity(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/findings?severity=high"
    )
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["severity"] == "high"


async def test_list_findings_filter_by_category(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/findings?category=cookie"
    )
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["category"] == "cookie"


async def test_list_findings_filter_by_engine(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/findings?scanner_engine=cookie_scanner"
    )
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["scanner_engine"] == "cookie_scanner"


async def test_list_findings_filter_by_affected_url(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/findings?affected_url=page1"
    )
    body = r.json()
    assert body["total"] == 1
    assert "page1" in body["items"][0]["affected_url"]


async def test_list_findings_filter_by_min_confidence(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/findings?min_confidence=0.95"
    )
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["confidence"] >= 0.95


async def test_list_findings_pagination(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/findings?limit=1&offset=1"
    )
    body = r.json()
    assert body["total"] == 2
    assert len(body["items"]) == 1


# ---------------------------------------------------------------------------
# GET /scan-results/{id}/engine-diagnostics
# ---------------------------------------------------------------------------


async def test_list_engine_diagnostics(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/engine-diagnostics"
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 2


async def test_engine_diagnostics_not_found(client):
    r = await client.get(
        "/scan-results/00000000-0000-0000-0000-000000000000/engine-diagnostics"
    )
    assert r.status_code == 404


async def test_engine_diagnostics_response_fields(client, seeded):
    item = (
        await client.get(
            f"/scan-results/{seeded['scan_result_id']}/engine-diagnostics"
        )
    ).json()[0]
    assert "engine_name" in item
    assert "status" in item
    assert "findings_count" in item
    assert "duration_ms" in item


async def test_engine_diagnostics_filter_by_status(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/engine-diagnostics?status=passed"
    )
    body = r.json()
    assert len(body) == 1
    assert body[0]["status"] == "passed"


async def test_engine_diagnostics_filter_by_category(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/engine-diagnostics?category=tls_dns"
    )
    body = r.json()
    assert len(body) == 1
    assert body[0]["engine_name"] == "tls_checker"


async def test_engine_diagnostics_filter_by_engine_name(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/engine-diagnostics"
        "?engine_name=security_headers"
    )
    body = r.json()
    assert len(body) == 1
    assert body[0]["engine_name"] == "security_headers"


async def test_engine_diagnostics_ordered_by_name(client, seeded):
    body = (
        await client.get(
            f"/scan-results/{seeded['scan_result_id']}/engine-diagnostics"
        )
    ).json()
    names = [item["engine_name"] for item in body]
    assert names == sorted(names)


# ---------------------------------------------------------------------------
# GET /scan-results/{id}/reports
# ---------------------------------------------------------------------------


async def test_list_reports(client, seeded):
    r = await client.get(f"/scan-results/{seeded['scan_result_id']}/reports")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert body[0]["format"] == "json"


async def test_list_reports_not_found(client):
    r = await client.get(
        "/scan-results/00000000-0000-0000-0000-000000000000/reports"
    )
    assert r.status_code == 404


async def test_list_reports_empty_when_none(client, db_engine, _test_user):
    ids = await _seed(db_engine, url="https://noreport.com", with_findings=False, user_id=_test_user.id)
    r = await client.get(f"/scan-results/{ids['scan_result_id']}/reports")
    assert r.json() == []


# ---------------------------------------------------------------------------
# GET /scan-results/{id}/reports/{format}
# ---------------------------------------------------------------------------


async def test_get_report_by_format_json(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/reports/json"
    )
    assert r.status_code == 200
    body = r.json()
    assert body["format"] == "json"
    assert body["content_json"] == {"summary": "ok"}


async def test_get_report_by_format_not_found(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/reports/sarif"
    )
    assert r.status_code == 404


async def test_get_report_by_pdf_format_not_found(client, seeded):
    # PDF is a valid format but the seed fixture only seeds a JSON report,
    # so this 404s on "no PDF report available" — not on "invalid format".
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/reports/pdf"
    )
    assert r.status_code == 404


async def test_get_report_by_invalid_format(client, seeded):
    r = await client.get(
        f"/scan-results/{seeded['scan_result_id']}/reports/yaml"
    )
    assert r.status_code == 422


async def test_get_report_scan_result_not_found(client):
    r = await client.get(
        "/scan-results/00000000-0000-0000-0000-000000000000/reports/json"
    )
    assert r.status_code == 404
