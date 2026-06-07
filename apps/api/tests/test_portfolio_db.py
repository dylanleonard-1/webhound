# WebHound API — apps/api/tests/test_portfolio_db.py
# Phase-16: DB-bound portfolio service tests against the in-memory SQLite
# fixture (no HTTP client, no Redis). Covers client-group CRUD, site
# assignment + tenant isolation, and org-scoped portfolio aggregation.

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.models.org import Org
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.website import Website
from apps.api.services import portfolio as svc


@pytest.fixture
async def session(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as s:
        yield s


async def _org(s, slug="acme") -> Org:
    org = Org(slug=slug, name=slug.title())
    s.add(org)
    await s.flush()
    return org


async def _site(s, org_id, host, *, risk=10, level="low", meta=None,
                group_id=None) -> Website:
    site = Website(url=f"https://{host}", hostname=host, scheme="https",
                   org_id=org_id, group_id=group_id)
    s.add(site)
    await s.flush()
    job = ScanJob(website_id=site.id, org_id=org_id, requested_url=site.url)
    s.add(job)
    await s.flush()
    result = ScanResultRecord(
        scan_job_id=job.id, risk_score=risk, risk_level=level,
        scanner_metadata=meta or {})
    s.add(result)
    await s.flush()
    return site


# ---------------------------------------------------------------------------
# Client groups (Task 2)
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_create_and_list_client_group(session) -> None:
    org = await _org(session)
    g = await svc.create_client_group(
        session, org.id, name="Joe's Pizza", group_type="client")
    assert g["name"] == "Joe's Pizza"
    groups = await svc.list_client_groups(session, org.id)
    assert len(groups) == 1
    assert groups[0]["group_type"] == "client"


@pytest.mark.anyio
async def test_assign_site_to_group_and_count(session) -> None:
    org = await _org(session)
    g = await svc.create_client_group(session, org.id, name="Bright Dental")
    s1 = await _site(session, org.id, "brightdental.com")
    s2 = await _site(session, org.id, "brightdentalnorth.com")
    assert await svc.assign_site_to_group(
        session, org.id, s1.id, g["group_id"])
    assert await svc.assign_site_to_group(
        session, org.id, s2.id, g["group_id"])
    groups = await svc.list_client_groups(session, org.id)
    assert groups[0]["site_count"] == 2
    # Clearing the assignment.
    assert await svc.assign_site_to_group(session, org.id, s1.id, None)
    groups = await svc.list_client_groups(session, org.id)
    assert groups[0]["site_count"] == 1


@pytest.mark.anyio
async def test_tenant_isolation_on_assignment(session) -> None:
    org_a = await _org(session, "a")
    org_b = await _org(session, "b")
    g_b = await svc.create_client_group(session, org_b.id, name="B group")
    site_a = await _site(session, org_a.id, "sitea.com")
    # Org A cannot assign its site to Org B's group.
    assert await svc.assign_site_to_group(
        session, org_a.id, site_a.id, g_b["group_id"]) is False
    # And cannot touch a site it doesn't own.
    site_b = await _site(session, org_b.id, "siteb.com")
    assert await svc.assign_site_to_group(
        session, org_a.id, site_b.id, None) is False


# ---------------------------------------------------------------------------
# Portfolio aggregation (Task 3) — org-scoped
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_portfolio_rows_scoped_to_org(session) -> None:
    org_a = await _org(session, "a")
    org_b = await _org(session, "b")
    await _site(session, org_a.id, "a1.com", risk=70, level="high")
    await _site(session, org_a.id, "a2.com", risk=5, level="safe")
    await _site(session, org_b.id, "b1.com", risk=90, level="critical")
    rows = await svc.get_portfolio_rows(session, org_a.id)
    assert len(rows) == 2                      # only org A's sites
    domains = {r.domain for r in rows}
    assert domains == {"a1.com", "a2.com"}


@pytest.mark.anyio
async def test_portfolio_summary_from_db(session) -> None:
    org = await _org(session)
    await _site(session, org.id, "x.com", risk=70, level="high",
                meta={"security_stories":
                      [{"correlation_type": "possible_compromise"}]})
    await _site(session, org.id, "y.com", risk=5, level="safe")
    view = await svc.get_portfolio_summary(session, org.id)
    assert view["summary"]["sites_monitored"] == 2
    assert view["summary"]["sites_with_compromise"] == 1


@pytest.mark.anyio
async def test_single_site_org_works(session) -> None:
    """Task 9 backward-compat: a single-site org gets a valid 1-site
    portfolio — no breakage, no special-casing."""
    org = await _org(session)
    await _site(session, org.id, "only.com", risk=20, level="low")
    view = await svc.get_portfolio_summary(session, org.id)
    assert view["summary"]["sites_monitored"] == 1
    assert "portfolio_risk_score" in view["summary"]


@pytest.mark.anyio
async def test_site_rows_carry_health_and_top_issue(session) -> None:
    """Task 1/8: /sites exposes health_score + top_issue (the table cols)."""
    org = await _org(session)
    await _site(session, org.id, "x.com", risk=70, level="high", meta={
        "report_sections": {"security_risks": [
            {"title": "Exposed Admin panel detected"}]},
        "security_stories": [{"correlation_type": "possible_compromise"}]})
    rows = await svc.get_portfolio_rows(session, org.id)
    r = rows[0]
    assert isinstance(r.health_score, int)
    assert r.top_issue == "Possible website compromise"  # compromise wins


@pytest.mark.anyio
async def test_portfolio_wade_groups_not_duplicates(session) -> None:
    """Task 5: portfolio-WADE answers the cross-site change questions,
    grouping the shared change instead of one alert per site."""
    org = await _org(session)
    meta = {"wade_anomaly_count": 2,
            "security_stories": [{"correlation_type": "possible_compromise"}]}
    await _site(session, org.id, "a.com", meta=meta)
    await _site(session, org.id, "b.com", meta=meta)
    w = await svc.get_portfolio_wade(session, org.id)
    assert w["changed_count"] == 2
    assert len(w["sites_with_suspicious_changes"]) == 2


@pytest.mark.anyio
async def test_portfolio_alerts_no_duplicates(session) -> None:
    """Task 10: cross-site alerts contain no duplicate (type, indicator,
    affected-set) entries."""
    org = await _org(session)
    meta = {"external_script_domains": ["weird-shared-xyz.com"],
            "wade_anomaly_count": 1}
    for h in ("a.com", "b.com", "c.com"):
        await _site(session, org.id, h, meta=meta)
    alerts = await svc.get_portfolio_alerts(session, org.id)
    keys = [(a["alert_type"], a.get("shared_indicator") or "",
             tuple(sorted(a["affected_site_ids"]))) for a in alerts]
    assert len(keys) == len(set(keys))
