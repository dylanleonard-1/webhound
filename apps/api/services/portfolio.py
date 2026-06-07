# WebHound API — apps/api/services/portfolio.py
# Phase-16 Agency/MSP portfolio service. Aggregates an organization's
# sites + their latest scan into the portfolio views, reusing the tested
# scanner-side portfolio package (webhound.portfolio).
#
# DESIGN: the heavy logic is a PURE function, build_portfolio_view, that
# takes plain SiteRow dicts and returns the full payload — unit-testable
# with no DB or Redis. The DB-bound wrappers just query the org's sites +
# latest scan and feed the pure core, so single-site users are entirely
# unaffected (a 1-site portfolio is just a 1-site rollup).

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.website import Website

from webhound.portfolio import (
    BrandingConfig,
    ClientGroup,
    ClientGroupManager,
    SiteRecord,
    SiteRegistry,
    SiteScanSummary,
    build_dashboard_data,
    build_executive_report,
    compute_portfolio_scores,
    detect_cross_site_alerts,
    build_risk_rollup,
)


@dataclass
class SiteRow:
    """The per-site data the portfolio aggregation needs — assembled from
    a Website + its latest scan, but plain so the core stays testable."""

    site_id: str
    domain: str
    url: str
    verified: bool = False
    organization: str = ""
    group_id: str | None = None
    group_name: str | None = None
    industry: str = ""
    plan: str = "standard"
    tags: list[str] = field(default_factory=list)
    monitoring: bool = False
    last_scan_at: str | None = None
    risk_score: int = 0
    risk_level: str = "safe"
    scanner_metadata: dict[str, Any] | None = None
    scan_failed: bool = False
    has_tls_issue: bool = False

    def to_summary(self) -> SiteScanSummary:
        if self.scanner_metadata:
            s = SiteScanSummary.from_scan_metadata({
                **self.scanner_metadata,
                "risk_score": self.risk_score,
                "risk_level": self.risk_level,
                "scan_completed_at": self.last_scan_at,
            })
        else:
            s = SiteScanSummary(
                risk_score=self.risk_score, risk_level=self.risk_level,
                last_scan_at=self.last_scan_at,
                scan_count=1 if self.last_scan_at else 0)
        # Overlay API-supplied operational signals.
        s.scan_failed = self.scan_failed
        s.has_tls_issue = self.has_tls_issue
        return s


def _registry_from_rows(rows: list[SiteRow]) -> SiteRegistry:
    reg = SiteRegistry()
    for r in rows:
        reg.add(SiteRecord(
            site_id=r.site_id, url=r.url, owner=r.organization,
            organization=r.organization, industry=r.industry, plan=r.plan,
            tags=list(r.tags),
            groups=[r.group_id] if r.group_id else [],
            summary=r.to_summary()))
    return reg


def build_portfolio_view(
    rows: list[SiteRow], *, branding: dict[str, Any] | None = None,
    previous_scores: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """PURE core — the full portfolio payload from site rows. No DB."""
    reg = _registry_from_rows(rows)
    sites = reg.all()
    dashboard = build_dashboard_data(reg)
    report = build_executive_report(
        reg,
        branding=BrandingConfig(**branding) if branding else None,
        previous_scores=previous_scores)
    return {
        "summary": {
            "sites_monitored": reg.count,
            **dashboard["scores"],
            "cross_site_alert_count": dashboard["cross_site_alert_count"],
            "sites_with_compromise":
                build_risk_rollup(sites).sites_with_compromise,
        },
        "dashboard": dashboard,
        "report": report.to_dict(),
    }


# ---------------------------------------------------------------------------
# DB-bound: assemble SiteRows for an org from latest scans
# ---------------------------------------------------------------------------


def _derive_signals(meta: dict[str, Any] | None) -> tuple[bool, bool]:
    """(scan_failed, has_tls_issue) from scan metadata."""
    m = meta or {}
    failed = bool(m.get("failure_reason"))
    # A TLS finding shows up in report sections / engines.
    tls = False
    for sec in (m.get("report_sections") or {}).get("security_risks", []):
        t = (sec.get("title", "") or "").lower()
        if "tls" in t or "certificate" in t or "https" in t:
            tls = True
            break
    return failed, tls


async def get_portfolio_rows(
    db: AsyncSession, org_id: uuid.UUID,
) -> list[SiteRow]:
    """Assemble one SiteRow per org website, joined to its latest scan."""
    sites = (await db.execute(
        sa.select(Website).where(Website.org_id == org_id))).scalars().all()
    rows: list[SiteRow] = []
    for site in sites:
        latest = (await db.execute(
            sa.select(ScanResultRecord)
            .join(ScanJob, ScanResultRecord.scan_job_id == ScanJob.id)
            .where(ScanJob.website_id == site.id)
            .order_by(ScanResultRecord.created_at.desc())
            .limit(1))).scalars().first()
        meta = getattr(latest, "scanner_metadata", None) if latest else None
        failed, tls = _derive_signals(meta)
        group_id = getattr(site, "group_id", None)
        rows.append(SiteRow(
            site_id=str(site.id), domain=site.hostname, url=site.url,
            verified=str(getattr(site, "verification_status", "")) ==
            "verified",
            organization=str(org_id),
            group_id=str(group_id) if group_id else None,
            monitoring=latest is not None,
            last_scan_at=(latest.created_at.isoformat()
                          if latest and latest.created_at else None),
            risk_score=int(getattr(latest, "risk_score", 0) or 0)
            if latest else 0,
            risk_level=str(getattr(latest, "risk_level", "safe"))
            if latest else "safe",
            scanner_metadata=meta, scan_failed=failed, has_tls_issue=tls))
    return rows


async def get_portfolio_summary(
    db: AsyncSession, org_id: uuid.UUID,
) -> dict[str, Any]:
    rows = await get_portfolio_rows(db, org_id)
    return build_portfolio_view(rows)


async def get_portfolio_alerts(
    db: AsyncSession, org_id: uuid.UUID,
) -> list[dict[str, Any]]:
    rows = await get_portfolio_rows(db, org_id)
    reg = _registry_from_rows(rows)
    return [a.to_dict() for a in detect_cross_site_alerts(reg.all())]


# ---------------------------------------------------------------------------
# Client groups (Task 2) — persisted, org-scoped
# ---------------------------------------------------------------------------


async def list_client_groups(
    db: AsyncSession, org_id: uuid.UUID,
) -> list[dict[str, Any]]:
    from apps.api.models.website_group import WebsiteGroup
    groups = (await db.execute(
        sa.select(WebsiteGroup).where(WebsiteGroup.org_id == org_id)
    )).scalars().all()
    # site counts per group
    counts = dict((await db.execute(
        sa.select(Website.group_id, sa.func.count())
        .where(Website.org_id == org_id, Website.group_id.is_not(None))
        .group_by(Website.group_id))).all())
    return [{
        "group_id": str(g.id), "name": g.name, "group_type": g.group_type,
        "parent_group_id": str(g.parent_group_id) if g.parent_group_id
        else None,
        "site_count": int(counts.get(g.id, 0)),
    } for g in groups]


async def create_client_group(
    db: AsyncSession, org_id: uuid.UUID, *, name: str,
    group_type: str = "agency_client", parent_group_id: str | None = None,
) -> dict[str, Any]:
    from apps.api.models.website_group import WebsiteGroup
    group = WebsiteGroup(
        org_id=org_id, name=name, group_type=group_type,
        parent_group_id=uuid.UUID(parent_group_id)
        if parent_group_id else None)
    db.add(group)
    await db.flush()
    return {"group_id": str(group.id), "name": group.name,
            "group_type": group.group_type,
            "parent_group_id": parent_group_id, "site_count": 0}


async def assign_site_to_group(
    db: AsyncSession, org_id: uuid.UUID, site_id: uuid.UUID,
    group_id: str | None,
) -> bool:
    """Assign (or clear, group_id=None) a site's portfolio group. Both the
    site and the group must belong to the org (tenant isolation)."""
    site = await db.get(Website, site_id)
    if site is None or site.org_id != org_id:
        return False
    if group_id is None:
        site.group_id = None
        return True
    from apps.api.models.website_group import WebsiteGroup
    group = await db.get(WebsiteGroup, uuid.UUID(group_id))
    if group is None or group.org_id != org_id:
        return False
    site.group_id = group.id
    return True


async def get_portfolio_report(
    db: AsyncSession, org_id: uuid.UUID,
    *, branding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows = await get_portfolio_rows(db, org_id)
    return build_portfolio_view(rows, branding=branding)["report"]
