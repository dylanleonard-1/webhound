# WebHound — scanner/webhound/portfolio/site_registry.py
# Phase-17 Agency & Multi-Site Command Center, Task 1: the registry of
# sites one customer (or agency) monitors, plus a normalized
# SiteScanSummary that extracts the handful of fields the portfolio
# layer reasons over from a full scan's metadata.
#
# Pure data + aggregation — no scanning, no I/O. The portfolio layer is
# decoupled from ScanResult via SiteScanSummary so it scales from 1 to
# 100+ sites cheaply.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class SiteScanSummary:
    """The normalized view of one site's latest scan that the portfolio
    layer needs. Built from ScanResult.metadata via from_scan_metadata."""

    risk_score: int = 0
    risk_level: str = "safe"
    finding_type_counts: dict[str, int] = field(default_factory=dict)
    third_party_domains: list[str] = field(default_factory=list)
    threat_correlation_types: list[str] = field(default_factory=list)
    has_compromise_story: bool = False
    framework: str | None = None
    last_scan_at: str | None = None
    scan_count: int = 0
    change_frequency: int = 0          # recurring/total changes this period
    open_alert_count: int = 0
    # Phase-16 per-site signals the API supplies for cross-site alerts.
    has_tls_issue: bool = False
    has_admin_exposure: bool = False
    scan_failed: bool = False
    wade_changed: bool = False
    new_script_hosts: list[str] = field(default_factory=list)
    failing_engines: list[str] = field(default_factory=list)

    @property
    def confirmed_risk_count(self) -> int:
        return self.finding_type_counts.get("confirmed_risk", 0)

    @property
    def likely_risk_count(self) -> int:
        return self.finding_type_counts.get("likely_risk", 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "finding_type_counts": dict(self.finding_type_counts),
            "third_party_domains": list(self.third_party_domains),
            "threat_correlation_types": list(self.threat_correlation_types),
            "has_compromise_story": self.has_compromise_story,
            "framework": self.framework,
            "last_scan_at": self.last_scan_at,
            "scan_count": self.scan_count,
            "change_frequency": self.change_frequency,
            "open_alert_count": self.open_alert_count,
            "has_tls_issue": self.has_tls_issue,
            "has_admin_exposure": self.has_admin_exposure,
            "scan_failed": self.scan_failed,
            "wade_changed": self.wade_changed,
            "new_script_hosts": list(self.new_script_hosts),
            "failing_engines": list(self.failing_engines),
        }

    @classmethod
    def from_scan_metadata(
        cls, metadata: dict[str, Any] | None,
    ) -> "SiteScanSummary":
        m = metadata or {}
        breakdown = m.get("risk_breakdown") or {}
        stories = m.get("security_stories") or []
        corr = m.get("threat_correlations") or []
        frameworks = m.get("frameworks") or {}
        timeline = m.get("wade_timeline") or {}
        third_party = (m.get("external_script_domains")
                       or m.get("external_domains") or [])
        # Browser-observed third parties if present.
        bp = m.get("browser_pass") or {}
        if bp.get("browser_third_party_domains"):
            third_party = sorted(set(list(third_party)
                                     + bp["browser_third_party_domains"]))
        # Phase-16 signals derived from the report sections / WADE.
        report_sections = m.get("report_sections") or {}
        sec_risks = report_sections.get("security_risks") or []
        admin_exposure = any(
            "admin" in (e.get("title", "").lower())
            for e in sec_risks)
        wade_changed = bool(m.get("wade_anomaly_count", 0))
        return cls(
            risk_score=int(m.get("risk_score", 0) or 0),
            risk_level=str(m.get("risk_level", "safe")),
            finding_type_counts=dict(breakdown.get("type_counts") or {}),
            third_party_domains=list(third_party),
            threat_correlation_types=[c.get("correlation_type")
                                      for c in corr
                                      if c.get("correlation_type")],
            has_compromise_story=any(
                s.get("correlation_type") == "possible_compromise"
                for s in stories),
            framework=frameworks.get("primary_framework"),
            last_scan_at=m.get("scan_completed_at"),
            scan_count=int(m.get("scan_count", 1) or 1),
            change_frequency=int(timeline.get("recurring_count", 0) or 0),
            has_admin_exposure=admin_exposure,
            wade_changed=wade_changed,
        )


@dataclass
class SiteRecord:
    """One monitored site + its ownership/classification metadata."""

    site_id: str
    url: str
    owner: str = ""
    organization: str = ""
    industry: str = ""
    plan: str = "standard"
    tags: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)   # client-group ids
    summary: SiteScanSummary = field(default_factory=SiteScanSummary)

    def has_tag(self, tag: str) -> bool:
        return tag in self.tags

    def in_group(self, group_id: str) -> bool:
        return group_id in self.groups

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "url": self.url,
            "owner": self.owner,
            "organization": self.organization,
            "industry": self.industry,
            "plan": self.plan,
            "tags": list(self.tags),
            "groups": list(self.groups),
            "summary": self.summary.to_dict(),
        }


class SiteRegistry:
    """Holds the sites one customer/agency monitors. Scales 1→100+."""

    def __init__(self) -> None:
        self._sites: dict[str, SiteRecord] = {}

    def add(self, record: SiteRecord) -> None:
        self._sites[record.site_id] = record

    def remove(self, site_id: str) -> None:
        self._sites.pop(site_id, None)

    def get(self, site_id: str) -> SiteRecord | None:
        return self._sites.get(site_id)

    def update_summary(self, site_id: str, summary: SiteScanSummary) -> bool:
        rec = self._sites.get(site_id)
        if rec is None:
            return False
        rec.summary = summary
        return True

    @property
    def count(self) -> int:
        return len(self._sites)

    def all(self) -> list[SiteRecord]:
        return list(self._sites.values())

    def by_organization(self, org: str) -> list[SiteRecord]:
        return [s for s in self._sites.values() if s.organization == org]

    def by_tag(self, tag: str) -> list[SiteRecord]:
        return [s for s in self._sites.values() if s.has_tag(tag)]

    def by_group(self, group_id: str) -> list[SiteRecord]:
        return [s for s in self._sites.values() if s.in_group(group_id)]

    def by_industry(self, industry: str) -> list[SiteRecord]:
        return [s for s in self._sites.values() if s.industry == industry]

    def filter(self, predicate) -> list[SiteRecord]:
        return [s for s in self._sites.values() if predicate(s)]

    @classmethod
    def from_records(cls, records: Iterable[SiteRecord]) -> "SiteRegistry":
        reg = cls()
        for r in records:
            reg.add(r)
        return reg
