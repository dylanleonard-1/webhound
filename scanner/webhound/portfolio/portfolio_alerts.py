# WebHound — scanner/webhound/portfolio/portfolio_alerts.py
# Phase-17 Task 3/5: cross-site alerts + portfolio WADE. Looks ACROSS a
# portfolio for shared risk — the same vendor, script host, threat-intel
# indicator, or compromise pattern affecting multiple sites at once — and
# for shared anomalies (the portfolio-WADE comparison).
#
# A shared risk across many sites is materially more important than the
# same finding on one site: it's a single point of failure for the whole
# portfolio (e.g. an agency's shared analytics vendor gets compromised).

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webhound.portfolio.site_registry import SiteRecord


class CrossSiteAlertType(str, Enum):
    SHARED_VENDOR_RISK = "shared_vendor_risk"
    SHARED_SCRIPT_RISK = "shared_script_risk"
    SHARED_THREAT_INDICATOR = "shared_threat_indicator"
    SHARED_COMPROMISE = "shared_compromise_pattern"
    WIDESPREAD_ISSUE = "widespread_issue"


class CrossSiteSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CrossSiteAlert:
    alert_type: CrossSiteAlertType
    severity: CrossSiteSeverity
    title: str
    detail: str
    affected_site_ids: list[str] = field(default_factory=list)
    shared_indicator: str | None = None

    @property
    def affected_count(self) -> int:
        return len(self.affected_site_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "affected_count": self.affected_count,
            "affected_site_ids": list(self.affected_site_ids),
            "shared_indicator": self.shared_indicator,
        }


def _registrable(host: str) -> str:
    try:
        from webhound.browser.network_capture import _registrable as _r
        return _r(host)
    except Exception:  # noqa: BLE001
        return host


# Known-vendor hosts that being shared is EXPECTED (an agency using GA on
# every client site is normal, not an alert) — suppress these unless a
# threat indicator is attached.
def _is_trusted(host: str) -> bool:
    try:
        from webhound.threat_intel.domain_classifier import (
            DomainClass, DomainClassifier,
        )
        cls = DomainClassifier().classify(host)
        return cls.classification in (DomainClass.TRUSTED,
                                      DomainClass.COMMON_BENIGN)
    except Exception:  # noqa: BLE001
        return False


def detect_cross_site_alerts(
    sites: list[SiteRecord], *, min_sites: int = 2,
) -> list[CrossSiteAlert]:
    """Find risks shared across >= min_sites sites in the portfolio."""
    alerts: list[CrossSiteAlert] = []
    n = len(sites)
    if n < min_sites:
        return alerts

    # --- Shared third-party vendors (unknown ones are the concern) ------
    vendor_sites: dict[str, set[str]] = defaultdict(set)
    for rec in sites:
        for host in rec.summary.third_party_domains:
            vendor_sites[_registrable(host)].add(rec.site_id)
    for vendor, site_ids in vendor_sites.items():
        if len(site_ids) < min_sites:
            continue
        if _is_trusted(vendor):
            continue                       # shared GA/Stripe/etc. is normal
        share = len(site_ids) / n
        sev = (CrossSiteSeverity.HIGH if share >= 0.5
               else CrossSiteSeverity.MEDIUM)
        alerts.append(CrossSiteAlert(
            alert_type=CrossSiteAlertType.SHARED_VENDOR_RISK,
            severity=sev,
            title=f"Unrecognised vendor on {len(site_ids)} sites: {vendor}",
            detail=(f"{len(site_ids)} of your {n} sites load from the "
                    f"unrecognised third party '{vendor}'. A shared "
                    "third-party is a single point of failure — if it's "
                    "compromised, every site that uses it is affected."),
            affected_site_ids=sorted(site_ids), shared_indicator=vendor))

    # --- Shared threat-intel indicators ---------------------------------
    corr_sites: dict[str, set[str]] = defaultdict(set)
    for rec in sites:
        for ctype in rec.summary.threat_correlation_types:
            corr_sites[ctype].add(rec.site_id)
    for ctype, site_ids in corr_sites.items():
        if len(site_ids) < min_sites:
            continue
        alerts.append(CrossSiteAlert(
            alert_type=CrossSiteAlertType.SHARED_THREAT_INDICATOR,
            severity=CrossSiteSeverity.HIGH,
            title=f"'{ctype}' detected across {len(site_ids)} sites",
            detail=(f"The same threat-intel correlation ({ctype}) fired on "
                    f"{len(site_ids)} sites — a coordinated pattern worth "
                    "investigating as one incident."),
            affected_site_ids=sorted(site_ids), shared_indicator=ctype))

    # --- Shared compromise pattern --------------------------------------
    compromised = [r.site_id for r in sites if r.summary.has_compromise_story]
    if len(compromised) >= min_sites:
        alerts.append(CrossSiteAlert(
            alert_type=CrossSiteAlertType.SHARED_COMPROMISE,
            severity=CrossSiteSeverity.CRITICAL,
            title=f"Possible compromise on {len(compromised)} sites",
            detail=("Multiple sites in your portfolio show compromise "
                    "indicators at the same time. This can signal a "
                    "shared-infrastructure or supply-chain attack affecting "
                    "your whole portfolio."),
            affected_site_ids=sorted(compromised)))

    # --- Widespread elevated risk ---------------------------------------
    high_risk = [r.site_id for r in sites
                 if r.summary.risk_level in ("high", "critical")]
    if len(high_risk) >= max(min_sites, n // 2) and n >= 3:
        alerts.append(CrossSiteAlert(
            alert_type=CrossSiteAlertType.WIDESPREAD_ISSUE,
            severity=CrossSiteSeverity.HIGH,
            title=f"{len(high_risk)} of {n} sites at high/critical risk",
            detail=("A large share of your portfolio is at elevated risk — "
                    "consider a portfolio-wide remediation push."),
            affected_site_ids=sorted(high_risk)))

    # Most-affected / most-severe first.
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    alerts.sort(key=lambda a: (sev_rank[a.severity.value], a.affected_count),
                reverse=True)
    return alerts


# ---------------------------------------------------------------------------
# Portfolio WADE (Task 5): compare sites that SHOULD look alike (franchise
# locations, store locations) and flag the odd ones out.
# ---------------------------------------------------------------------------


@dataclass
class PortfolioDiff:
    shared_vendors: list[str] = field(default_factory=list)
    outlier_sites: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "shared_vendors": list(self.shared_vendors),
            "outlier_sites": list(self.outlier_sites),
        }


def compare_sites(sites: list[SiteRecord]) -> PortfolioDiff:
    """Portfolio-WADE: among sites expected to be similar, find the shared
    baseline (vendors present on most) and the outliers (sites carrying
    vendors none of their peers have — the 'unexpected difference')."""
    diff = PortfolioDiff()
    n = len(sites)
    if n < 2:
        return diff

    vendor_counts: dict[str, int] = defaultdict(int)
    per_site: dict[str, set[str]] = {}
    for rec in sites:
        vs = {_registrable(h) for h in rec.summary.third_party_domains}
        per_site[rec.site_id] = vs
        for v in vs:
            vendor_counts[v] += 1

    # Shared baseline: vendors on > half the sites.
    diff.shared_vendors = sorted(
        v for v, c in vendor_counts.items() if c > n / 2)

    # Outliers: sites carrying a vendor that ONLY they have.
    for rec in sites:
        unique = [v for v in per_site[rec.site_id]
                  if vendor_counts[v] == 1 and not _is_trusted(v)]
        if unique:
            diff.outlier_sites.append({
                "site_id": rec.site_id, "url": rec.url,
                "unique_vendors": sorted(unique)})
    return diff
