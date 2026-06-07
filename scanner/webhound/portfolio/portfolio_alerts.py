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
    # Phase-16 portfolio alert types.
    SHARED_VENDOR_CHANGE = "shared_vendor_change"
    SHARED_SCRIPT_CHANGE = "shared_script_change"
    MULTI_SITE_THREAT_INDICATOR = "multi_site_threat_indicator"
    MULTI_SITE_TLS_ISSUE = "multi_site_tls_issue"
    MULTI_SITE_ADMIN_EXPOSURE = "multi_site_admin_exposure"
    MULTI_SITE_SCAN_FAILURE = "multi_site_scan_failure"
    MULTI_SITE_WADE_CHANGE = "multi_site_wade_change"


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

    # --- Phase-16: shared per-site operational signals ------------------
    def _sites_where(pred) -> list[str]:
        return [r.site_id for r in sites if pred(r.summary)]

    tls_sites = _sites_where(lambda s: s.has_tls_issue)
    if len(tls_sites) >= min_sites:
        alerts.append(CrossSiteAlert(
            alert_type=CrossSiteAlertType.MULTI_SITE_TLS_ISSUE,
            severity=CrossSiteSeverity.HIGH,
            title=f"TLS issue on {len(tls_sites)} sites",
            detail=("Several sites share a TLS/certificate problem — often a "
                    "shared wildcard cert or a single expiring certificate "
                    "across locations."),
            affected_site_ids=sorted(tls_sites)))

    admin_sites = _sites_where(lambda s: s.has_admin_exposure)
    if len(admin_sites) >= min_sites:
        alerts.append(CrossSiteAlert(
            alert_type=CrossSiteAlertType.MULTI_SITE_ADMIN_EXPOSURE,
            severity=CrossSiteSeverity.HIGH,
            title=f"Admin surface exposed on {len(admin_sites)} sites",
            detail=("Multiple sites expose an administrative surface — likely "
                    "a shared platform/template. Restrict them together."),
            affected_site_ids=sorted(admin_sites)))

    failed_sites = _sites_where(lambda s: s.scan_failed)
    if len(failed_sites) >= min_sites:
        alerts.append(CrossSiteAlert(
            alert_type=CrossSiteAlertType.MULTI_SITE_SCAN_FAILURE,
            severity=CrossSiteSeverity.MEDIUM,
            title=f"Scans failing on {len(failed_sites)} sites",
            detail=("Several sites failed to scan — could be shared "
                    "infrastructure, a WAF blocking the scanner, or an "
                    "outage. Coverage is degraded until resolved."),
            affected_site_ids=sorted(failed_sites)))

    wade_sites = _sites_where(lambda s: s.wade_changed)
    if len(wade_sites) >= min_sites:
        alerts.append(CrossSiteAlert(
            alert_type=CrossSiteAlertType.MULTI_SITE_WADE_CHANGE,
            severity=CrossSiteSeverity.MEDIUM,
            title=f"Changes detected on {len(wade_sites)} sites this period",
            detail=("Multiple sites changed since their last scan. Review the "
                    "grouped changes to confirm they were expected "
                    "deployments rather than coordinated tampering."),
            affected_site_ids=sorted(wade_sites)))

    # Shared engine failures (MULTI_SITE_SCAN_FAILURE companion).
    engine_sites: dict[str, set[str]] = defaultdict(set)
    for rec in sites:
        for eng in rec.summary.failing_engines:
            engine_sites[eng].add(rec.site_id)
    for eng, sids in engine_sites.items():
        if len(sids) >= max(min_sites, 3):
            alerts.append(CrossSiteAlert(
                alert_type=CrossSiteAlertType.MULTI_SITE_SCAN_FAILURE,
                severity=CrossSiteSeverity.LOW,
                title=f"Engine '{eng}' failing across {len(sids)} sites",
                detail=(f"The {eng} engine errored on {len(sids)} sites — "
                        "likely a systemic issue, not site-specific."),
                affected_site_ids=sorted(sids), shared_indicator=eng))

    # --- Shared NEW scripts/vendors (change-oriented) -------------------
    new_script_sites: dict[str, set[str]] = defaultdict(set)
    for rec in sites:
        for host in rec.summary.new_script_hosts:
            new_script_sites[_registrable(host)].add(rec.site_id)
    for vendor, sids in new_script_sites.items():
        if len(sids) < min_sites or _is_trusted(vendor):
            continue
        alerts.append(CrossSiteAlert(
            alert_type=CrossSiteAlertType.SHARED_SCRIPT_CHANGE,
            severity=CrossSiteSeverity.HIGH,
            title=f"New script '{vendor}' appeared on {len(sids)} sites",
            detail=(f"The same new third-party script ('{vendor}') was added "
                    f"to {len(sids)} sites at once — a coordinated change "
                    "worth confirming was intentional."),
            affected_site_ids=sorted(sids), shared_indicator=vendor))

    # Deduplicate (Task 5: do not duplicate). Two alerts collapse when
    # they share (type, indicator, affected-site set) — the higher
    # severity wins. This guarantees a customer never sees the same
    # cross-site story twice.
    deduped: dict[tuple, CrossSiteAlert] = {}
    for a in alerts:
        key = (a.alert_type.value, a.shared_indicator or "",
               tuple(sorted(a.affected_site_ids)))
        prev = deduped.get(key)
        if prev is None or _sev_rank(a) > _sev_rank(prev):
            deduped[key] = a
    alerts = list(deduped.values())

    # Most-affected / most-severe first.
    alerts.sort(key=lambda a: (_sev_rank(a), a.affected_count), reverse=True)
    return alerts


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _sev_rank(a: "CrossSiteAlert") -> int:
    return _SEV_RANK[a.severity.value]


@dataclass
class PortfolioWadeSummary:
    """Portfolio-WADE rollup (Task 5): the cross-site change picture
    without duplicating each site's individual alerts."""

    sites_changed: list[str] = field(default_factory=list)
    sites_with_suspicious_changes: list[str] = field(default_factory=list)
    sites_with_new_third_parties: list[str] = field(default_factory=list)
    sites_riskier: list[str] = field(default_factory=list)
    sites_improved: list[str] = field(default_factory=list)
    shared_changes: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sites_changed": list(self.sites_changed),
            "sites_with_suspicious_changes":
                list(self.sites_with_suspicious_changes),
            "sites_with_new_third_parties":
                list(self.sites_with_new_third_parties),
            "sites_riskier": list(self.sites_riskier),
            "sites_improved": list(self.sites_improved),
            "shared_changes": list(self.shared_changes),
            "changed_count": len(self.sites_changed),
        }


def summarize_portfolio_wade(sites: list[SiteRecord]) -> PortfolioWadeSummary:
    """Answer the Task-5 portfolio-WADE questions across the portfolio,
    grouping related changes instead of repeating per-site alerts.

    ``sites_riskier`` / ``sites_improved`` use each site's risk
    *direction* when the caller has supplied it via summary.metadata
    (``risk_direction`` in {increased, decreased}); otherwise they stay
    empty (a single scan has no direction)."""
    out = PortfolioWadeSummary()
    SUSPICIOUS = {"suspicious_script_change", "suspicious_iframe",
                  "suspicious_redirect", "possible_compromise",
                  "possible_skimmer", "possible_website_compromise"}
    for rec in sites:
        s = rec.summary
        if s.wade_changed or s.change_frequency:
            out.sites_changed.append(rec.site_id)
        if s.has_compromise_story or any(
                t in SUSPICIOUS for t in s.threat_correlation_types):
            out.sites_with_suspicious_changes.append(rec.site_id)
        if s.new_script_hosts:
            out.sites_with_new_third_parties.append(rec.site_id)
        direction = s.risk_direction
        if direction == "increased":
            out.sites_riskier.append(rec.site_id)
        elif direction == "decreased":
            out.sites_improved.append(rec.site_id)

    # Shared changes: the same NEW script host appearing on >= 2 sites.
    shared: dict[str, set[str]] = defaultdict(set)
    for rec in sites:
        for host in rec.summary.new_script_hosts:
            shared[_registrable(host)].add(rec.site_id)
    out.shared_changes = [
        {"indicator": v, "site_ids": sorted(sids), "site_count": len(sids)}
        for v, sids in shared.items() if len(sids) >= 2]
    return out


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
