# WebHound — webhound/threat_intel/coverage.py
# Phase-5C: guarantees that *every* host in the canonical inventory
# flows through the threat-intel pipeline — no source bypasses the
# classification step.
#
# The orchestrator already runs ThreatIntelEngine.analyze_inventory
# over the aggregated host map (Phase-4). This module adds the audit
# layer: after the analysis pass it walks the inventory, records the
# classification on each HostInventoryEntry, validates no host was
# silently skipped, and emits a structured coverage report the
# dashboard + production-readiness module consume.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from webhound.core.url_discovery import HostInventoryEntry
from webhound.threat_intel.domain_classifier import (
    DomainClass,
    DomainClassifier,
)


@dataclass
class ThreatIntelCoverageReport:
    """Outcome of a coverage audit pass.

    ``unclassified_hosts`` is the gap list — hosts that the audit
    couldn't classify (the classifier raised or returned None). If
    this list is non-empty in production it's a real bug; the
    audit emits it so the dashboard can flag it and the production
    readiness check can fail closed.

    ``per_tier_count`` is the histogram of final classifications
    across the inventory (trusted / common_benign / suspicious /
    risky / malicious_indicator / unknown). The dashboard renders
    this as the threat-intel coverage tile."""

    total_hosts: int = 0
    classified_hosts: int = 0
    unclassified_hosts: list[str] = field(default_factory=list)
    per_tier_count: dict[str, int] = field(default_factory=dict)
    per_source_count: dict[str, int] = field(default_factory=dict)
    enriched_via_external_provider: int = 0

    @property
    def coverage_ratio(self) -> float:
        if self.total_hosts == 0:
            return 1.0
        return round(self.classified_hosts / self.total_hosts, 4)

    @property
    def has_coverage_gap(self) -> bool:
        return bool(self.unclassified_hosts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_hosts": self.total_hosts,
            "classified_hosts": self.classified_hosts,
            "unclassified_hosts": list(self.unclassified_hosts),
            "per_tier_count": dict(self.per_tier_count),
            "per_source_count": dict(self.per_source_count),
            "enriched_via_external_provider":
                self.enriched_via_external_provider,
            "coverage_ratio": self.coverage_ratio,
            "has_coverage_gap": self.has_coverage_gap,
        }


def audit_threat_intel_coverage(
    inventory: Mapping[str, HostInventoryEntry],
    *,
    classifier: DomainClassifier | None = None,
    already_enriched: set[str] | None = None,
) -> ThreatIntelCoverageReport:
    """Walk the scan-wide host inventory, run the local classifier
    against every host (cheap + offline), populate the entry's
    ``vendor_classification`` + ``threat_intel_state`` fields, and
    return a structured coverage report.

    ``already_enriched`` is the optional set of hosts the live
    enrichment service (VirusTotal etc.) checked this scan; those
    entries' ``vt_status`` is annotated so the dashboard can render
    a 'VT verdict available' indicator.

    Pure-function — no I/O. The DomainClassifier itself is offline-
    safe (static lists + heuristics)."""
    classifier = classifier or DomainClassifier()
    already_enriched = already_enriched or set()
    report = ThreatIntelCoverageReport(total_hosts=len(inventory))
    for host, entry in inventory.items():
        for src in entry.discovery_sources:
            report.per_source_count[src] = (
                report.per_source_count.get(src, 0) + 1
            )
        try:
            cls = classifier.classify(host)
        except Exception:  # noqa: BLE001
            report.unclassified_hosts.append(host)
            entry.threat_intel_state = "unavailable"
            continue
        if cls is None:
            report.unclassified_hosts.append(host)
            entry.threat_intel_state = "unavailable"
            continue
        # Populate the canonical-inventory downstream slots so the
        # JSON export carries them without the caller re-running
        # classification.
        entry.vendor_classification = cls.classification.value
        entry.threat_intel_state = "checked"
        report.classified_hosts += 1
        tier = cls.classification.value
        report.per_tier_count[tier] = (
            report.per_tier_count.get(tier, 0) + 1
        )
        # External-provider enrichment (VT etc.) is tracked
        # separately so 'classified' and 'externally checked' are
        # distinct signals.
        if host in already_enriched:
            entry.vt_status = "checked"
            report.enriched_via_external_provider += 1
    return report


def required_tiers_present(
    report: ThreatIntelCoverageReport,
) -> set[str]:
    """Return the set of DomainClass tier values present in the
    report. Used by the production-readiness module to verify a
    scan exercised every classifier branch."""
    return {tier for tier in DomainClass.__members__.values()
             if report.per_tier_count.get(tier.value, 0) > 0}
