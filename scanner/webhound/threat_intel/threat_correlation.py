# WebHound — scanner/webhound/threat_intel/threat_correlation.py
# Phase-13 Task 6/9: correlate threat-intel signals into named risks and
# give WADE a richer vendor-change vocabulary.
#
# Combines: threat-feed hits, supply-chain changes, unknown scripts,
# unknown iframes, unknown domains → one of:
#   Supply Chain Risk
#   Possible Skimmer
#   Possible Phishing Infrastructure
#   Possible Website Compromise
#
# Pure; consumes reputation/supply-chain outputs the caller gathered.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webhound.threat_intel.feed_normalizer import ThreatCategory
from webhound.threat_intel.supply_chain import (
    SupplyChainChange,
    SupplyChainChangeType,
)


class ThreatCorrelationType(str, Enum):
    SUPPLY_CHAIN_RISK = "supply_chain_risk"
    POSSIBLE_SKIMMER = "possible_skimmer"
    POSSIBLE_PHISHING_INFRA = "possible_phishing_infrastructure"
    POSSIBLE_COMPROMISE = "possible_website_compromise"


# Task 9: the vendor-change vocabulary WADE speaks.
class WadeVendorEvent(str, Enum):
    KNOWN_VENDOR_ADDED = "known_vendor_added"
    UNKNOWN_VENDOR_ADDED = "unknown_vendor_added"
    KNOWN_VENDOR_REMOVED = "known_vendor_removed"
    UNKNOWN_VENDOR_REPLACED = "unknown_vendor_replaced"
    THREAT_INTEL_HIT = "threat_intel_hit"
    SUPPLY_CHAIN_RISK = "supply_chain_risk"


@dataclass
class ThreatCorrelation:
    correlation_type: ThreatCorrelationType
    confidence: str                  # confirmed/high/medium/low/heuristic
    severity: str                    # info/low/medium/high/critical
    title: str
    narrative: str
    recommendation: str
    signals: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_type": self.correlation_type.value,
            "confidence": self.confidence,
            "severity": self.severity,
            "title": self.title,
            "narrative": self.narrative,
            "recommendation": self.recommendation,
            "signals": list(self.signals),
            "hosts": list(self.hosts),
        }


@dataclass
class ThreatSignals:
    """The inputs the correlator reasons over — caller fills what it has."""

    feed_hits: list[dict[str, Any]] = field(default_factory=list)      # FeedMatch-ish dicts
    feed_categories: list[ThreatCategory] = field(default_factory=list)
    supply_chain_changes: list[SupplyChainChange] = field(default_factory=list)
    unknown_scripts: list[str] = field(default_factory=list)          # hosts
    unknown_iframes: list[str] = field(default_factory=list)
    unknown_domains: list[str] = field(default_factory=list)
    impersonation_hosts: list[str] = field(default_factory=list)
    wade_changed: bool = False        # WADE saw a change this scan


def correlate_threats(signals: ThreatSignals) -> list[ThreatCorrelation]:
    """Produce named threat correlations from the gathered signals.

    Ordered most-severe first. Each rule requires CONVERGING evidence so
    a single soft signal never manufactures a scary story."""
    out: list[ThreatCorrelation] = []
    has_feed = bool(signals.feed_hits)
    skimmer_feed = (ThreatCategory.SKIMMER in signals.feed_categories)
    phishing_feed = (ThreatCategory.PHISHING in signals.feed_categories)
    crit_supply = [c for c in signals.supply_chain_changes
                   if c.severity in ("critical", "high")]

    # 1. Possible Skimmer: skimmer feed hit OR (unknown script + iframe +
    #    WADE change on the same scan) — the magecart footprint.
    if skimmer_feed or (signals.unknown_scripts and signals.unknown_iframes
                        and signals.wade_changed):
        out.append(ThreatCorrelation(
            ThreatCorrelationType.POSSIBLE_SKIMMER,
            confidence="high" if skimmer_feed else "medium",
            severity="critical" if skimmer_feed else "high",
            title="Possible Payment Skimmer",
            narrative=(
                "WebHound found indicators consistent with a payment "
                "skimmer (Magecart-style): an unrecognised script combined "
                "with a hidden iframe and recent change activity, or a "
                "direct threat-feed hit. Skimmers exfiltrate card data from "
                "checkout pages."),
            recommendation=(
                "Treat as an active incident on payment pages: snapshot the "
                "scripts, compare to your build, and rotate keys."),
            signals=_skimmer_signals(signals),
            hosts=_uniq(signals.unknown_scripts + signals.unknown_iframes)))

    # 2. Possible Phishing Infrastructure: phishing feed hit OR brand
    #    impersonation host present.
    if phishing_feed or signals.impersonation_hosts:
        out.append(ThreatCorrelation(
            ThreatCorrelationType.POSSIBLE_PHISHING_INFRA,
            confidence="high" if phishing_feed else "medium",
            severity="high",
            title="Possible Phishing Infrastructure",
            narrative=(
                "WebHound observed a domain associated with phishing — "
                "either flagged by a threat feed or impersonating a known "
                "brand (payment/auth provider)."),
            recommendation=(
                "Verify the domain is yours; if it impersonates a brand you "
                "don't control, report it for takedown."),
            signals=([f"impersonation: {h}" for h in signals.impersonation_hosts]
                     + (["phishing feed hit"] if phishing_feed else [])),
            hosts=_uniq(signals.impersonation_hosts)))

    # 3. Supply Chain Risk: a critical/high supply-chain change, or a feed
    #    hit on a third-party host.
    if crit_supply or (has_feed and signals.unknown_scripts):
        worst = crit_supply[0] if crit_supply else None
        out.append(ThreatCorrelation(
            ThreatCorrelationType.SUPPLY_CHAIN_RISK,
            confidence="high" if (crit_supply and worst
                                  and worst.severity == "critical") else "medium",
            severity=(worst.severity if worst else "high"),
            title="Supply Chain Risk",
            narrative=(
                "WebHound detected a change in the third-party code your "
                "site depends on that warrants review — a known vendor "
                "replaced, a flagged host added, or an unrecognised "
                "provider taking over a sensitive role."),
            recommendation=(
                "Confirm the vendor change was intentional; pin trusted "
                "scripts with SRI and tighten CSP to an explicit allowlist."),
            signals=[c.detail for c in signals.supply_chain_changes
                     if c.severity in ("critical", "high")][:5],
            hosts=_uniq([c.host for c in (crit_supply or [])])))

    # 4. Possible Website Compromise: a feed hit converging with WADE
    #    change activity but not matching a more specific story above.
    if (has_feed and signals.wade_changed and not out):
        out.append(ThreatCorrelation(
            ThreatCorrelationType.POSSIBLE_COMPROMISE,
            confidence="medium", severity="high",
            title="Possible Website Compromise",
            narrative=(
                "A threat-intelligence indicator was observed alongside "
                "recent changes to your site — together suggestive of "
                "tampering."),
            recommendation="Investigate recent deployments and the flagged "
                           "host before dismissing.",
            signals=["threat-feed hit", "recent WADE change"],
            hosts=_uniq(signals.unknown_domains)))

    return out


def classify_wade_vendor_event(change: SupplyChainChange) -> WadeVendorEvent:
    """Task 9: map a supply-chain change to WADE's vendor-event vocabulary."""
    t = change.change_type
    if t == SupplyChainChangeType.NEW_KNOWN_VENDOR or t == SupplyChainChangeType.NEW_CDN:
        return WadeVendorEvent.KNOWN_VENDOR_ADDED
    if t == SupplyChainChangeType.NEW_UNKNOWN_VENDOR:
        return WadeVendorEvent.UNKNOWN_VENDOR_ADDED
    if t == SupplyChainChangeType.VENDOR_REMOVED:
        return WadeVendorEvent.KNOWN_VENDOR_REMOVED
    if t in (SupplyChainChangeType.KNOWN_REPLACED_BY_UNKNOWN,):
        return WadeVendorEvent.UNKNOWN_VENDOR_REPLACED
    if t in (SupplyChainChangeType.NEW_MALICIOUS_VENDOR,
             SupplyChainChangeType.KNOWN_REPLACED_BY_MALICIOUS):
        return WadeVendorEvent.THREAT_INTEL_HIT
    return WadeVendorEvent.SUPPLY_CHAIN_RISK


def _skimmer_signals(s: ThreatSignals) -> list[str]:
    out = []
    if s.unknown_scripts:
        out.append(f"unknown script(s): {', '.join(s.unknown_scripts[:3])}")
    if s.unknown_iframes:
        out.append(f"unknown iframe(s): {', '.join(s.unknown_iframes[:3])}")
    if s.wade_changed:
        out.append("recent change activity (WADE)")
    if ThreatCategory.SKIMMER in s.feed_categories:
        out.append("skimmer threat-feed hit")
    return out


def _uniq(items: list[str]) -> list[str]:
    seen: list[str] = []
    for i in items:
        if i and i not in seen:
            seen.append(i)
    return seen
