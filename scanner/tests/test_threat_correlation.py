# WebHound — tests/test_threat_correlation.py
# Phase-13 Task 6/9: threat correlation + WADE vendor-event mapping.

from __future__ import annotations

from webhound.threat_intel.feed_normalizer import ThreatCategory
from webhound.threat_intel.supply_chain import (
    SupplyChainChange,
    SupplyChainChangeType,
    SupplyChainSeverity,
)
from webhound.threat_intel.threat_correlation import (
    ThreatCorrelationType,
    ThreatSignals,
    WadeVendorEvent,
    classify_wade_vendor_event,
    correlate_threats,
)


def _types(cs):
    return {c.correlation_type for c in cs}


def test_skimmer_from_feed_hit() -> None:
    cs = correlate_threats(ThreatSignals(
        feed_hits=[{"x": 1}],
        feed_categories=[ThreatCategory.SKIMMER]))
    skim = next(c for c in cs
                if c.correlation_type == ThreatCorrelationType.POSSIBLE_SKIMMER)
    assert skim.severity == "critical"
    assert skim.confidence == "high"


def test_skimmer_from_converging_signals() -> None:
    cs = correlate_threats(ThreatSignals(
        unknown_scripts=["unknown-x.test"],
        unknown_iframes=["evil-frame.test"],
        wade_changed=True))
    assert ThreatCorrelationType.POSSIBLE_SKIMMER in _types(cs)


def test_no_skimmer_from_single_signal() -> None:
    # Unknown script alone is not a skimmer story.
    cs = correlate_threats(ThreatSignals(unknown_scripts=["x.test"]))
    assert ThreatCorrelationType.POSSIBLE_SKIMMER not in _types(cs)


def test_phishing_from_impersonation() -> None:
    cs = correlate_threats(ThreatSignals(
        impersonation_hosts=["paypa1.com"]))
    assert ThreatCorrelationType.POSSIBLE_PHISHING_INFRA in _types(cs)


def test_supply_chain_risk_from_critical_change() -> None:
    change = SupplyChainChange(
        SupplyChainChangeType.KNOWN_REPLACED_BY_MALICIOUS,
        SupplyChainSeverity.CRITICAL, host="evil.test",
        replaced_host="js.stripe.com", category="payment",
        detail="stripe replaced by malicious evil.test")
    cs = correlate_threats(ThreatSignals(supply_chain_changes=[change]))
    sc = next(c for c in cs
              if c.correlation_type == ThreatCorrelationType.SUPPLY_CHAIN_RISK)
    assert sc.severity == "critical"
    assert "stripe" in sc.signals[0]


def test_possible_compromise_from_feed_plus_change() -> None:
    cs = correlate_threats(ThreatSignals(
        feed_hits=[{"x": 1}],
        feed_categories=[ThreatCategory.MALWARE],
        wade_changed=True,
        unknown_domains=["sketchy.test"]))
    # Malware feed + WADE change, no skimmer/phishing/supply specifics →
    # compromise story.
    assert ThreatCorrelationType.POSSIBLE_COMPROMISE in _types(cs)


def test_clean_signals_no_correlation() -> None:
    assert correlate_threats(ThreatSignals()) == []


# ---------------------------------------------------------------------------
# WADE vendor events (Task 9)
# ---------------------------------------------------------------------------


def test_wade_vendor_event_mapping() -> None:
    def ev(t, sev=SupplyChainSeverity.INFO):
        return classify_wade_vendor_event(
            SupplyChainChange(t, sev, host="h"))

    assert ev(SupplyChainChangeType.NEW_KNOWN_VENDOR) == \
        WadeVendorEvent.KNOWN_VENDOR_ADDED
    assert ev(SupplyChainChangeType.NEW_CDN) == \
        WadeVendorEvent.KNOWN_VENDOR_ADDED
    assert ev(SupplyChainChangeType.NEW_UNKNOWN_VENDOR) == \
        WadeVendorEvent.UNKNOWN_VENDOR_ADDED
    assert ev(SupplyChainChangeType.VENDOR_REMOVED) == \
        WadeVendorEvent.KNOWN_VENDOR_REMOVED
    assert ev(SupplyChainChangeType.KNOWN_REPLACED_BY_UNKNOWN) == \
        WadeVendorEvent.UNKNOWN_VENDOR_REPLACED
    assert ev(SupplyChainChangeType.KNOWN_REPLACED_BY_MALICIOUS) == \
        WadeVendorEvent.THREAT_INTEL_HIT
    assert ev(SupplyChainChangeType.NEW_MALICIOUS_VENDOR) == \
        WadeVendorEvent.THREAT_INTEL_HIT
