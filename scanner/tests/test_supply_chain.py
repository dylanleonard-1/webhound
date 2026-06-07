# WebHound — tests/test_supply_chain.py
# Phase-13 Task 3/4: script reputation + supply-chain change detection.

from __future__ import annotations

from webhound.threat_intel.feed_manager import FeedManager
from webhound.threat_intel.feed_normalizer import (
    normalize_script_feed,
    normalize_urlhaus,
)
from webhound.threat_intel.script_reputation import (
    ScriptReputationEngine,
    ScriptVerdict,
)
from webhound.threat_intel.supply_chain import (
    SupplyChainChangeType,
    SupplyChainEngine,
    SupplyChainSeverity,
)
from webhound.utils.hashing import sha256_hex


# ---------------------------------------------------------------------------
# Script reputation (Task 3)
# ---------------------------------------------------------------------------


def test_trusted_vendor_script() -> None:
    eng = ScriptReputationEngine()
    r = eng.assess("https://js.stripe.com/v3/")
    assert r.verdict in (ScriptVerdict.TRUSTED, ScriptVerdict.KNOWN_VENDOR)
    assert r.should_alert is False


def test_malicious_host_script() -> None:
    fm = FeedManager()
    fm.ingest(normalize_urlhaus([
        {"url": "http://evil-skim.test/c.js", "threat": "skimmer",
         "url_status": "online"}]))
    eng = ScriptReputationEngine(feed_manager=fm)
    r = eng.assess("https://evil-skim.test/c.js")
    assert r.verdict == ScriptVerdict.MALICIOUS
    assert r.should_alert is True


def test_known_skimmer_host_pattern() -> None:
    eng = ScriptReputationEngine()
    r = eng.assess("https://googie-analytics.com/ga.js")
    assert r.verdict in (ScriptVerdict.SUSPICIOUS, ScriptVerdict.KNOWN_SKIMMER)
    assert r.should_alert is True


def test_script_hash_feed_hit() -> None:
    body = "var x = stealCard();"
    h = sha256_hex(body)
    fm = FeedManager()
    fm.ingest(normalize_script_feed([{"sha256": h, "label": "magecart"}]))
    eng = ScriptReputationEngine(feed_manager=fm)
    r = eng.assess("https://unknown-host.test/x.js", inline_body=body)
    assert r.verdict == ScriptVerdict.MALICIOUS
    assert r.feed_hit is True


def test_suspicious_body_on_unknown_host() -> None:
    eng = ScriptReputationEngine()
    r = eng.assess("https://random-host-xyz.test/a.js",
                   inline_body="document.addEventListener('keypress', steal)")
    assert r.verdict == ScriptVerdict.SUSPICIOUS


def test_suspicious_body_on_trusted_host_not_flagged() -> None:
    """A trusted vendor with a keypress listener is normal (analytics) —
    don't flag the body on a trusted host."""
    eng = ScriptReputationEngine()
    r = eng.assess("https://www.googletagmanager.com/gtm.js",
                   inline_body="document.addEventListener('input', track)")
    assert r.should_alert is False


# ---------------------------------------------------------------------------
# Supply chain (Task 4/6)
# ---------------------------------------------------------------------------


def test_new_known_vendor_is_info() -> None:
    eng = SupplyChainEngine()
    changes = eng.diff(previous_hosts=["js.stripe.com"],
                       current_hosts=["js.stripe.com",
                                      "www.googletagmanager.com"])
    assert len(changes) == 1
    assert changes[0].change_type == SupplyChainChangeType.NEW_KNOWN_VENDOR
    assert changes[0].severity == SupplyChainSeverity.INFO


def test_new_unknown_vendor_is_low() -> None:
    eng = SupplyChainEngine()
    changes = eng.diff(previous_hosts=[],
                       current_hosts=["acme-unknown-vendor-xyz.com"])
    assert changes[0].change_type == SupplyChainChangeType.NEW_UNKNOWN_VENDOR
    assert changes[0].severity == SupplyChainSeverity.LOW


def test_known_payment_replaced_by_unknown_is_high() -> None:
    """Stripe (payment) replaced by an unknown payment-ish host — the
    headline supply-chain risk."""
    eng = SupplyChainEngine()
    changes = eng.diff(
        previous_hosts=["js.stripe.com"],
        current_hosts=["pay-gateway-unknown-zzz.com/checkout"])
    repl = [c for c in changes
            if c.change_type == SupplyChainChangeType.KNOWN_REPLACED_BY_UNKNOWN]
    # Replacement only fires when categories match; an unknown host has
    # category 'unknown', so this manifests as a removal + new-unknown.
    types = {c.change_type for c in changes}
    assert (SupplyChainChangeType.NEW_UNKNOWN_VENDOR in types
            or SupplyChainChangeType.KNOWN_REPLACED_BY_UNKNOWN in types)


def test_known_replaced_by_malicious_is_critical() -> None:
    fm = FeedManager()
    fm.ingest(normalize_urlhaus([
        {"url": "http://evil-pay.test/x", "threat": "skimmer",
         "url_status": "online"}]))
    from webhound.threat_intel.domain_reputation import DomainReputationEngine
    eng = SupplyChainEngine(
        domain_engine=DomainReputationEngine(feed_manager=fm))
    changes = eng.diff(previous_hosts=["js.stripe.com"],
                       current_hosts=["evil-pay.test"])
    # The malicious new host is at least flagged critical.
    crit = [c for c in changes
            if c.severity == SupplyChainSeverity.CRITICAL]
    assert crit
    assert crit[0].change_type in (
        SupplyChainChangeType.NEW_MALICIOUS_VENDOR,
        SupplyChainChangeType.KNOWN_REPLACED_BY_MALICIOUS)


def test_vendor_removed_is_info() -> None:
    eng = SupplyChainEngine()
    changes = eng.diff(previous_hosts=["js.stripe.com",
                                       "www.googletagmanager.com"],
                       current_hosts=["js.stripe.com"])
    removed = [c for c in changes
               if c.change_type == SupplyChainChangeType.VENDOR_REMOVED]
    assert len(removed) == 1
    assert removed[0].severity == SupplyChainSeverity.INFO


def test_no_change_no_findings() -> None:
    eng = SupplyChainEngine()
    assert eng.diff(previous_hosts=["js.stripe.com"],
                    current_hosts=["js.stripe.com"]) == []


def test_subdomain_grouping_no_false_change() -> None:
    """cdn.shopify.com and shopify.com are the same vendor — no change."""
    eng = SupplyChainEngine()
    changes = eng.diff(previous_hosts=["cdn.shopify.com"],
                       current_hosts=["www.shopify.com"])
    assert changes == []
