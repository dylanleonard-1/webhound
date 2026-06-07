# WebHound — tests/test_domain_reputation.py
# Phase-13 Task 2/5/7/8: brand impersonation + domain reputation.

from __future__ import annotations

from webhound.threat_intel.brand_impersonation import (
    BrandClass,
    ImpersonationTechnique,
    assess_domain,
)
from webhound.threat_intel.domain_reputation import (
    DomainReputationEngine,
    ReputationClass,
)
from webhound.threat_intel.feed_manager import FeedManager
from webhound.threat_intel.feed_normalizer import normalize_urlhaus


# ---------------------------------------------------------------------------
# Brand impersonation (Task 5)
# ---------------------------------------------------------------------------


def test_legit_brand_not_impersonation() -> None:
    assert assess_domain("https://www.paypal.com/").is_impersonation is False
    assert assess_domain("js.stripe.com").is_impersonation is False


def test_typosquat_detected() -> None:
    v = assess_domain("https://paypl.com/login")      # dropped a char
    assert v.is_impersonation
    assert v.brand == "paypal"
    assert v.brand_class == BrandClass.PAYMENT


def test_homoglyph_detected() -> None:
    # Cyrillic 'а' in p­аypal
    v = assess_domain("https://pаypal.com/")
    assert v.is_impersonation
    assert v.technique == ImpersonationTechnique.HOMOGLYPH
    assert v.brand == "paypal"


def test_combosquat_detected() -> None:
    v = assess_domain("https://stripe-secure-checkout.com/")
    assert v.is_impersonation
    assert v.brand == "stripe"
    assert v.technique == ImpersonationTechnique.COMBOSQUAT


def test_brand_on_other_tld() -> None:
    v = assess_domain("https://okta.tk/")
    assert v.is_impersonation
    assert v.brand == "okta"
    assert v.brand_class == BrandClass.AUTH


def test_unrelated_domain_not_impersonation() -> None:
    assert assess_domain("https://my-random-blog-1234.com/").is_impersonation \
        is False


# ---------------------------------------------------------------------------
# Domain reputation (Task 2/7/8)
# ---------------------------------------------------------------------------


def test_trusted_vendor_is_trusted_no_alert() -> None:
    eng = DomainReputationEngine()
    rep = eng.assess("https://cdn.cloudflare.com/x.js")
    assert rep.reputation in (ReputationClass.TRUSTED,
                              ReputationClass.KNOWN_VENDOR)
    assert rep.should_alert is False


def test_known_payment_vendor_no_alert() -> None:
    eng = DomainReputationEngine()
    rep = eng.assess("https://js.stripe.com/v3/")
    assert rep.reputation == ReputationClass.KNOWN_VENDOR
    assert rep.vendor_category == "payment"
    assert rep.should_alert is False


def test_feed_hit_is_malicious_and_alerts() -> None:
    fm = FeedManager()
    fm.ingest(normalize_urlhaus([
        {"url": "http://evil-skim.test/a.js", "threat": "skimmer",
         "url_status": "online"}]))
    eng = DomainReputationEngine(feed_manager=fm)
    rep = eng.assess("https://evil-skim.test/a.js")
    assert rep.reputation == ReputationClass.MALICIOUS
    assert rep.feed_hit is True
    assert rep.should_alert is True
    assert "urlhaus" in rep.feed_sources


def test_impersonation_domain_flagged() -> None:
    eng = DomainReputationEngine()
    rep = eng.assess("https://pаypal.com/")     # homoglyph
    assert rep.reputation == ReputationClass.MALICIOUS
    assert rep.impersonation is not None
    assert rep.should_alert is True


def test_feed_hit_overrides_trusted_classification() -> None:
    # Even a host that would classify benign alerts if a feed flags it.
    fm = FeedManager()
    fm.ingest(normalize_urlhaus([
        {"url": "http://compromised-cdn.test/x", "threat": "malware",
         "url_status": "online"}]))
    eng = DomainReputationEngine(feed_manager=fm)
    rep = eng.assess("compromised-cdn.test")
    assert rep.reputation == ReputationClass.MALICIOUS


def test_unknown_domain_is_unknown_no_alert() -> None:
    eng = DomainReputationEngine()
    rep = eng.assess("https://acmewidgets.com/")    # no soft signals
    assert rep.reputation in (ReputationClass.UNKNOWN, ReputationClass.NORMAL)
    assert rep.should_alert is False


def test_soft_suspicious_domain_does_not_alert() -> None:
    """A domain that's only mildly suspicious (excessive hyphens) is
    noted but must not alert without feed/impersonation context (Task 8)."""
    eng = DomainReputationEngine()
    rep = eng.assess("https://some-new-startup-xyz-portal.com/")
    assert rep.should_alert is False


def test_reputation_cached_stable() -> None:
    eng = DomainReputationEngine()
    r1 = eng.assess("https://js.stripe.com/")
    r2 = eng.assess("https://js.stripe.com/")
    assert r1.reputation == r2.reputation
