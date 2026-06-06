# WebHound — tests/test_vendor_categories.py
# Phase-6C functional vendor categories: WHAT a vendor does, separate
# from its risk tier. Known services must classify as inventory-grade
# (trusted / common_benign), never as scary findings.

from __future__ import annotations

import pytest

from webhound.threat_intel.domain_classifier import (
    DomainClass,
    DomainClassifier,
    vendor_category,
)


@pytest.mark.parametrize("domain,category", [
    ("js.stripe.com", "payment"),
    ("www.paypal.com", "payment"),
    ("cdn.shopify.com", "commerce"),
    ("static.parastorage.com", "cdn"),         # Wix CDN
    ("assets.website-files.com", "cdn"),       # Webflow CDN
    ("www.webflow.com", "commerce"),
    ("www.google-analytics.com", "analytics"),
    ("www.googletagmanager.com", "analytics"),
    ("connect.facebook.net", "ads"),
    ("analytics.tiktok.com", "social"),
    ("static.klaviyo.com", "marketing"),
    ("js.hs-scripts.com", "marketing"),
    ("widget.intercom.io", "chat"),
    ("ekr.zdassets.com", "cdn"),               # Zendesk assets
    ("static.zendesk.com", "chat"),
    ("script.hotjar.com", "analytics"),
    ("cdn.auth0.com", "identity"),
    ("my-app.vercel.app", "hosting"),
    ("totally-unknown.example.org", "unknown"),
])
def test_vendor_category_mapping(domain, category) -> None:
    assert vendor_category(domain) == category


@pytest.mark.parametrize("domain", [
    "cdn.shopify.com", "www.wix.com", "static.klaviyo.com",
    "js.hubspot.com", "widget.intercom.io", "static.zendesk.com",
    "analytics.tiktok.com", "script.hotjar.com", "js.stripe.com",
    "www.paypal.com", "assets.webflow.com",
])
def test_known_services_are_inventory_grade(domain) -> None:
    """Task-7 contract: household vendors must never classify as
    suspicious/risky by default — they're inventory, not threats."""
    result = DomainClassifier().classify(domain)
    assert result.classification in (
        DomainClass.TRUSTED, DomainClass.COMMON_BENIGN,
    ), f"{domain} classified as {result.classification}"


def test_classification_carries_vendor_category() -> None:
    r = DomainClassifier().classify("js.stripe.com")
    assert r.vendor_category == "payment"


def test_unknown_domain_keeps_unknown_category_and_risk_signals() -> None:
    """Functional categorisation must not weaken risk classification of
    unrecognised domains."""
    r = DomainClassifier().classify("secure-paypal-login-verify.tk")
    assert r.vendor_category == "unknown"
    assert r.classification in (
        DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR,
    )
