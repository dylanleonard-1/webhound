# WebHound — scanner/webhound/industry/vendor_catalog.py
# Phase-19 Task 5: small-business vendor awareness.
#
# The generic DomainClassifier (threat_intel/domain_classifier.py) knows the
# household web vendors — Stripe, Shopify, Google Analytics, Cloudflare. It
# does NOT know the industry-specific SaaS that a restaurant, dental office,
# or law firm relies on (Toast, Zocdoc, Clio, ServiceTitan). This catalog
# fills that gap so those vendors are recognised as *normal for the business*
# rather than surfaced as scary unknown third parties.
#
# Contract (Task 5):
#   - Known vendors should NOT become scary findings by default.
#   - Unknown vendors on sensitive flows SHOULD become review items
#     (that escalation lives in risk_adjustments.py; this file just answers
#     "is this a known industry vendor, and what does it do?").

from __future__ import annotations

from dataclasses import dataclass

import tldextract

from webhound.industry.models import Industry


@dataclass(frozen=True)
class IndustryVendor:
    """A SaaS vendor that is normal-to-expected for one or more industries."""

    name: str                       # display name ("DoorDash")
    function: str                   # what it does ("food delivery")
    industries: tuple[Industry, ...]  # industries where it's expected


# Registrable host → vendor record. Hosts are matched on the registrable
# domain so app.toasttab.com and order.toasttab.com both resolve to Toast.
_VENDORS: dict[str, IndustryVendor] = {
    # --- Restaurant --------------------------------------------------------
    "toasttab.com": IndustryVendor("Toast", "ordering & payments",
                                   (Industry.RESTAURANT,)),
    "doordash.com": IndustryVendor("DoorDash", "food delivery",
                                   (Industry.RESTAURANT,)),
    "ubereats.com": IndustryVendor("Uber Eats", "food delivery",
                                   (Industry.RESTAURANT,)),
    "grubhub.com": IndustryVendor("Grubhub", "food delivery",
                                  (Industry.RESTAURANT,)),
    "opentable.com": IndustryVendor("OpenTable", "reservations",
                                    (Industry.RESTAURANT,)),
    "clover.com": IndustryVendor("Clover", "point of sale & payments",
                                 (Industry.RESTAURANT,)),
    "chownow.com": IndustryVendor("ChowNow", "online ordering",
                                  (Industry.RESTAURANT,)),
    "olo.com": IndustryVendor("Olo", "online ordering",
                              (Industry.RESTAURANT,)),
    # Square serves restaurants AND retail/ecommerce.
    "squareup.com": IndustryVendor("Square", "payments & point of sale",
                                   (Industry.RESTAURANT,
                                    Industry.LOCAL_ECOMMERCE)),

    # --- Dental / healthcare ----------------------------------------------
    "zocdoc.com": IndustryVendor("Zocdoc", "appointment booking",
                                 (Industry.DENTAL_HEALTHCARE,)),
    "nexhealth.com": IndustryVendor("NexHealth", "patient scheduling & intake",
                                    (Industry.DENTAL_HEALTHCARE,)),
    "solutionreach.com": IndustryVendor("Solutionreach",
                                        "patient communication",
                                        (Industry.DENTAL_HEALTHCARE,)),
    "getweave.com": IndustryVendor("Weave", "patient communication",
                                   (Industry.DENTAL_HEALTHCARE,)),
    "weavehq.com": IndustryVendor("Weave", "patient communication",
                                  (Industry.DENTAL_HEALTHCARE,)),
    "simplepractice.com": IndustryVendor("SimplePractice",
                                         "practice management & intake",
                                         (Industry.DENTAL_HEALTHCARE,)),
    "phreesia.com": IndustryVendor("Phreesia", "patient intake",
                                   (Industry.DENTAL_HEALTHCARE,)),
    "dentrix.com": IndustryVendor("Dentrix", "practice management",
                                  (Industry.DENTAL_HEALTHCARE,)),

    # --- Law firm ----------------------------------------------------------
    "clio.com": IndustryVendor("Clio", "legal practice management",
                               (Industry.LAW_FIRM,)),
    "lawpay.com": IndustryVendor("LawPay", "legal payments",
                                 (Industry.LAW_FIRM,)),
    "mycase.com": IndustryVendor("MyCase", "legal case management",
                                 (Industry.LAW_FIRM,)),
    # Calendly & HubSpot are cross-industry but listed under the industries
    # where they most commonly appear on intake/consultation flows.
    "calendly.com": IndustryVendor("Calendly", "appointment scheduling",
                                   (Industry.LAW_FIRM,
                                    Industry.PROFESSIONAL_SERVICES,
                                    Industry.HOME_SERVICES)),

    # --- Local ecommerce ---------------------------------------------------
    "shopify.com": IndustryVendor("Shopify", "ecommerce platform",
                                  (Industry.LOCAL_ECOMMERCE,)),
    "myshopify.com": IndustryVendor("Shopify", "ecommerce platform",
                                    (Industry.LOCAL_ECOMMERCE,)),
    "stripe.com": IndustryVendor("Stripe", "payments",
                                 (Industry.LOCAL_ECOMMERCE,)),
    "paypal.com": IndustryVendor("PayPal", "payments",
                                 (Industry.LOCAL_ECOMMERCE,)),
    "klarna.com": IndustryVendor("Klarna", "buy-now-pay-later",
                                 (Industry.LOCAL_ECOMMERCE,)),
    "afterpay.com": IndustryVendor("Afterpay", "buy-now-pay-later",
                                   (Industry.LOCAL_ECOMMERCE,)),
    "shipstation.com": IndustryVendor("ShipStation", "shipping & fulfilment",
                                      (Industry.LOCAL_ECOMMERCE,)),
    "klaviyo.com": IndustryVendor("Klaviyo", "email marketing",
                                  (Industry.LOCAL_ECOMMERCE,)),

    # --- Home services -----------------------------------------------------
    "servicetitan.com": IndustryVendor("ServiceTitan",
                                       "field-service management",
                                       (Industry.HOME_SERVICES,)),
    "housecallpro.com": IndustryVendor("Housecall Pro",
                                       "field-service management",
                                       (Industry.HOME_SERVICES,)),
    "getjobber.com": IndustryVendor("Jobber", "field-service management",
                                    (Industry.HOME_SERVICES,)),
    "thumbtack.com": IndustryVendor("Thumbtack", "lead generation",
                                    (Industry.HOME_SERVICES,)),
    "angi.com": IndustryVendor("Angi", "lead generation",
                               (Industry.HOME_SERVICES,)),

    # --- Nonprofit / church ------------------------------------------------
    "donorbox.org": IndustryVendor("Donorbox", "donations",
                                   (Industry.NONPROFIT_CHURCH,)),
    "givebutter.com": IndustryVendor("Givebutter", "donations & fundraising",
                                     (Industry.NONPROFIT_CHURCH,)),
    "tithe.ly": IndustryVendor("Tithe.ly", "church giving",
                               (Industry.NONPROFIT_CHURCH,)),
    "planningcenteronline.com": IndustryVendor("Planning Center",
                                               "church management",
                                               (Industry.NONPROFIT_CHURCH,)),
    "classy.org": IndustryVendor("Classy", "fundraising",
                                 (Industry.NONPROFIT_CHURCH,)),
}


def _registrable(host_or_url: str) -> str:
    """Registrable domain of a host or URL (toasttab.com from
    app.toasttab.com / https://app.toasttab.com/x)."""
    s = (host_or_url or "").strip().lower()
    if not s:
        return ""
    if "://" in s:
        from urllib.parse import urlparse
        s = (urlparse(s).hostname or "")
    else:
        s = s.split("/", 1)[0]
    ext = tldextract.extract(s)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return s


def lookup(host_or_url: str) -> IndustryVendor | None:
    """Return the :class:`IndustryVendor` for a host/URL, or None if it is not
    a known industry vendor in this catalog."""
    return _VENDORS.get(_registrable(host_or_url))


def is_known_industry_vendor(
    host_or_url: str, industry: Industry | None = None,
) -> bool:
    """True if *host_or_url* is a recognised industry vendor.

    When *industry* is given, the vendor must be expected for that industry
    (DoorDash is "known" for a restaurant, not for a law firm)."""
    vendor = lookup(host_or_url)
    if vendor is None:
        return False
    if industry is None or industry == Industry.UNKNOWN:
        return True
    return industry in vendor.industries


def vendors_for(industry: Industry) -> list[IndustryVendor]:
    """All catalog vendors expected for *industry* (deduplicated by name)."""
    seen: dict[str, IndustryVendor] = {}
    for vendor in _VENDORS.values():
        if industry in vendor.industries and vendor.name not in seen:
            seen[vendor.name] = vendor
    return list(seen.values())
