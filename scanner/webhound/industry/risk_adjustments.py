# WebHound — scanner/webhound/industry/risk_adjustments.py
# Phase-19 Task 4 (risk adjustments) + Task 6 (industry-specific WADE).
#
# This is the heart of "feels built for my business" — but the guiding rule
# is *adjust context, not raw panic*. We never invent a vulnerability. We
# raise or lower how loudly a change/vendor is surfaced based on:
#   - the industry,
#   - what the affected page does (PageKind),
#   - whether the third party is a known/expected vendor.
#
# We deliberately use business-friendly framing (BusinessLabel) and never
# assert HIPAA / PCI compliance.

from __future__ import annotations

from dataclasses import dataclass, field

from webhound.industry.context_rules import PageClassification, classify_page
from webhound.industry.models import (
    BusinessLabel,
    Industry,
    PageKind,
    ReviewPriority,
)
from webhound.industry.vendor_catalog import is_known_industry_vendor
from webhound.industry.vendor_catalog import lookup as vendor_lookup

# Optional reuse of the generic domain classifier so household vendors
# (Stripe, Google, Cloudflare) also count as "known" even if they aren't in
# the small-business catalog.
try:  # pragma: no cover - import guard
    from webhound.threat_intel.domain_classifier import (
        DomainClass,
        DomainClassifier,
    )
    _GENERIC_CLF: DomainClassifier | None = DomainClassifier()
except Exception:  # pragma: no cover
    _GENERIC_CLF = None
    DomainClass = None  # type: ignore


@dataclass
class IndustryAssessment:
    """The industry layer's read on a vendor/change against a page.

    ``priority`` is review effort, NOT confirmed danger. ``business_label``
    frames the kind of information at stake in plain language."""

    priority: ReviewPriority
    business_label: BusinessLabel
    is_known_vendor: bool
    rationale: str
    page_kind: PageKind = PageKind.GENERAL
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "priority": self.priority.value,
            "business_label": self.business_label.value,
            "is_known_vendor": self.is_known_vendor,
            "rationale": self.rationale,
            "page_kind": self.page_kind.value,
            "signals": list(self.signals),
        }


def _vendor_is_known(host: str | None, industry: Industry) -> tuple[bool, str]:
    """Is *host* a vendor we'd expect? Returns (known, display-name)."""
    if not host:
        return False, ""
    # Industry-specific catalog (Toast, Zocdoc, Clio, …).
    cat_vendor = vendor_lookup(host)
    if cat_vendor is not None and is_known_industry_vendor(host, industry):
        return True, cat_vendor.name
    # Household web vendors via the generic classifier (Stripe, Google, …).
    if _GENERIC_CLF is not None and DomainClass is not None:
        cls = _GENERIC_CLF.classify(host)
        if cls.classification in (DomainClass.TRUSTED,
                                  DomainClass.COMMON_BENIGN):
            return True, host
        if cls.classification in (DomainClass.RISKY,
                                  DomainClass.MALICIOUS_INDICATOR):
            return False, host
    # A catalog vendor that belongs to *other* industries is still "named",
    # but not expected here → treat as not-known-for-this-industry.
    if cat_vendor is not None:
        return False, cat_vendor.name
    return False, host


def assess_vendor_on_page(
    industry: Industry,
    page: PageClassification | str,
    host: str | None,
    *,
    title: str | None = None,
) -> IndustryAssessment:
    """Assess a third-party *host* appearing on *page* for *industry*.

    Core rule (Task 5): known vendors are inventory (NONE/LOW); unknown
    vendors on sensitive flows escalate to REVIEW/HIGH with the right
    business label."""
    pc = (page if isinstance(page, PageClassification)
          else classify_page(industry, page, title=title))
    known, name = _vendor_is_known(host, industry)
    label = pc.business_label

    if known:
        return IndustryAssessment(
            priority=ReviewPriority.NONE,
            business_label=label,
            is_known_vendor=True,
            rationale=(f"{name} is a recognised vendor for "
                       f"{industry.display_name.lower()} sites — expected, "
                       f"no action needed."),
            page_kind=pc.kind,
            signals=[f"known vendor: {name}"],
        )

    # Unknown vendor. How loud depends on the page's sensitivity.
    if pc.is_sensitive:
        priority = (ReviewPriority.HIGH
                    if label in (BusinessLabel.PAYMENT_RELATED,
                                 BusinessLabel.PRIVACY_SENSITIVE,
                                 BusinessLabel.CLIENT_INTAKE,
                                 BusinessLabel.DONATION_RELATED)
                    else ReviewPriority.REVIEW)
        rationale = (
            f"An unrecognised third party appears on a "
            f"{_label_phrase(label)} page ({pc.kind.value}). Worth a quick "
            f"review to confirm it's something you added."
        )
    else:
        priority = ReviewPriority.LOW
        rationale = ("An unrecognised third party appears on a general page — "
                     "noted for your next review.")

    return IndustryAssessment(
        priority=priority,
        business_label=label,
        is_known_vendor=False,
        rationale=rationale,
        page_kind=pc.kind,
        signals=[f"unknown vendor: {host}"] if host else ["unknown vendor"],
    )


# WADE change types (string values, to avoid a hard import dependency on the
# wade package from the industry layer) that represent *script* changes.
_SCRIPT_CHANGE_VALUES = frozenset({
    "new_script_source", "changed_inline_script", "suspicious_script_change",
})
_FORM_CHANGE_VALUES = frozenset({"new_form", "form_field_change"})
_VENDOR_CHANGE_VALUES = frozenset({
    "new_marketing_tool", "new_analytics_tool", "new_third_party_service",
    "new_payment_provider", "new_auth_provider",
})


def assess_change(
    industry: Industry,
    change_type: str,
    page: PageClassification | str,
    *,
    host: str | None = None,
    title: str | None = None,
    is_document_upload: bool = False,
) -> IndustryAssessment:
    """Industry-specific reading of a WADE change (Task 6).

    *change_type* is a WADE change-type or diff-type string value. The
    assessment blends: is the change on a sensitive page for this industry,
    is the involved vendor known, and is the change a script/form change.

    Examples (from the Phase-19 brief):
      restaurant + new DoorDash script   → known vendor, NONE/LOW
      dentist + new external form (patient page) → REVIEW, privacy-sensitive
      ecommerce + new unknown checkout script    → HIGH
      law firm + new document-upload form        → REVIEW
    """
    pc = (page if isinstance(page, PageClassification)
          else classify_page(industry, page, title=title))
    label = pc.business_label
    ctype = (change_type or "").strip().lower()

    # A named-vendor addition: defer to vendor knowledge — calm if known.
    if ctype in _VENDOR_CHANGE_VALUES or host:
        vendor_assess = assess_vendor_on_page(industry, pc, host, title=title)
        if vendor_assess.is_known_vendor:
            return vendor_assess
        # Unknown vendor: vendor_assess already encodes sensitivity-based
        # escalation. Sharpen the rationale for script changes on payment
        # pages (the Magecart signature).
        if ctype in _SCRIPT_CHANGE_VALUES and \
                label == BusinessLabel.PAYMENT_RELATED:
            return IndustryAssessment(
                priority=ReviewPriority.HIGH,
                business_label=label,
                is_known_vendor=False,
                rationale=("A new or changed script from an unrecognised "
                           "source on a payment page is the pattern card "
                           "skimmers use. Please review this soon."),
                page_kind=pc.kind,
                signals=["unknown script on payment page"],
            )
        return vendor_assess

    # Form changes: a new/changed form on a sensitive page is a review item,
    # regardless of vendor (the form itself collects the sensitive data).
    if ctype in _FORM_CHANGE_VALUES or is_document_upload:
        if is_document_upload or pc.kind == PageKind.DOCUMENT_UPLOAD:
            return IndustryAssessment(
                priority=ReviewPriority.REVIEW,
                business_label=BusinessLabel.CLIENT_INTAKE,
                is_known_vendor=False,
                rationale=("A document-upload form sends client files to a "
                           "destination — confirm it's one you recognise."),
                page_kind=PageKind.DOCUMENT_UPLOAD,
                signals=["document upload form change"],
            )
        if pc.is_sensitive:
            return IndustryAssessment(
                priority=ReviewPriority.REVIEW,
                business_label=label,
                is_known_vendor=False,
                rationale=(f"A form changed on a {_label_phrase(label)} page. "
                           f"Confirm the form still sends information where "
                           f"you expect."),
                page_kind=pc.kind,
                signals=["form change on sensitive page"],
            )
        return IndustryAssessment(
            priority=ReviewPriority.LOW,
            business_label=label,
            is_known_vendor=False,
            rationale="A form changed on a general page — noted for review.",
            page_kind=pc.kind,
            signals=["form change on general page"],
        )

    # Script / other changes on sensitive pages without a clear vendor.
    if ctype in _SCRIPT_CHANGE_VALUES and pc.is_sensitive:
        priority = (ReviewPriority.HIGH
                    if label == BusinessLabel.PAYMENT_RELATED
                    else ReviewPriority.REVIEW)
        return IndustryAssessment(
            priority=priority,
            business_label=label,
            is_known_vendor=False,
            rationale=(f"A script changed on a {_label_phrase(label)} page. "
                       f"Worth confirming against your recent updates."),
            page_kind=pc.kind,
            signals=["script change on sensitive page"],
        )

    # Default: low-key note, framed by the page's purpose.
    return IndustryAssessment(
        priority=ReviewPriority.LOW if pc.is_sensitive else ReviewPriority.NONE,
        business_label=label,
        is_known_vendor=False,
        rationale="Change noted in context of this page.",
        page_kind=pc.kind,
        signals=[f"change: {ctype}"] if ctype else [],
    )


def _label_phrase(label: BusinessLabel) -> str:
    """A natural noun phrase for prose ("payment-related" → 'payment')."""
    return {
        BusinessLabel.PAYMENT_RELATED: "payment",
        BusinessLabel.CUSTOMER_INFORMATION: "customer-information",
        BusinessLabel.APPOINTMENT_OR_BOOKING: "appointment/booking",
        BusinessLabel.PRIVACY_SENSITIVE: "privacy-sensitive",
        BusinessLabel.CLIENT_INTAKE: "client-intake",
        BusinessLabel.DONATION_RELATED: "donation",
        BusinessLabel.GENERAL: "general",
    }.get(label, "general")
