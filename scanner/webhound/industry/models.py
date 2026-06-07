# WebHound — scanner/webhound/industry/models.py
# Phase-19 Industry-Specific Intelligence: the shared vocabulary.
#
# These types are the common language between the industry classifier, the
# profiles, the context/page rules, the risk-adjustment layer, the
# recommendation engine, and the report-template selector.
#
# Design rules (Phase-19):
#   - No legal/compliance promises. We never assert HIPAA / PCI compliance.
#   - Adjust *context*, not raw panic — every label here is business-friendly.
#   - Keep technical detail available; these models add framing, not fear.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Industry taxonomy
# ---------------------------------------------------------------------------


class Industry(str, Enum):
    """The small-business industries WebHound tailors itself to.

    UNKNOWN is the honest default — when signals don't converge, we stay
    generic rather than guessing wrong and mis-framing the report.
    """

    RESTAURANT = "restaurant"
    DENTAL_HEALTHCARE = "dental_healthcare"
    LAW_FIRM = "law_firm"
    LOCAL_ECOMMERCE = "local_ecommerce"
    HOME_SERVICES = "home_services"
    NONPROFIT_CHURCH = "nonprofit_church"
    PROFESSIONAL_SERVICES = "professional_services"
    UNKNOWN = "unknown"

    @property
    def display_name(self) -> str:
        return _DISPLAY_NAMES.get(self, "Business")


_DISPLAY_NAMES: dict["Industry", str] = {
    Industry.RESTAURANT: "Restaurant",
    Industry.DENTAL_HEALTHCARE: "Dental / Healthcare Practice",
    Industry.LAW_FIRM: "Law Firm",
    Industry.LOCAL_ECOMMERCE: "Online Store",
    Industry.HOME_SERVICES: "Home Services / Contractor",
    Industry.NONPROFIT_CHURCH: "Nonprofit / Church",
    Industry.PROFESSIONAL_SERVICES: "Professional Services",
    Industry.UNKNOWN: "Business",
}


def industry_from_value(value: Any) -> "Industry":
    """Coerce a string / Industry / None into an Industry (UNKNOWN on miss).

    Accepts the enum value ("law_firm"), the enum name ("LAW_FIRM"), or a
    loose label ("law firm", "dentist") so a user-selected category from the
    UI maps cleanly without the caller knowing the exact spelling."""
    if isinstance(value, Industry):
        return value
    if value is None:
        return Industry.UNKNOWN
    s = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    for ind in Industry:
        if s == ind.value or s == ind.name.lower():
            return ind
    # Loose aliases for user-selected categories.
    return _ALIASES.get(s, Industry.UNKNOWN)


_ALIASES: dict[str, "Industry"] = {
    "food": Industry.RESTAURANT,
    "cafe": Industry.RESTAURANT,
    "bar": Industry.RESTAURANT,
    "dentist": Industry.DENTAL_HEALTHCARE,
    "dental": Industry.DENTAL_HEALTHCARE,
    "healthcare": Industry.DENTAL_HEALTHCARE,
    "medical": Industry.DENTAL_HEALTHCARE,
    "doctor": Industry.DENTAL_HEALTHCARE,
    "clinic": Industry.DENTAL_HEALTHCARE,
    "lawyer": Industry.LAW_FIRM,
    "attorney": Industry.LAW_FIRM,
    "legal": Industry.LAW_FIRM,
    "ecommerce": Industry.LOCAL_ECOMMERCE,
    "e_commerce": Industry.LOCAL_ECOMMERCE,
    "shop": Industry.LOCAL_ECOMMERCE,
    "store": Industry.LOCAL_ECOMMERCE,
    "retail": Industry.LOCAL_ECOMMERCE,
    "contractor": Industry.HOME_SERVICES,
    "home_services": Industry.HOME_SERVICES,
    "plumbing": Industry.HOME_SERVICES,
    "hvac": Industry.HOME_SERVICES,
    "roofing": Industry.HOME_SERVICES,
    "electrical": Industry.HOME_SERVICES,
    "nonprofit": Industry.NONPROFIT_CHURCH,
    "non_profit": Industry.NONPROFIT_CHURCH,
    "church": Industry.NONPROFIT_CHURCH,
    "charity": Industry.NONPROFIT_CHURCH,
    "consulting": Industry.PROFESSIONAL_SERVICES,
    "agency": Industry.PROFESSIONAL_SERVICES,
    "accounting": Industry.PROFESSIONAL_SERVICES,
    "professional": Industry.PROFESSIONAL_SERVICES,
}


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------


class Confidence(str, Enum):
    """How sure the classifier is about the inferred industry."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"low": 1, "medium": 2, "high": 3}[self.value]


# ---------------------------------------------------------------------------
# Page kinds — industry-relevant page types (Task 3)
# ---------------------------------------------------------------------------


class PageKind(str, Enum):
    """The business-meaningful kind of a page, richer than the generic WADE
    context types. Used to decide how sensitive a change on the page is."""

    # Restaurant
    ONLINE_ORDERING = "online_ordering"
    RESERVATIONS = "reservations"
    GIFT_CARDS = "gift_cards"
    # Commerce / payment (shared)
    CHECKOUT = "checkout"
    CART = "cart"
    PAYMENT = "payment"
    CUSTOMER_ACCOUNT = "customer_account"
    ORDER_STATUS = "order_status"
    # Healthcare
    PATIENT_FORM = "patient_form"
    APPOINTMENT_BOOKING = "appointment_booking"
    INSURANCE_FORM = "insurance_form"
    PATIENT_PORTAL = "patient_portal"
    # Legal
    CONSULTATION_FORM = "consultation_form"
    CASE_INTAKE = "case_intake"
    DOCUMENT_UPLOAD = "document_upload"
    CLIENT_PORTAL = "client_portal"
    # Home services
    QUOTE_REQUEST = "quote_request"
    BOOKING = "booking"
    # Nonprofit
    DONATION = "donation"
    # Shared / generic
    CONTACT = "contact"
    LOGIN = "login"
    GENERAL = "general"


# Page kinds that handle money, identity, or privacy-sensitive details.
# A change on one of these always deserves a closer look.
SENSITIVE_PAGE_KINDS: frozenset[PageKind] = frozenset({
    PageKind.ONLINE_ORDERING, PageKind.GIFT_CARDS,
    PageKind.CHECKOUT, PageKind.CART, PageKind.PAYMENT,
    PageKind.CUSTOMER_ACCOUNT,
    PageKind.PATIENT_FORM, PageKind.APPOINTMENT_BOOKING,
    PageKind.INSURANCE_FORM, PageKind.PATIENT_PORTAL,
    PageKind.CONSULTATION_FORM, PageKind.CASE_INTAKE,
    PageKind.DOCUMENT_UPLOAD, PageKind.CLIENT_PORTAL,
    PageKind.QUOTE_REQUEST, PageKind.BOOKING,
    PageKind.DONATION, PageKind.LOGIN,
})


# ---------------------------------------------------------------------------
# Business-friendly labels for sensitive data (Task 4)
# ---------------------------------------------------------------------------


class BusinessLabel(str, Enum):
    """Plain-language framing for *what kind of information* a page touches.

    Deliberately avoids regulatory words ("PHI", "PCI cardholder data") so we
    never imply a compliance judgement we can't make."""

    PAYMENT_RELATED = "payment-related"
    CUSTOMER_INFORMATION = "customer information"
    APPOINTMENT_OR_BOOKING = "appointment or booking information"
    PRIVACY_SENSITIVE = "privacy-sensitive"
    CLIENT_INTAKE = "client intake"
    DONATION_RELATED = "donation-related"
    GENERAL = "general"


# ---------------------------------------------------------------------------
# Review priority (Task 5 / 6) — how loudly to surface a change/vendor.
# ---------------------------------------------------------------------------


class ReviewPriority(str, Enum):
    """How much attention a change or vendor deserves — framed as *review*
    effort, never as confirmed danger."""

    NONE = "none"        # known/expected — inventory, no action
    LOW = "low"          # worth noting on the next pass
    REVIEW = "review"    # a person should look at this
    HIGH = "high"        # look at this soon (sensitive flow + unknown)

    @property
    def rank(self) -> int:
        return {"none": 0, "low": 1, "review": 2, "high": 3}[self.value]


# ---------------------------------------------------------------------------
# Classifier input / output
# ---------------------------------------------------------------------------


@dataclass
class IndustrySignals:
    """Safe, passively-observed signals the classifier reasons over.

    Every field is optional so callers can supply whatever a scan surfaced —
    a homepage title alone, a full crawl's text, a user-selected category, or
    any mix. Nothing here requires executing JavaScript or fetching anything.
    """

    domain: str | None = None
    page_title: str | None = None
    meta_description: str | None = None
    homepage_text: str | None = None
    # schema.org @type values seen in JSON-LD / microdata (e.g. "Dentist").
    schema_types: list[str] = field(default_factory=list)
    # Registrable hosts of detected third-party vendors (e.g. "doordash.com").
    detected_vendors: list[str] = field(default_factory=list)
    # Extra free-text snippets (nav labels, link text, headings).
    extra_text: list[str] = field(default_factory=list)
    # A category the user explicitly selected in the UI, if any. When present
    # and recognised, it is treated as authoritative (HIGH confidence).
    user_category: str | None = None

    def combined_text(self) -> str:
        """All free-text signals lower-cased into one searchable blob."""
        parts = [
            self.domain or "",
            self.page_title or "",
            self.meta_description or "",
            self.homepage_text or "",
            *(self.extra_text or []),
        ]
        return " ".join(p for p in parts if p).lower()


@dataclass
class IndustryClassification:
    """The classifier's verdict, with a transparent score breakdown so the
    dashboard can show *why* an industry was inferred."""

    industry: Industry
    confidence: Confidence
    score: float = 0.0
    signals: list[str] = field(default_factory=list)
    scores_by_industry: dict[str, float] = field(default_factory=dict)
    source: str = "inferred"   # "user_selected" | "inferred" | "default"

    def to_dict(self) -> dict[str, Any]:
        return {
            "industry": self.industry.value,
            "industry_display": self.industry.display_name,
            "confidence": self.confidence.value,
            "score": round(self.score, 2),
            "signals": list(self.signals),
            "scores_by_industry": {
                k: round(v, 2) for k, v in self.scores_by_industry.items()
            },
            "source": self.source,
        }


# ---------------------------------------------------------------------------
# Industry profile (Task 1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IndustryProfile:
    """Everything WebHound knows about how a kind of business uses its site.

    Drives page classification, vendor expectations, risk framing,
    recommendations, and report sections."""

    industry: Industry
    common_functions: tuple[str, ...]
    sensitive_pages: tuple[PageKind, ...]
    common_vendors: tuple[str, ...]          # display names, for prose
    normal_third_parties: tuple[str, ...]    # vendor functions expected here
    important_forms: tuple[str, ...]
    business_risks: tuple[str, ...]
    language_style: str                      # tone descriptor for copy
    recommendation_priorities: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "industry": self.industry.value,
            "common_functions": list(self.common_functions),
            "sensitive_pages": [p.value for p in self.sensitive_pages],
            "common_vendors": list(self.common_vendors),
            "normal_third_parties": list(self.normal_third_parties),
            "important_forms": list(self.important_forms),
            "business_risks": list(self.business_risks),
            "language_style": self.language_style,
            "recommendation_priorities": list(self.recommendation_priorities),
        }
