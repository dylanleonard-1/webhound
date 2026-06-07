# WebHound — scanner/webhound/industry/recommendation_rules.py
# Phase-19 Task 7: recommendations that fit the customer.
#
# These are business-friendly, action-oriented suggestions written for an
# owner, not a security team. They never promise compliance and never try to
# scare — they point the owner at the few things actually worth a look.

from __future__ import annotations

from dataclasses import dataclass, field

from webhound.industry.industry_profiles import profile_for
from webhound.industry.models import (
    BusinessLabel,
    Industry,
    PageKind,
    ReviewPriority,
)
from webhound.industry.risk_adjustments import IndustryAssessment


@dataclass
class IndustryRecommendation:
    """One business-friendly recommendation."""

    title: str
    detail: str
    priority: ReviewPriority = ReviewPriority.REVIEW
    related_pages: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "detail": self.detail,
            "priority": self.priority.value,
            "related_pages": list(self.related_pages),
        }


# Baseline recommendations per industry — always shown, lowest priority,
# framed as "here's what to keep an eye on for a business like yours".
_BASELINE: dict[Industry, list[tuple[str, str]]] = {
    Industry.RESTAURANT: [
        ("Review your online ordering and payment changes",
         "When your online ordering or payment provider changes, take a "
         "moment to confirm orders still flow to the right place."),
        ("Keep an eye on your reservation page",
         "Confirm your reservation links still point to your real booking "
         "provider (OpenTable, Toast, etc.)."),
    ],
    Industry.DENTAL_HEALTHCARE: [
        ("Review appointment and patient-intake forms",
         "Check that appointment and new-patient forms send information only "
         "to the systems you use, with no unexpected third-party "
         "destinations."),
        ("Check your patient-portal links",
         "Confirm portal and booking links point to your real provider so "
         "patients always land in the right place."),
    ],
    Industry.LAW_FIRM: [
        ("Review client intake and consultation forms",
         "Confirm consultation and case-intake forms deliver client details "
         "only to the systems you trust."),
        ("Review document-upload forms",
         "Any form that lets clients upload files should send those files to "
         "a destination you recognise."),
    ],
    Industry.LOCAL_ECOMMERCE: [
        ("Review checkout scripts and payment third parties",
         "The checkout page is the most important page to watch — confirm "
         "any new scripts or payment-related services there are ones you "
         "added."),
        ("Watch your customer-account pages",
         "Account pages hold personal details; review changes there with a "
         "little extra care."),
    ],
    Industry.HOME_SERVICES: [
        ("Review your quote and contact forms",
         "Confirm quote, estimate, and contact forms send customer details "
         "to the systems you use."),
        ("Check your booking flow",
         "Make sure booking links point to your real scheduling tool."),
    ],
    Industry.NONPROFIT_CHURCH: [
        ("Review your donation flow",
         "Confirm your giving/donation page still uses your real provider "
         "and that no unexpected third parties were added."),
        ("Check supporter sign-up forms",
         "Volunteer and newsletter forms should send details only where you "
         "expect."),
    ],
    Industry.PROFESSIONAL_SERVICES: [
        ("Review contact and consultation forms",
         "Confirm client enquiry forms deliver details only to the systems "
         "you trust."),
        ("Check scheduling and sign-in links",
         "Make sure scheduling and client sign-in links point to your real "
         "tools."),
    ],
    Industry.UNKNOWN: [
        ("Review payment, sign-in, and contact pages",
         "These pages matter most on any site — confirm recent changes to "
         "them are ones you made."),
    ],
}


def baseline_recommendations(industry: Industry) -> list[IndustryRecommendation]:
    """The standing, always-on recommendations for *industry*."""
    out: list[IndustryRecommendation] = []
    for title, detail in _BASELINE.get(industry, _BASELINE[Industry.UNKNOWN]):
        out.append(IndustryRecommendation(
            title=title, detail=detail, priority=ReviewPriority.LOW,
        ))
    return out


def recommendations_for(
    industry: Industry,
    assessments: list[IndustryAssessment] | None = None,
) -> list[IndustryRecommendation]:
    """Build the recommendation list for *industry*.

    Combines the standing baseline with targeted, higher-priority items
    derived from any concrete *assessments* (vendor/change reviews surfaced
    by risk_adjustments). Sorted by priority, highest first."""
    recs: list[IndustryRecommendation] = list(baseline_recommendations(industry))

    for a in assessments or []:
        if a.priority.rank < ReviewPriority.REVIEW.rank:
            continue   # NONE/LOW assessments fold into the baseline framing
        recs.append(IndustryRecommendation(
            title=_targeted_title(a),
            detail=a.rationale,
            priority=a.priority,
            related_pages=[a.page_kind.value],
        ))

    recs.sort(key=lambda r: r.priority.rank, reverse=True)
    return recs


def _targeted_title(a: IndustryAssessment) -> str:
    label_titles = {
        BusinessLabel.PAYMENT_RELATED: "Review a payment-related change",
        BusinessLabel.PRIVACY_SENSITIVE: "Review a privacy-sensitive form",
        BusinessLabel.CLIENT_INTAKE: "Review a client-intake change",
        BusinessLabel.APPOINTMENT_OR_BOOKING: "Review a booking change",
        BusinessLabel.CUSTOMER_INFORMATION: "Review a customer-information page",
        BusinessLabel.DONATION_RELATED: "Review a donation-flow change",
    }
    if a.page_kind == PageKind.DOCUMENT_UPLOAD:
        return "Review a document-upload form"
    return label_titles.get(a.business_label, "Review a change on your site")


def recommendation_priorities(industry: Industry) -> tuple[str, ...]:
    """The profile's ordered priority themes (used by the report header)."""
    return profile_for(industry).recommendation_priorities
