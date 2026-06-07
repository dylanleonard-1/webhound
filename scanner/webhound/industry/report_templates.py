# WebHound — scanner/webhound/industry/report_templates.py
# Phase-19 Task 8: industry-focused report sections.
#
# Selects the right set of report sections for a business and frames them in
# the industry's voice. Technical findings stay available in the advanced
# view; these sections are the customer-facing framing layer on top.

from __future__ import annotations

from dataclasses import dataclass, field

from webhound.industry.industry_profiles import profile_for
from webhound.industry.models import (
    Confidence,
    Industry,
    IndustryClassification,
)


@dataclass(frozen=True)
class ReportSection:
    """One industry-specific section of the customer report."""

    key: str
    title: str
    summary: str

    def to_dict(self) -> dict[str, str]:
        return {"key": self.key, "title": self.title, "summary": self.summary}


@dataclass
class IndustryReportTemplate:
    """The selected report framing for a scan."""

    industry: Industry
    headline: str
    intro: str
    language_style: str
    sections: list[ReportSection] = field(default_factory=list)

    def section_titles(self) -> list[str]:
        return [s.title for s in self.sections]

    def to_dict(self) -> dict[str, object]:
        return {
            "industry": self.industry.value,
            "industry_display": self.industry.display_name,
            "headline": self.headline,
            "intro": self.intro,
            "language_style": self.language_style,
            "sections": [s.to_dict() for s in self.sections],
        }


# Industry → ordered report sections (Task 8).
_SECTIONS: dict[Industry, list[ReportSection]] = {
    Industry.RESTAURANT: [
        ReportSection("online_ordering_safety", "Online Ordering Safety",
                      "How your online ordering flow looks, and whether "
                      "anything changed around it."),
        ReportSection("reservation_payment_changes",
                      "Reservation & Payment Changes",
                      "Changes affecting your reservation and payment links."),
        ReportSection("vendor_review", "Third-Party Vendor Review",
                      "The outside services your site uses (Toast, DoorDash, "
                      "OpenTable, …) and any new ones."),
    ],
    Industry.DENTAL_HEALTHCARE: [
        ReportSection("patient_form_review",
                      "Appointment & Patient Form Review",
                      "How your appointment and patient-intake forms look, and "
                      "where they send information."),
        ReportSection("portal_link_review", "Portal & Link Review",
                      "Whether your patient-portal and booking links point "
                      "where they should."),
        ReportSection("privacy_sensitive_changes",
                      "Privacy-Sensitive Form Changes",
                      "Changes on pages that collect privacy-sensitive "
                      "patient details."),
    ],
    Industry.LAW_FIRM: [
        ReportSection("client_intake_review", "Client Intake Review",
                      "How your consultation and case-intake forms look, and "
                      "where client details go."),
        ReportSection("document_upload_review", "Document Upload Review",
                      "Whether document-upload forms send client files to a "
                      "destination you recognise."),
        ReportSection("contact_form_integrity", "Contact Form Integrity",
                      "The integrity of your contact and enquiry forms."),
    ],
    Industry.LOCAL_ECOMMERCE: [
        ReportSection("checkout_monitoring", "Checkout Monitoring",
                      "What runs on your checkout page and whether anything "
                      "changed there."),
        ReportSection("payment_provider_review", "Payment Provider Review",
                      "Your payment-related third parties and any new "
                      "additions."),
        ReportSection("customer_account_surface", "Customer Account Surface",
                      "The pages where customer personal details live."),
    ],
    Industry.HOME_SERVICES: [
        ReportSection("quote_form_integrity", "Quote & Contact Form Integrity",
                      "How your quote, estimate, and contact forms look, and "
                      "where they send leads."),
        ReportSection("booking_review", "Booking Review",
                      "Whether your booking links point to your real "
                      "scheduling tool."),
        ReportSection("vendor_review", "Third-Party Vendor Review",
                      "The outside services your site uses and any new ones."),
    ],
    Industry.NONPROFIT_CHURCH: [
        ReportSection("donation_flow", "Donation Flow Integrity",
                      "How your giving/donation flow looks and whether "
                      "anything changed around it."),
        ReportSection("payment_provider_review", "Payment Provider Review",
                      "Your donation/payment provider and any new additions."),
        ReportSection("supporter_forms", "Supporter Form Review",
                      "Your volunteer and newsletter forms and where they "
                      "send details."),
    ],
    Industry.PROFESSIONAL_SERVICES: [
        ReportSection("contact_form_integrity",
                      "Contact & Consultation Form Integrity",
                      "How your enquiry forms look and where client details "
                      "go."),
        ReportSection("scheduling_review", "Scheduling & Sign-In Review",
                      "Whether your scheduling and client sign-in links point "
                      "where they should."),
        ReportSection("vendor_review", "Third-Party Vendor Review",
                      "The outside services your site uses and any new ones."),
    ],
    Industry.UNKNOWN: [
        ReportSection("key_pages", "Key Page Review",
                      "Changes to your payment, sign-in, and contact pages."),
        ReportSection("vendor_review", "Third-Party Vendor Review",
                      "The outside services your site uses and any new ones."),
    ],
}

_HEADLINES: dict[Industry, str] = {
    Industry.RESTAURANT: "Your restaurant website at a glance",
    Industry.DENTAL_HEALTHCARE: "Your practice website at a glance",
    Industry.LAW_FIRM: "Your firm's website at a glance",
    Industry.LOCAL_ECOMMERCE: "Your online store at a glance",
    Industry.HOME_SERVICES: "Your business website at a glance",
    Industry.NONPROFIT_CHURCH: "Your organization's website at a glance",
    Industry.PROFESSIONAL_SERVICES: "Your business website at a glance",
    Industry.UNKNOWN: "Your website at a glance",
}


def report_sections_for(industry: Industry) -> list[ReportSection]:
    """The ordered report sections for *industry* (Task 8)."""
    return list(_SECTIONS.get(industry, _SECTIONS[Industry.UNKNOWN]))


def select_template(
    classification: IndustryClassification | Industry,
) -> IndustryReportTemplate:
    """Choose and build the report template for a classification.

    Accepts either a full :class:`IndustryClassification` or a bare
    :class:`Industry`. When confidence is LOW we still tailor the sections
    but soften the intro so we don't over-claim what kind of business it is."""
    if isinstance(classification, IndustryClassification):
        industry = classification.industry
        confidence = classification.confidence
    else:
        industry = classification
        confidence = Confidence.MEDIUM

    profile = profile_for(industry)
    headline = _HEADLINES.get(industry, _HEADLINES[Industry.UNKNOWN])

    if industry == Industry.UNKNOWN:
        intro = ("We couldn't confidently tell what kind of business this is, "
                 "so this report focuses on the pages that matter on any "
                 "site — payment, sign-in, and contact.")
    elif confidence == Confidence.LOW:
        intro = (f"This looks like it may be a "
                 f"{industry.display_name.lower()} site, so we've framed the "
                 f"report that way. If that's not right, the technical "
                 f"findings below apply regardless.")
    else:
        intro = (f"This report is tailored for a "
                 f"{industry.display_name.lower()}. We focused on the parts "
                 f"of your site that matter most for a business like yours.")

    return IndustryReportTemplate(
        industry=industry,
        headline=headline,
        intro=intro,
        language_style=profile.language_style,
        sections=report_sections_for(industry),
    )
