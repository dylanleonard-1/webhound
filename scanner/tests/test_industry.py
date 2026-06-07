# WebHound — tests/test_industry.py
# Phase-19 Industry-Specific Intelligence (Task 10).
#
# Covers: industry classification (restaurant / dentist / law / ecommerce /
# unknown), known-vendor suppression, unknown-vendor escalation on sensitive
# flows, industry-specific WADE change reads, and report-template selection.

from __future__ import annotations

import pytest

from webhound.industry import (
    BusinessLabel,
    Confidence,
    Industry,
    IndustrySignals,
    PageKind,
    ReviewPriority,
    assess_change,
    assess_vendor_on_page,
    classify_industry,
    classify_page,
    is_known_industry_vendor,
    profile_for,
    recommendations_for,
    select_template,
)


# ---------------------------------------------------------------------------
# Task 2 — industry classification
# ---------------------------------------------------------------------------


def test_restaurant_classification() -> None:
    sig = IndustrySignals(
        page_title="Joe's Pizza & Pasta",
        meta_description="Authentic Italian dining",
        homepage_text="View our menu, order online, make a reservation, "
                      "catering available, takeout and delivery",
    )
    result = classify_industry(sig)
    assert result.industry == Industry.RESTAURANT
    assert result.confidence in (Confidence.HIGH, Confidence.MEDIUM)


def test_dentist_classification() -> None:
    sig = IndustrySignals(
        homepage_text="Bright Smile Dental — new patient forms, book your "
                      "appointment, we accept most insurance plans",
        schema_types=["Dentist"],
    )
    result = classify_industry(sig)
    assert result.industry == Industry.DENTAL_HEALTHCARE
    assert result.confidence == Confidence.HIGH


def test_law_firm_classification() -> None:
    sig = IndustrySignals(
        homepage_text="Our experienced attorneys offer a free consultation. "
                      "Practice areas include personal injury litigation.",
    )
    result = classify_industry(sig)
    assert result.industry == Industry.LAW_FIRM


def test_ecommerce_classification() -> None:
    sig = IndustrySignals(
        homepage_text="Browse our products, add to cart and checkout. "
                      "Free shipping on all orders.",
        detected_vendors=["shopify.com", "stripe.com"],
    )
    result = classify_industry(sig)
    assert result.industry == Industry.LOCAL_ECOMMERCE


def test_home_services_classification() -> None:
    sig = IndustrySignals(
        homepage_text="Request a free quote for HVAC repair and plumbing. "
                      "Licensed & insured. Serving the metro service area.",
    )
    result = classify_industry(sig)
    assert result.industry == Industry.HOME_SERVICES


def test_nonprofit_classification() -> None:
    sig = IndustrySignals(
        homepage_text="Join our church community. Worship times, sermons, "
                      "volunteer opportunities, and ways to give and donate.",
    )
    result = classify_industry(sig)
    assert result.industry == Industry.NONPROFIT_CHURCH


def test_unknown_classification() -> None:
    sig = IndustrySignals(homepage_text="Welcome to our website. Hello world.")
    result = classify_industry(sig)
    assert result.industry == Industry.UNKNOWN
    assert result.confidence == Confidence.LOW


def test_user_selected_category_is_authoritative() -> None:
    # Text screams restaurant, but the user told us it's a law firm.
    sig = IndustrySignals(
        homepage_text="menu, order online, reservations",
        user_category="lawyer",
    )
    result = classify_industry(sig)
    assert result.industry == Industry.LAW_FIRM
    assert result.confidence == Confidence.HIGH
    assert result.source == "user_selected"


def test_vendor_signal_contributes_to_classification() -> None:
    # Vendors alone (Zocdoc + Weave) should point at dental even with thin text.
    sig = IndustrySignals(detected_vendors=["zocdoc.com", "getweave.com"])
    result = classify_industry(sig)
    assert result.industry == Industry.DENTAL_HEALTHCARE


# ---------------------------------------------------------------------------
# Task 5 — vendor catalog / known-vendor suppression
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host,industry", [
    ("doordash.com", Industry.RESTAURANT),
    ("app.toasttab.com", Industry.RESTAURANT),
    ("zocdoc.com", Industry.DENTAL_HEALTHCARE),
    ("clio.com", Industry.LAW_FIRM),
    ("servicetitan.com", Industry.HOME_SERVICES),
])
def test_known_industry_vendor_recognised(host, industry) -> None:
    assert is_known_industry_vendor(host, industry) is True


def test_restaurant_doordash_is_not_scary() -> None:
    """A known restaurant vendor must never become a scary finding."""
    a = assess_vendor_on_page(
        Industry.RESTAURANT, "https://joes.com/order-online", "doordash.com")
    assert a.is_known_vendor is True
    assert a.priority == ReviewPriority.NONE


def test_known_vendor_suppression_on_sensitive_page() -> None:
    # Stripe (household payment vendor) on a checkout page is expected.
    a = assess_vendor_on_page(
        Industry.LOCAL_ECOMMERCE, "https://shop.com/checkout", "js.stripe.com")
    assert a.is_known_vendor is True
    assert a.priority == ReviewPriority.NONE


def test_unknown_vendor_on_checkout_escalates_to_review() -> None:
    a = assess_vendor_on_page(
        Industry.LOCAL_ECOMMERCE, "https://shop.com/checkout",
        "weird-unknown-tracker-xyz.com")
    assert a.is_known_vendor is False
    assert a.priority == ReviewPriority.HIGH
    assert a.business_label == BusinessLabel.PAYMENT_RELATED


def test_vendor_known_for_other_industry_not_expected_here() -> None:
    # DoorDash is known, but not expected on a law firm site.
    a = assess_vendor_on_page(
        Industry.LAW_FIRM, "https://firm.com/contact", "doordash.com")
    assert a.is_known_vendor is False


# ---------------------------------------------------------------------------
# Task 3 — page classification
# ---------------------------------------------------------------------------


def test_dentist_patient_form_page_is_sensitive() -> None:
    pc = classify_page(Industry.DENTAL_HEALTHCARE,
                       "https://dds.com/new-patient-forms")
    assert pc.kind == PageKind.PATIENT_FORM
    assert pc.is_sensitive is True
    assert pc.business_label == BusinessLabel.PRIVACY_SENSITIVE


def test_law_document_upload_page_classified() -> None:
    pc = classify_page(Industry.LAW_FIRM,
                       "https://firm.com/upload-your-documents")
    assert pc.kind == PageKind.DOCUMENT_UPLOAD
    assert pc.is_sensitive is True


def test_ecommerce_checkout_page_classified() -> None:
    pc = classify_page(Industry.LOCAL_ECOMMERCE, "https://shop.com/checkout")
    assert pc.kind == PageKind.CHECKOUT
    assert pc.business_label == BusinessLabel.PAYMENT_RELATED


# ---------------------------------------------------------------------------
# Task 4 / 6 — industry-specific risk adjustments + WADE reads
# ---------------------------------------------------------------------------


def test_dentist_external_patient_form_gets_higher_context() -> None:
    """A new external form on a patient page is a privacy-sensitive review."""
    a = assess_change(
        Industry.DENTAL_HEALTHCARE, "new_form",
        "https://dds.com/new-patient-forms", host="unknown-formhost.com")
    assert a.priority.rank >= ReviewPriority.REVIEW.rank
    assert a.business_label == BusinessLabel.PRIVACY_SENSITIVE


def test_restaurant_doordash_change_is_not_scary() -> None:
    """A new DoorDash script on a restaurant site is a known-vendor change."""
    a = assess_change(
        Industry.RESTAURANT, "new_script_source",
        "https://joes.com/order-online", host="doordash.com")
    assert a.is_known_vendor is True
    assert a.priority == ReviewPriority.NONE


def test_ecommerce_checkout_script_change_is_high_review() -> None:
    a = assess_change(
        Industry.LOCAL_ECOMMERCE, "new_script_source",
        "https://shop.com/checkout", host="sketchy-new-host.com")
    assert a.priority == ReviewPriority.HIGH


def test_ecommerce_checkout_script_change_no_host_still_high() -> None:
    # Even with no resolvable host, a script change on checkout is high.
    a = assess_change(
        Industry.LOCAL_ECOMMERCE, "changed_inline_script",
        "https://shop.com/checkout")
    assert a.priority == ReviewPriority.HIGH


def test_law_firm_document_upload_form_gets_review() -> None:
    a = assess_change(
        Industry.LAW_FIRM, "new_form", "https://firm.com/case-intake",
        is_document_upload=True)
    assert a.priority.rank >= ReviewPriority.REVIEW.rank
    assert a.business_label == BusinessLabel.CLIENT_INTAKE


def test_general_page_change_stays_calm() -> None:
    a = assess_change(
        Industry.RESTAURANT, "normal_content_update",
        "https://joes.com/about-us")
    assert a.priority in (ReviewPriority.NONE, ReviewPriority.LOW)


# ---------------------------------------------------------------------------
# Task 7 — recommendations
# ---------------------------------------------------------------------------


def test_recommendations_are_industry_specific() -> None:
    recs = recommendations_for(Industry.LOCAL_ECOMMERCE)
    assert recs
    joined = " ".join(r.title.lower() + " " + r.detail.lower() for r in recs)
    assert "checkout" in joined


def test_targeted_assessment_raises_recommendation_priority() -> None:
    a = assess_change(
        Industry.LOCAL_ECOMMERCE, "new_script_source",
        "https://shop.com/checkout", host="sketchy-host.com")
    recs = recommendations_for(Industry.LOCAL_ECOMMERCE, [a])
    assert recs[0].priority == ReviewPriority.HIGH   # sorted highest-first


def test_recommendations_make_no_compliance_promises() -> None:
    """Guardrail: never claim HIPAA / PCI compliance to the owner."""
    for industry in Industry:
        for rec in recommendations_for(industry):
            text = (rec.title + " " + rec.detail).lower()
            assert "hipaa" not in text
            assert "pci" not in text
            assert "compliant" not in text


# ---------------------------------------------------------------------------
# Task 8 — report template selection
# ---------------------------------------------------------------------------


def test_industry_report_template_selection() -> None:
    classification = classify_industry(IndustrySignals(
        schema_types=["Restaurant"],
        homepage_text="menu, order online, reservations, catering",
    ))
    template = select_template(classification)
    assert template.industry == Industry.RESTAURANT
    titles = template.section_titles()
    assert "Online Ordering Safety" in titles


def test_template_selection_accepts_bare_industry() -> None:
    template = select_template(Industry.LAW_FIRM)
    assert template.industry == Industry.LAW_FIRM
    assert "Client Intake Review" in template.section_titles()


def test_unknown_template_is_generic_but_useful() -> None:
    template = select_template(Industry.UNKNOWN)
    assert template.industry == Industry.UNKNOWN
    assert template.sections   # still has generic key-page sections


def test_every_industry_has_a_profile_and_template() -> None:
    for industry in Industry:
        profile = profile_for(industry)
        assert profile.industry == industry
        template = select_template(industry)
        assert template.sections
