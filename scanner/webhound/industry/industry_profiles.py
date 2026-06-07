# WebHound — scanner/webhound/industry/industry_profiles.py
# Phase-19 Task 1: the profile for each supported industry.
#
# A profile captures how a kind of small business actually uses its website:
# what it does, which pages are sensitive, which vendors are normal, what can
# go wrong, and how to talk to the owner about it. Everything downstream
# (page rules, risk framing, recommendations, report sections) reads from
# here, so adding an industry is a matter of adding one profile.

from __future__ import annotations

from webhound.industry.models import Industry, IndustryProfile, PageKind

# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

_RESTAURANT = IndustryProfile(
    industry=Industry.RESTAURANT,
    common_functions=(
        "menu", "online ordering", "reservations", "catering enquiries",
        "gift cards", "hours & location", "delivery links",
    ),
    sensitive_pages=(
        PageKind.ONLINE_ORDERING, PageKind.GIFT_CARDS,
        PageKind.RESERVATIONS, PageKind.CHECKOUT, PageKind.PAYMENT,
        PageKind.CONTACT,
    ),
    common_vendors=(
        "Toast", "DoorDash", "Uber Eats", "Grubhub", "OpenTable",
        "Square", "Clover",
    ),
    normal_third_parties=("payment", "ordering", "reservations", "delivery"),
    important_forms=(
        "online ordering", "reservation requests", "catering enquiries",
        "gift-card purchases", "contact",
    ),
    business_risks=(
        "a tampered online-ordering or payment flow could expose customer "
        "card details",
        "a fake reservation or ordering page could damage customer trust",
        "an unexpected new payment provider could redirect orders",
    ),
    language_style="warm_casual",
    recommendation_priorities=(
        "online ordering & payment integrity",
        "reservation page integrity",
        "third-party vendor review",
    ),
)

_DENTAL = IndustryProfile(
    industry=Industry.DENTAL_HEALTHCARE,
    common_functions=(
        "appointment booking", "new-patient forms", "insurance information",
        "services", "patient portal link", "contact",
    ),
    sensitive_pages=(
        PageKind.PATIENT_FORM, PageKind.APPOINTMENT_BOOKING,
        PageKind.INSURANCE_FORM, PageKind.PATIENT_PORTAL,
        PageKind.CONTACT,
    ),
    common_vendors=(
        "Zocdoc", "NexHealth", "Solutionreach", "Weave", "SimplePractice",
        "Phreesia",
    ),
    normal_third_parties=("appointment booking", "patient intake",
                          "patient communication", "payment"),
    important_forms=(
        "new-patient intake", "appointment requests", "insurance forms",
        "contact",
    ),
    business_risks=(
        "patient-intake forms collect privacy-sensitive details — an "
        "unexpected destination for that data is a concern",
        "a changed appointment or portal link could send patients to the "
        "wrong place",
        "a new external form on a patient page warrants a closer look",
    ),
    language_style="professional_caring",
    recommendation_priorities=(
        "patient form & intake review",
        "appointment / portal link review",
        "privacy-sensitive form changes",
    ),
)

_LAW = IndustryProfile(
    industry=Industry.LAW_FIRM,
    common_functions=(
        "practice areas", "consultation requests", "case evaluation",
        "client portal link", "document upload", "contact",
    ),
    sensitive_pages=(
        PageKind.CONSULTATION_FORM, PageKind.CASE_INTAKE,
        PageKind.DOCUMENT_UPLOAD, PageKind.CLIENT_PORTAL,
        PageKind.CONTACT,
    ),
    common_vendors=("Clio", "LawPay", "Calendly", "MyCase", "HubSpot"),
    normal_third_parties=("scheduling", "payment", "case management", "crm"),
    important_forms=(
        "consultation requests", "case intake", "document upload", "contact",
    ),
    business_risks=(
        "case-intake and consultation forms collect confidential client "
        "details — an unexpected destination is a concern",
        "a document-upload form sends client files somewhere; that "
        "destination should be one you recognise",
        "an exposed or changed client-portal link warrants review",
    ),
    language_style="formal_trustworthy",
    recommendation_priorities=(
        "client intake review",
        "document upload review",
        "contact form integrity",
    ),
)

_ECOMMERCE = IndustryProfile(
    industry=Industry.LOCAL_ECOMMERCE,
    common_functions=(
        "product catalog", "shopping cart", "checkout", "customer accounts",
        "order status", "shipping", "promotions",
    ),
    sensitive_pages=(
        PageKind.CHECKOUT, PageKind.CART, PageKind.PAYMENT,
        PageKind.CUSTOMER_ACCOUNT, PageKind.ORDER_STATUS, PageKind.LOGIN,
    ),
    common_vendors=(
        "Shopify", "Stripe", "PayPal", "Klarna", "Afterpay", "ShipStation",
        "Klaviyo",
    ),
    normal_third_parties=("payment", "ecommerce platform", "shipping",
                          "email marketing", "analytics"),
    important_forms=(
        "checkout", "account sign-up / login", "newsletter sign-up",
    ),
    business_risks=(
        "a script change on the checkout page is the classic card-skimming "
        "(Magecart) signature and matters more than anywhere else",
        "a new payment-related third party could intercept orders",
        "the customer-account surface is where personal details live",
    ),
    language_style="clear_practical",
    recommendation_priorities=(
        "checkout monitoring",
        "payment provider review",
        "customer account surface",
    ),
)

_HOME = IndustryProfile(
    industry=Industry.HOME_SERVICES,
    common_functions=(
        "services offered", "quote / estimate requests", "online booking",
        "service area", "reviews", "contact",
    ),
    sensitive_pages=(
        PageKind.QUOTE_REQUEST, PageKind.BOOKING, PageKind.CONTACT,
        PageKind.PAYMENT,
    ),
    common_vendors=("ServiceTitan", "Housecall Pro", "Jobber", "Thumbtack"),
    normal_third_parties=("scheduling", "field-service management",
                          "lead generation", "payment"),
    important_forms=(
        "quote / estimate requests", "booking requests", "contact",
    ),
    business_risks=(
        "quote and contact forms carry customer names, addresses, and phone "
        "numbers — their integrity matters",
        "a tampered booking or quote form could send leads to someone else",
        "an unexpected payment step could intercept deposits",
    ),
    language_style="plain_friendly",
    recommendation_priorities=(
        "quote & contact form integrity",
        "booking form review",
        "third-party vendor review",
    ),
)

_NONPROFIT = IndustryProfile(
    industry=Industry.NONPROFIT_CHURCH,
    common_functions=(
        "about / mission", "donations", "events", "volunteer sign-up",
        "newsletter", "contact",
    ),
    sensitive_pages=(
        PageKind.DONATION, PageKind.PAYMENT, PageKind.CONTACT,
    ),
    common_vendors=("Donorbox", "Givebutter", "Tithe.ly", "Planning Center",
                    "Classy"),
    normal_third_parties=("donations", "payment", "email marketing"),
    important_forms=(
        "donation", "volunteer sign-up", "event registration", "contact",
    ),
    business_risks=(
        "the donation flow handles supporters' payment details — a change "
        "there deserves a closer look",
        "a tampered giving page could divert donations",
        "supporter contact details should only go where you expect",
    ),
    language_style="warm_mission_driven",
    recommendation_priorities=(
        "donation flow integrity",
        "payment provider review",
        "supporter form review",
    ),
)

_PROFESSIONAL = IndustryProfile(
    industry=Industry.PROFESSIONAL_SERVICES,
    common_functions=(
        "services", "consultation / contact requests", "scheduling",
        "client portal link", "about", "contact",
    ),
    sensitive_pages=(
        PageKind.CONSULTATION_FORM, PageKind.CONTACT, PageKind.LOGIN,
        PageKind.PAYMENT,
    ),
    common_vendors=("Calendly", "HubSpot", "Stripe", "QuickBooks"),
    normal_third_parties=("scheduling", "crm", "payment"),
    important_forms=(
        "consultation / contact requests", "scheduling", "client sign-in",
    ),
    business_risks=(
        "contact and consultation forms carry client details — their "
        "destination should be one you recognise",
        "a changed scheduling or sign-in link could mislead clients",
        "an unexpected payment step warrants review",
    ),
    language_style="professional_approachable",
    recommendation_priorities=(
        "contact & consultation form integrity",
        "scheduling / sign-in review",
        "third-party vendor review",
    ),
)

_UNKNOWN = IndustryProfile(
    industry=Industry.UNKNOWN,
    common_functions=("general website pages",),
    sensitive_pages=(
        PageKind.CHECKOUT, PageKind.PAYMENT, PageKind.LOGIN,
        PageKind.CONTACT,
    ),
    common_vendors=(),
    normal_third_parties=("payment", "analytics"),
    important_forms=("contact", "sign-in"),
    business_risks=(
        "changes to payment, sign-in, or contact pages deserve review",
    ),
    language_style="clear_neutral",
    recommendation_priorities=(
        "payment & sign-in integrity",
        "contact form integrity",
        "third-party vendor review",
    ),
)


PROFILES: dict[Industry, IndustryProfile] = {
    Industry.RESTAURANT: _RESTAURANT,
    Industry.DENTAL_HEALTHCARE: _DENTAL,
    Industry.LAW_FIRM: _LAW,
    Industry.LOCAL_ECOMMERCE: _ECOMMERCE,
    Industry.HOME_SERVICES: _HOME,
    Industry.NONPROFIT_CHURCH: _NONPROFIT,
    Industry.PROFESSIONAL_SERVICES: _PROFESSIONAL,
    Industry.UNKNOWN: _UNKNOWN,
}


def profile_for(industry: Industry | None) -> IndustryProfile:
    """Return the profile for *industry*, falling back to the UNKNOWN
    profile (never raises, never returns None)."""
    if industry is None:
        return _UNKNOWN
    return PROFILES.get(industry, _UNKNOWN)
