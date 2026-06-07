# WebHound — scanner/webhound/industry/context_rules.py
# Phase-19 Task 3 (+ Task 9 graph integration): which pages are sensitive
# for a given industry, and how to read a page's purpose.
#
# This complements the WADE ContextEngine (wade/context_engine.py). WADE
# classifies pages into security-generic contexts (checkout/login/admin);
# here we classify into business-meaningful kinds (online ordering, patient
# intake, case upload) so the rest of the industry layer can reason about
# what a change actually touches.

from __future__ import annotations

import re
from dataclasses import dataclass, field

from webhound.industry.industry_profiles import profile_for
from webhound.industry.models import (
    SENSITIVE_PAGE_KINDS,
    BusinessLabel,
    Industry,
    PageKind,
)

# ---------------------------------------------------------------------------
# URL / text patterns → PageKind. Ordered: more specific kinds first so a
# "/patient-forms" page reads as PATIENT_FORM, not generic CONTACT.
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[re.Pattern[str], PageKind]] = [
    # Restaurant
    (re.compile(r"order[-_ ]?online|online[-_ ]?order|/order\b", re.I),
     PageKind.ONLINE_ORDERING),
    (re.compile(r"reservation|book[-_ ]?(a[-_ ]?)?table|opentable", re.I),
     PageKind.RESERVATIONS),
    (re.compile(r"gift[-_ ]?cards?", re.I), PageKind.GIFT_CARDS),
    # Commerce / payment
    (re.compile(r"/checkout|/cart/checkout", re.I), PageKind.CHECKOUT),
    (re.compile(r"/cart|/basket|/bag\b", re.I), PageKind.CART),
    (re.compile(r"/payment|/pay(/|$)|/billing", re.I), PageKind.PAYMENT),
    (re.compile(r"order[-_ ]?status|track[-_ ]?order", re.I),
     PageKind.ORDER_STATUS),
    (re.compile(r"/account|/profile|/my[-_/]", re.I),
     PageKind.CUSTOMER_ACCOUNT),
    # Healthcare
    (re.compile(r"new[-_ ]?patient|patient[-_ ]?forms?|intake[-_ ]?forms?",
                re.I), PageKind.PATIENT_FORM),
    (re.compile(r"patient[-_ ]?portal|mychart", re.I), PageKind.PATIENT_PORTAL),
    (re.compile(r"insurance", re.I), PageKind.INSURANCE_FORM),
    (re.compile(r"appointment|book[-_ ]?(an[-_ ]?)?appointment|schedule",
                re.I), PageKind.APPOINTMENT_BOOKING),
    # Legal
    (re.compile(r"case[-_ ]?intake|new[-_ ]?case|case[-_ ]?evaluation", re.I),
     PageKind.CASE_INTAKE),
    (re.compile(r"document[-_ ]?upload|upload[-_ ]?(your[-_ ]?)?documents?|"
                r"file[-_ ]?upload", re.I), PageKind.DOCUMENT_UPLOAD),
    (re.compile(r"client[-_ ]?portal|/portal", re.I), PageKind.CLIENT_PORTAL),
    (re.compile(r"consultation|free[-_ ]?consult|case[-_ ]?review", re.I),
     PageKind.CONSULTATION_FORM),
    # Home services
    (re.compile(r"\bquote\b|request[-_ ]?(a[-_ ]?)?quote|estimate", re.I),
     PageKind.QUOTE_REQUEST),
    (re.compile(r"/book(ing)?\b|schedule[-_ ]?service", re.I),
     PageKind.BOOKING),
    # Nonprofit
    (re.compile(r"donate|donation|/give\b|giving", re.I), PageKind.DONATION),
    # Shared
    (re.compile(r"/login|/signin|/sign-in|/auth|/register|/sign-up", re.I),
     PageKind.LOGIN),
    (re.compile(r"/contact|contact[-_ ]?us|get[-_ ]?in[-_ ]?touch", re.I),
     PageKind.CONTACT),
]

# PageKind → business-friendly label for the kind of data it touches (Task 4).
_KIND_LABEL: dict[PageKind, BusinessLabel] = {
    PageKind.ONLINE_ORDERING: BusinessLabel.PAYMENT_RELATED,
    PageKind.GIFT_CARDS: BusinessLabel.PAYMENT_RELATED,
    PageKind.CHECKOUT: BusinessLabel.PAYMENT_RELATED,
    PageKind.CART: BusinessLabel.PAYMENT_RELATED,
    PageKind.PAYMENT: BusinessLabel.PAYMENT_RELATED,
    PageKind.DONATION: BusinessLabel.DONATION_RELATED,
    PageKind.RESERVATIONS: BusinessLabel.APPOINTMENT_OR_BOOKING,
    PageKind.APPOINTMENT_BOOKING: BusinessLabel.APPOINTMENT_OR_BOOKING,
    PageKind.BOOKING: BusinessLabel.APPOINTMENT_OR_BOOKING,
    PageKind.PATIENT_FORM: BusinessLabel.PRIVACY_SENSITIVE,
    PageKind.INSURANCE_FORM: BusinessLabel.PRIVACY_SENSITIVE,
    PageKind.PATIENT_PORTAL: BusinessLabel.PRIVACY_SENSITIVE,
    PageKind.CASE_INTAKE: BusinessLabel.CLIENT_INTAKE,
    PageKind.CONSULTATION_FORM: BusinessLabel.CLIENT_INTAKE,
    PageKind.DOCUMENT_UPLOAD: BusinessLabel.CLIENT_INTAKE,
    PageKind.CLIENT_PORTAL: BusinessLabel.CLIENT_INTAKE,
    PageKind.CUSTOMER_ACCOUNT: BusinessLabel.CUSTOMER_INFORMATION,
    PageKind.ORDER_STATUS: BusinessLabel.CUSTOMER_INFORMATION,
    PageKind.LOGIN: BusinessLabel.CUSTOMER_INFORMATION,
    PageKind.CONTACT: BusinessLabel.CUSTOMER_INFORMATION,
    PageKind.GENERAL: BusinessLabel.GENERAL,
}


@dataclass
class PageClassification:
    """How the industry layer reads one page."""

    url: str
    kind: PageKind
    is_sensitive: bool
    business_label: BusinessLabel
    matched: bool = False        # did a pattern match (vs. defaulted)?
    signals: list[str] = field(default_factory=list)


def classify_page(
    industry: Industry,
    url: str,
    *,
    title: str | None = None,
    has_form: bool = False,
) -> PageClassification:
    """Classify *url* (and optional title) into a :class:`PageClassification`.

    *industry* refines the result: the same page is "sensitive" for some
    industries and routine for others. *has_form* nudges a generic page
    toward CONTACT when it carries a form but matched nothing specific."""
    haystack = f"{url} {title or ''}"
    for rx, kind in _PATTERNS:
        if rx.search(haystack):
            is_sensitive = _is_sensitive(industry, kind)
            return PageClassification(
                url=url, kind=kind, is_sensitive=is_sensitive,
                business_label=_KIND_LABEL.get(kind, BusinessLabel.GENERAL),
                matched=True,
                signals=[f"matched {kind.value}"],
            )
    # No specific match: a page that carries a form is at least a contact-grade
    # surface; otherwise it's general.
    if has_form:
        return PageClassification(
            url=url, kind=PageKind.CONTACT,
            is_sensitive=_is_sensitive(industry, PageKind.CONTACT),
            business_label=BusinessLabel.CUSTOMER_INFORMATION,
            matched=False, signals=["form present, no specific page match"],
        )
    return PageClassification(
        url=url, kind=PageKind.GENERAL, is_sensitive=False,
        business_label=BusinessLabel.GENERAL, matched=False,
        signals=["no page-kind match"],
    )


def _is_sensitive(industry: Industry, kind: PageKind) -> bool:
    """A page kind is sensitive if it's globally sensitive OR explicitly
    listed in the industry's profile."""
    if kind in SENSITIVE_PAGE_KINDS:
        return True
    return kind in profile_for(industry).sensitive_pages


def sensitive_pages_for(industry: Industry) -> tuple[PageKind, ...]:
    """The page kinds the industry profile marks as sensitive (Task 3)."""
    return profile_for(industry).sensitive_pages


def business_label_for(kind: PageKind) -> BusinessLabel:
    return _KIND_LABEL.get(kind, BusinessLabel.GENERAL)


# ---------------------------------------------------------------------------
# Task 9 — Security Graph integration.
#
# Industry logic should be able to use graph context to answer questions like
# "which scripts touch checkout?" or "which vendors connect to payment?".
# These helpers take a GraphQuery (graph/graph_query.py) and a classifier so
# we reuse the existing traversals rather than re-implementing them.
# ---------------------------------------------------------------------------


def sensitive_pages_in_graph(industry: Industry, graph_query) -> list:
    """Return graph PAGE nodes whose URL classifies as a sensitive page for
    *industry*. ``graph_query`` is a ``webhound.graph.graph_query.GraphQuery``.
    """
    from webhound.graph.models import NodeType
    out = []
    for node_type in (NodeType.PAGE, NodeType.RENDERED_PAGE):
        for page in graph_query.g.nodes_of_type(node_type):
            pc = classify_page(industry, page.value or page.label or "")
            if pc.is_sensitive:
                out.append(page)
    return out


def scripts_touching_sensitive_flows(industry: Industry, graph_query) -> dict:
    """Map each sensitive page URL → the SCRIPT nodes it loads.

    Answers "which scripts touch checkout / patient intake / case upload?"."""
    out: dict[str, list] = {}
    for page in sensitive_pages_in_graph(industry, graph_query):
        scripts = graph_query.get_page_scripts(page.value or page.label or "")
        if scripts:
            out[page.value or page.label or ""] = scripts
    return out


def vendors_connected_to_payment(graph_query) -> list:
    """VENDOR / THIRD_PARTY_DOMAIN nodes reachable from a payment-context
    page. Uses the graph to surface who is connected to money flows."""
    from webhound.graph.models import NodeType
    from webhound.industry.models import Industry as _Ind
    seen: dict[str, object] = {}
    for node_type in (NodeType.PAGE, NodeType.RENDERED_PAGE):
        for page in graph_query.g.nodes_of_type(node_type):
            pc = classify_page(_Ind.UNKNOWN, page.value or page.label or "")
            if pc.business_label != BusinessLabel.PAYMENT_RELATED:
                continue
            url = page.value or page.label or ""
            for script in graph_query.get_page_scripts(url):
                for dom in graph_query.g.neighbors(
                    script.id, target_type=NodeType.THIRD_PARTY_DOMAIN
                ):
                    seen[dom.id] = dom
    return list(seen.values())
