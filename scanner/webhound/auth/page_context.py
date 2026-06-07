# WebHound — scanner/webhound/auth/page_context.py
# Phase-10 Task 8: classify an authenticated page by what kind of
# behind-login surface it is, so WADE + reporting can reason about
# sensitivity (a change in /account/settings matters more than one in
# a help article).

from __future__ import annotations

import re
from urllib.parse import urlparse

from webhound.auth.auth_context import AuthPageContext

# Ordered most-specific first. A path can match several; the first wins.
_PATTERNS: list[tuple[re.Pattern[str], AuthPageContext]] = [
    (re.compile(r"/(admin|wp-admin|administrator)(/|$)", re.I),
     AuthPageContext.ADMIN_PORTAL),
    (re.compile(r"/checkout|/payment|/billing/pay", re.I),
     AuthPageContext.CHECKOUT),
    (re.compile(r"/orders?(/|$)|/order-history|/purchase-history|/invoices?", re.I),
     AuthPageContext.ORDER_HISTORY),
    (re.compile(r"/book(ing|ings)?(/|$)|/reservations?|/appointments?", re.I),
     AuthPageContext.BOOKING_PORTAL),
    (re.compile(r"/(profile|account)/(settings|edit|preferences|security)", re.I),
     AuthPageContext.PROFILE_SETTINGS),
    (re.compile(r"/settings(/|$)|/preferences(/|$)", re.I),
     AuthPageContext.PROFILE_SETTINGS),
    (re.compile(r"/login|/signin|/sign-in|/sign-up|/register|/auth|/oauth|/sso|/2fa|/mfa", re.I),
     AuthPageContext.AUTHENTICATION_SURFACE),
    (re.compile(r"/dashboard|/overview|/home/app", re.I),
     AuthPageContext.DASHBOARD),
    (re.compile(r"/account(/|$)|/profile(/|$)|/my[-_/]", re.I),
     AuthPageContext.CUSTOMER_ACCOUNT),
    (re.compile(r"/member|/members|/portal|/workspace|/console", re.I),
     AuthPageContext.MEMBER_AREA),
]


def classify_auth_page(url: str) -> AuthPageContext:
    """Classify an authenticated page URL into an AuthPageContext.

    Returns OTHER when nothing matches — an authenticated page with no
    sensitive markers (e.g. a help-centre article behind login)."""
    try:
        path = urlparse(url).path or "/"
    except Exception:  # noqa: BLE001
        return AuthPageContext.OTHER
    for pattern, ctx in _PATTERNS:
        if pattern.search(path):
            return ctx
    return AuthPageContext.OTHER


# Page contexts whose changes WADE should treat as high-sensitivity.
SENSITIVE_AUTH_CONTEXTS = frozenset({
    AuthPageContext.ADMIN_PORTAL,
    AuthPageContext.CHECKOUT,
    AuthPageContext.PROFILE_SETTINGS,
    AuthPageContext.AUTHENTICATION_SURFACE,
    AuthPageContext.ORDER_HISTORY,
})


def is_sensitive_auth_context(ctx: AuthPageContext) -> bool:
    return ctx in SENSITIVE_AUTH_CONTEXTS
