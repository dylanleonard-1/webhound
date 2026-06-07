# WebHound — scanner/webhound/auth/auth_guard.py
# Phase-10 authenticated-scan safety guard (Task 9).
#
# Authenticated scanning is the highest-risk thing WebHound does: a real
# session is loaded, so a stray click could place an order, change a
# password, or delete an account. This guard is the hard stop. It is
# DENY-BY-DEFAULT for anything that could mutate state, and it is
# deliberately stricter than the public-scan safe_interactions deny-list.
#
# Contract:
#   * READ-ONLY. The authenticated browser pass navigates and observes.
#     It NEVER submits a form, completes a checkout, sends a message,
#     or activates any control whose label/role/destination implies a
#     state change.
#   * The guard operates on element metadata (text / aria / role / name
#     / type / href / inForm) and on candidate navigation URLs. It is a
#     pure decision layer — it performs no actions itself.

from __future__ import annotations

import re
from dataclasses import dataclass

# Destructive / state-changing vocabulary. Broader than the public
# deny-list: behind auth, even "save" or "update" mutates real data.
# Matched word-boundary, case-insensitive, against the element's
# combined accessible label.
DESTRUCTIVE_RE = re.compile(
    r"\b("
    # commerce / payment
    r"buy|purchase|pay|payment|checkout|place\s+order|order\s+now|"
    r"add\s+to\s+(cart|bag|basket)|remove\s+from\s+(cart|bag)|"
    r"complete\s+(order|purchase|payment)|subscribe|upgrade|downgrade|"
    r"renew|donate|tip|"
    # destructive
    r"delete|remove|destroy|erase|wipe|clear|cancel|revoke|deactivate|"
    r"close\s+account|terminate|"
    # account / profile mutation
    r"save|update|edit|change|modify|apply|submit|confirm|"
    r"reset\s+password|change\s+password|set\s+password|"
    r"enable|disable|activate|"
    # messaging / social
    r"send|post|publish|comment|reply|message|invite|share|"
    r"like|follow|unfollow|"
    # auth state changes
    r"log\s*out|logout|sign\s*out|"
    # user/role management
    r"add\s+user|remove\s+user|invite\s+user|grant|assign\s+role|"
    r"change\s+role|make\s+admin|ban|suspend"
    r")\b",
    re.IGNORECASE,
)

# URL path/query fragments that indicate a state-changing endpoint even
# without descriptive text (e.g. a bare icon button linking to
# /account/delete?id=...).
DESTRUCTIVE_URL_RE = re.compile(
    r"(/logout|/signout|/sign-out|"
    r"/delete|/remove|/destroy|/cancel|/deactivate|"
    r"/checkout/complete|/order/place|/orders/create|/pay\b|/payment/|"
    r"/password/(change|reset|set)|/account/(delete|close)|"
    r"/unsubscribe|/users?/(delete|remove|ban)|"
    r"[?&](action|do|cmd|op)=(delete|remove|update|save|create|cancel))",
    re.IGNORECASE,
)

# HTTP methods that mutate state — the authenticated pass must only ever
# trigger GET navigation. (Observation of XHR/fetch the *page* fires is
# fine; the guard governs what WE initiate.)
SAFE_METHODS = frozenset({"GET", "HEAD"})


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    reason: str


def is_safe_method(method: str | None) -> bool:
    return (method or "GET").upper() in SAFE_METHODS


def check_navigation(url: str) -> GuardDecision:
    """Decide whether the authenticated pass may navigate to *url*.

    Blocks state-changing endpoints reachable by GET (logout links,
    delete links, etc.) — the classic "GET request with side effects"
    foot-gun, which is exactly what wrecks an authenticated crawl."""
    if not url:
        return GuardDecision(False, "empty url")
    if DESTRUCTIVE_URL_RE.search(url):
        return GuardDecision(False, "destructive endpoint pattern in URL")
    return GuardDecision(True, "navigation looks read-only")


def check_click(meta: dict) -> GuardDecision:
    """Decide whether an element may be clicked during a DEEP
    authenticated scan. Deny-by-default: only elements that are clearly
    pure content-reveals (and not inside a form, not links to
    destructive endpoints) are allowed.

    ``meta`` keys: text, aria, name, title, type, role, href, inForm,
    disabled, expander (has aria-expanded/haspopup/data-toggle/summary).
    """
    label = " ".join(str(meta.get(k) or "") for k in
                     ("text", "aria", "name", "title", "role")).strip()
    short = (meta.get("text") or meta.get("aria") or "?")[:60]

    if meta.get("disabled"):
        return GuardDecision(False, "disabled")
    # Anything inside a form is off-limits — clicking could submit it.
    if meta.get("inForm"):
        return GuardDecision(False, "element inside a form")
    if (meta.get("type") or "").lower() in ("submit", "reset", "image"):
        return GuardDecision(False, "form submit/reset control")
    href = meta.get("href")
    if href:
        nav = check_navigation(str(href))
        if not nav.allowed:
            return GuardDecision(False, f"link → {nav.reason}")
        # A normal navigation link is allowed to be *followed* by the
        # crawler, but the click guard treats link-clicks conservatively:
        # only allow if it's also an expander (e.g. a menu toggle).
        if not meta.get("expander"):
            return GuardDecision(False, "navigation link (use crawler, not click)")
    if DESTRUCTIVE_RE.search(label):
        return GuardDecision(False, f"destructive label: {short!r}")
    # Positive signal required — same posture as public safe_interactions.
    if meta.get("expander"):
        return GuardDecision(True, "content expander")
    return GuardDecision(False, "no positive safe signal")


def assert_read_only(method: str, url: str) -> None:
    """Raise if a non-GET/HEAD request is about to be initiated by the
    scanner itself. A loud failure is correct here — a mutating request
    in an authenticated context is a contract violation, not a warning."""
    if not is_safe_method(method):
        raise AuthSafetyViolation(
            f"authenticated scan attempted {method} {url!r} — only "
            "GET/HEAD are permitted (read-only contract)"
        )


class AuthSafetyViolation(RuntimeError):
    """Raised when an authenticated-scan action would mutate state."""
