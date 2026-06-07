# WebHound — tests/test_auth_guard.py
# Phase-10 authenticated-scan safety core: AuthContext + AuthGuard.
# These encode the read-only contract — the most important tests in the
# phase. If any of these regress, authenticated scanning is unsafe.

from __future__ import annotations

import time

import pytest

from webhound.auth.auth_context import (
    AuthContext,
    AuthMode,
    AuthPageContext,
    AuthSource,
    SessionCookieMeta,
)
from webhound.auth.auth_guard import (
    AuthSafetyViolation,
    assert_read_only,
    check_click,
    check_navigation,
    is_safe_method,
)


def _meta(**kw) -> dict:
    base = {"text": "", "aria": "", "name": "", "title": "", "type": "",
            "role": "", "href": None, "inForm": False, "disabled": False,
            "expander": False}
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# Read-only method enforcement (Task 9)
# ---------------------------------------------------------------------------


def test_only_get_head_are_safe_methods() -> None:
    assert is_safe_method("GET")
    assert is_safe_method("HEAD")
    assert is_safe_method(None)
    for m in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        assert not is_safe_method(m)


def test_assert_read_only_raises_on_mutating_method() -> None:
    assert_read_only("GET", "https://t.test/account")  # no raise
    for m in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(AuthSafetyViolation):
            assert_read_only(m, "https://t.test/x")


# ---------------------------------------------------------------------------
# Navigation guard — GET-with-side-effects foot-gun
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "https://t.test/logout",
    "https://t.test/account/delete?id=5",
    "https://t.test/orders/create",
    "https://t.test/checkout/complete",
    "https://t.test/password/change",
    "https://t.test/users/ban?u=7",
    "https://t.test/cart/remove?item=3",
    "https://t.test/item?action=delete",
    "https://t.test/x?do=update",
])
def test_destructive_navigation_blocked(url) -> None:
    assert check_navigation(url).allowed is False


@pytest.mark.parametrize("url", [
    "https://t.test/account",
    "https://t.test/dashboard",
    "https://t.test/orders",
    "https://t.test/profile/settings",
    "https://t.test/bookings",
])
def test_readonly_navigation_allowed(url) -> None:
    assert check_navigation(url).allowed is True


# ---------------------------------------------------------------------------
# Click guard — deny by default
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text", [
    "Buy now", "Place order", "Complete purchase", "Pay", "Checkout",
    "Add to cart", "Subscribe", "Delete account", "Remove", "Cancel",
    "Save", "Update profile", "Edit", "Change password", "Reset password",
    "Send message", "Post comment", "Log out", "Sign out", "Deactivate",
    "Invite user", "Make admin", "Confirm", "Submit", "Publish",
])
def test_destructive_clicks_blocked(text) -> None:
    # Even with an expander signal, destructive labels are denied.
    assert check_click(_meta(text=text, expander=True)).allowed is False


def test_form_elements_never_clicked() -> None:
    assert check_click(_meta(text="Open", inForm=True, expander=True)
                       ).allowed is False
    assert check_click(_meta(text="Open menu", type="submit")).allowed is False


def test_destructive_links_blocked() -> None:
    assert check_click(_meta(text="x", href="/account/delete",
                             expander=True)).allowed is False
    assert check_click(_meta(text="Log out", href="/logout")).allowed is False


def test_plain_navigation_link_not_clicked() -> None:
    # A normal link is followed by the crawler, not clicked.
    assert check_click(_meta(text="Orders", href="/orders")).allowed is False


def test_safe_expander_allowed() -> None:
    assert check_click(_meta(text="Show details", expander=True)).allowed is True
    assert check_click(_meta(text="Open menu", expander=True)).allowed is True


def test_neutral_element_without_signal_blocked() -> None:
    assert check_click(_meta(text="Widget")).allowed is False


# ---------------------------------------------------------------------------
# AuthContext (Task 1) — secret-free
# ---------------------------------------------------------------------------


def test_cookie_meta_stores_no_value() -> None:
    c = SessionCookieMeta(name="session", domain=".t.test", value_length=42)
    assert "value" not in c.__dict__ or not hasattr(c, "value")
    assert c.value_length == 42
    d = AuthContext(cookies=[c]).to_dict()
    blob = repr(d)
    assert "42" in blob          # length present
    # no field literally named value carrying secret content
    assert all("value_length" == k or "value" not in k
               for entry in d["cookies"] for k in entry)


def test_context_available_only_with_unexpired_session() -> None:
    fresh = AuthContext(
        source=AuthSource.SESSION_COOKIE,
        cookies=[SessionCookieMeta(name="s", domain=".t.test")],
    )
    assert fresh.available is True

    expired = AuthContext(
        source=AuthSource.SESSION_COOKIE,
        cookies=[SessionCookieMeta(name="s", domain=".t.test")],
        session_expires_epoch=time.time() - 10,
    )
    assert expired.is_expired is True
    assert expired.available is False

    none = AuthContext()
    assert none.available is False


def test_auth_mode_intent_flags() -> None:
    assert AuthContext(mode=AuthMode.PUBLIC_ONLY).wants_public is True
    assert AuthContext(mode=AuthMode.PUBLIC_ONLY).wants_auth is False
    assert AuthContext(mode=AuthMode.AUTHENTICATED_ONLY).wants_auth is True
    assert AuthContext(mode=AuthMode.AUTHENTICATED_ONLY).wants_public is False
    assert AuthContext(mode=AuthMode.COMBINED).wants_auth is True
    assert AuthContext(mode=AuthMode.COMBINED).wants_public is True


def test_record_page_classifies() -> None:
    ctx = AuthContext()
    ctx.record_page("https://t.test/account",
                    AuthPageContext.CUSTOMER_ACCOUNT)
    assert "https://t.test/account" in ctx.authenticated_pages
    assert ctx.page_contexts["https://t.test/account"] == "customer_account"
