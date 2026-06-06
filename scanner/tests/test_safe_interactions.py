# WebHound — tests/test_safe_interactions.py
# Phase-6B safe interactions. The click decision is pure logic and is
# tested exhaustively; perform_safe_interactions is tested against a
# fake page that records clicks so the "never submit" contract is
# verified end-to-end without Playwright.

from __future__ import annotations

import pytest

from webhound.browser.models import BrowserTelemetry
from webhound.browser.safe_interactions import (
    decide_click,
    perform_safe_interactions,
)


def _meta(**kw) -> dict:
    base = {
        "index": 0, "tag": "button", "text": "", "aria": "",
        "type": "", "name": "", "title": "", "href": None,
        "disabled": False, "inForm": False, "expander": False,
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# decide_click — deny rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text", [
    "Submit", "Send message", "Pay now", "Purchase", "Buy",
    "Checkout", "Delete account", "Remove item", "Confirm",
    "Login", "Log in", "Sign in", "Sign up", "Register",
    "Subscribe", "Add to cart", "Place order", "Save changes",
    "Accept cookies", "Publish",
])
def test_transactional_text_is_denied(text) -> None:
    # Even WITH a positive expander signal, deny wins.
    d = decide_click(_meta(text=text, expander=True))
    assert d.allowed is False
    assert d.reason == "deny_list"


def test_submit_type_denied_regardless_of_text() -> None:
    d = decide_click(_meta(text="Open menu", type="submit"))
    assert d.allowed is False and d.reason == "submit_button"


def test_any_element_inside_form_denied() -> None:
    """Covers 'subscribe if it submits a form' — and every other
    in-form button, period."""
    d = decide_click(_meta(text="Open menu", inForm=True, expander=True))
    assert d.allowed is False and d.reason == "inside_form"


def test_links_and_disabled_denied() -> None:
    assert decide_click(_meta(href="/somewhere", expander=True)).reason == \
        "navigation_link"
    assert decide_click(_meta(disabled=True, expander=True)).reason == \
        "disabled"


def test_deny_matches_aria_label_too() -> None:
    d = decide_click(_meta(text="→", aria="Sign in to your account",
                           expander=True))
    assert d.allowed is False and d.reason == "deny_list"


# ---------------------------------------------------------------------------
# decide_click — allow requires a positive signal
# ---------------------------------------------------------------------------


def test_expander_attributes_allowed() -> None:
    d = decide_click(_meta(text="Products", expander=True))
    assert d.allowed is True and d.reason == "expander_attribute"


def test_menu_text_allowed() -> None:
    d = decide_click(_meta(text="Open navigation menu"))
    assert d.allowed is True and d.reason == "allow_text"


def test_neutral_button_without_signal_blocked() -> None:
    """'appears safe' is not enough — require a positive signal."""
    d = decide_click(_meta(text="Widget"))
    assert d.allowed is False and d.reason == "no_positive_signal"


# ---------------------------------------------------------------------------
# perform_safe_interactions — end-to-end against a fake page
# ---------------------------------------------------------------------------


class _FakeLocator:
    def __init__(self, page, idx):
        self._page, self._idx = page, idx

    def nth(self, idx):
        return _FakeLocator(self._page, idx)

    async def click(self, **kwargs):
        self._page.clicked.append(self._idx)


class _FakePage:
    def __init__(self, candidates):
        self._candidates = candidates
        self.clicked: list[int] = []

    async def evaluate(self, script):
        if "scrollTo" in script:
            return None
        return self._candidates

    def locator(self, _selector):
        return _FakeLocator(self, None)


@pytest.mark.asyncio
async def test_interactions_click_only_safe_candidates() -> None:
    candidates = [
        _meta(index=0, text="Open menu", expander=True),       # safe
        _meta(index=1, text="Submit", type="submit"),          # blocked
        _meta(index=2, text="Subscribe", inForm=True),         # blocked
        _meta(index=3, text="Show more", expander=False),      # safe (text)
        _meta(index=4, text="Pay now"),                        # blocked
    ]
    page = _FakePage(candidates)
    tel = BrowserTelemetry(page_url="https://target.test/")

    await perform_safe_interactions(page, tel)

    assert page.clicked == [0, 3]
    assert tel.blocked_interactions == 3
    assert any(i.startswith("scroll") for i in tel.interactions)
    assert sum(1 for i in tel.interactions if i.startswith("click")) == 2


@pytest.mark.asyncio
async def test_interactions_respect_click_cap() -> None:
    candidates = [
        _meta(index=i, text="Open menu", expander=True) for i in range(20)
    ]
    page = _FakePage(candidates)
    tel = BrowserTelemetry(page_url="https://target.test/")

    await perform_safe_interactions(page, tel, max_clicks=3)

    assert page.clicked == [0, 1, 2]


@pytest.mark.asyncio
async def test_interaction_walk_failure_is_isolated() -> None:
    class _DeadPage:
        async def evaluate(self, script):
            raise RuntimeError("ctx destroyed")

    tel = BrowserTelemetry(page_url="https://target.test/")
    await perform_safe_interactions(_DeadPage(), tel)
    assert tel.blocked_interactions == 0
    assert any("scroll failed" in e for e in tel.errors)
    assert any("interaction walk failed" in e for e in tel.errors)
