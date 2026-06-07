# WebHound — tests/test_auth_runner.py
# Phase-10 Tasks 3,8 + runner injection: auth_state threads into the
# browser pass, page-context classification, and build_auth assembly.
# Fully mocked — no Playwright.

from __future__ import annotations

import pytest

from webhound.auth import (
    AuthMode,
    AuthPageContext,
    AuthSource,
    build_auth,
    classify_auth_page,
    is_sensitive_auth_context,
)
from webhound.browser.models import BrowserTelemetry
from webhound.browser.playwright_runner import BrowserPassResult, run_browser_pass

_DOMAINS = {"example.com"}


# ---------------------------------------------------------------------------
# build_auth — assemble AuthContext + browser payload
# ---------------------------------------------------------------------------


def test_build_auth_public_only_no_session() -> None:
    ctx, state = build_auth(mode="public_only", allowed_domains=_DOMAINS)
    assert ctx.mode == AuthMode.PUBLIC_ONLY
    assert state is None
    assert ctx.available is False


def test_build_auth_from_cookies() -> None:
    ctx, state = build_auth(
        mode="combined", allowed_domains=_DOMAINS,
        session_cookies=[{"name": "session", "value": "SECRET",
                          "domain": "example.com"}])
    assert ctx.source == AuthSource.SESSION_COOKIE
    assert ctx.available is True
    assert state and state["cookies"][0]["value"] == "SECRET"
    # The context summary never carries the value.
    assert "SECRET" not in repr(ctx.to_dict())


def test_build_auth_prefers_storage_state() -> None:
    ctx, state = build_auth(
        mode="authenticated_only", allowed_domains=_DOMAINS,
        storage_state={"cookies": [{"name": "sid", "value": "v",
                                    "domain": "example.com"}],
                       "origins": []},
        session_cookies=[{"name": "session", "value": "x",
                          "domain": "example.com"}])
    assert ctx.source == AuthSource.STORAGE_STATE
    assert "storage_state" in state
    assert "cookies" not in state          # storage_state wins


def test_build_auth_no_usable_session_records_error() -> None:
    ctx, state = build_auth(
        mode="authenticated_only", allowed_domains=_DOMAINS,
        session_cookies=[{"name": "x", "value": "v",
                          "domain": "attacker.test"}])  # out of scope
    assert state is None
    assert ctx.errors


# ---------------------------------------------------------------------------
# Runner injection (Task 3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_state_threads_to_runner() -> None:
    seen = {}

    async def _fake_runner(urls, **kwargs):
        seen.update(kwargs)
        return BrowserPassResult(
            telemetries=[BrowserTelemetry(page_url=u) for u in urls])

    await run_browser_pass(
        ["https://example.com/account"], allow_network=True,
        auth_state={"cookies": [{"name": "s", "value": "v",
                                 "domain": "example.com"}]},
        runner=_fake_runner)
    assert "auth_state" in seen
    assert seen["auth_state"]["cookies"][0]["name"] == "s"


# ---------------------------------------------------------------------------
# Page context classification (Task 8)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,ctx", [
    ("https://t.test/admin/users", AuthPageContext.ADMIN_PORTAL),
    ("https://t.test/checkout", AuthPageContext.CHECKOUT),
    ("https://t.test/orders", AuthPageContext.ORDER_HISTORY),
    ("https://t.test/account/order-history", AuthPageContext.ORDER_HISTORY),
    ("https://t.test/bookings", AuthPageContext.BOOKING_PORTAL),
    ("https://t.test/account/settings", AuthPageContext.PROFILE_SETTINGS),
    ("https://t.test/settings", AuthPageContext.PROFILE_SETTINGS),
    ("https://t.test/login", AuthPageContext.AUTHENTICATION_SURFACE),
    ("https://t.test/dashboard", AuthPageContext.DASHBOARD),
    ("https://t.test/account", AuthPageContext.CUSTOMER_ACCOUNT),
    ("https://t.test/portal", AuthPageContext.MEMBER_AREA),
    ("https://t.test/help/article-5", AuthPageContext.OTHER),
])
def test_auth_page_classification(url, ctx) -> None:
    assert classify_auth_page(url) == ctx


def test_sensitive_contexts() -> None:
    assert is_sensitive_auth_context(AuthPageContext.ADMIN_PORTAL)
    assert is_sensitive_auth_context(AuthPageContext.CHECKOUT)
    assert not is_sensitive_auth_context(AuthPageContext.CUSTOMER_ACCOUNT)
    assert not is_sensitive_auth_context(AuthPageContext.OTHER)
