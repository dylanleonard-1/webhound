# WebHound — scanner/webhound/auth/builder.py
# Phase-10: assemble an AuthContext + the browser auth_state payload
# from whichever auth method the customer supplied. One entry point the
# orchestrator calls; keeps the loader wiring in the auth package.

from __future__ import annotations

from typing import Any

from webhound.auth.auth_context import AuthContext, AuthMode, AuthSource
from webhound.auth.session_loader import load_session_cookies
from webhound.auth.storage_state import load_storage_state


def build_auth(
    *,
    mode: str = "public_only",
    allowed_domains: set[str],
    session_cookies: list[dict[str, Any]] | None = None,
    storage_state: str | dict[str, Any] | None = None,
    now: float | None = None,
) -> tuple[AuthContext, dict[str, Any] | None]:
    """Return (AuthContext, browser_auth_state).

    ``browser_auth_state`` is the secret-carrying payload the runner
    injects into Playwright ({"storage_state": {...}} and/or
    {"cookies": [...]}), or None when no usable session was supplied.
    The AuthContext is secret-free and safe for metadata/reports.

    storageState is preferred when both are supplied."""
    try:
        auth_mode = AuthMode(mode)
    except ValueError:
        auth_mode = AuthMode.PUBLIC_ONLY

    ctx = AuthContext(mode=auth_mode)
    if auth_mode == AuthMode.PUBLIC_ONLY:
        return ctx, None

    browser_state: dict[str, Any] = {}

    if storage_state is not None:
        loaded = load_storage_state(
            storage_state, allowed_domains=allowed_domains, now=now)
        ctx.errors.extend(loaded.errors)
        if loaded.has_session:
            ctx.source = AuthSource.STORAGE_STATE
            ctx.cookies = loaded.cookie_meta
            ctx.auth_domains = set(loaded.auth_domains)
            ctx.storage_origins = list(loaded.origins)
            ctx.session_expires_epoch = loaded.earliest_expiry
            browser_state["storage_state"] = loaded.storage_state

    if session_cookies is not None and "storage_state" not in browser_state:
        loaded_c = load_session_cookies(
            session_cookies, allowed_domains=allowed_domains, now=now)
        ctx.errors.extend(loaded_c.errors)
        if loaded_c.has_session:
            ctx.source = AuthSource.SESSION_COOKIE
            ctx.cookies = loaded_c.cookie_meta
            ctx.auth_domains = set(loaded_c.auth_domains)
            ctx.session_expires_epoch = loaded_c.earliest_expiry
            browser_state["cookies"] = loaded_c.browser_cookies

    if not browser_state:
        if not ctx.errors:
            ctx.errors.append("no usable authenticated session supplied")
        return ctx, None
    return ctx, browser_state
