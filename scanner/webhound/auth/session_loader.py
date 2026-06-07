# WebHound — scanner/webhound/auth/session_loader.py
# Phase-10 Task 2: load customer-supplied session cookies into a usable,
# validated, SECRET-FREE form.
#
# The customer hands us raw cookies (name+value+attributes). We:
#   * validate scope (domain in-scope), path, and expiration
#   * produce browser-ready cookie dicts for Playwright injection
#   * produce SessionCookieMeta records that carry NO values for the
#     AuthContext / reports
#   * never log or persist the values
#
# The raw values live only in the returned ``browser_cookies`` list,
# which the runner hands straight to Playwright and then drops. Nothing
# in this module writes them anywhere.

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from webhound.auth.auth_context import SessionCookieMeta

# Cookie names that look like real session/auth material — used to warn
# when a customer uploads a cookie set with no obvious session cookie.
_SESSION_NAME_HINTS = (
    "session", "sess", "sid", "auth", "token", "jwt", "csrf",
    "remember", "login", "_secure", "connect.sid", "phpsessid",
    "asp.net", "laravel_session", "_rails", "access",
)


@dataclass
class LoadedSession:
    """Result of loading a cookie set."""

    browser_cookies: list[dict[str, Any]] = field(default_factory=list)  # for Playwright
    cookie_meta: list[SessionCookieMeta] = field(default_factory=list)   # secret-free
    auth_domains: set[str] = field(default_factory=set)
    earliest_expiry: float | None = None
    skipped: list[str] = field(default_factory=list)   # name: reason (no values)
    errors: list[str] = field(default_factory=list)

    @property
    def has_session(self) -> bool:
        return bool(self.browser_cookies)

    @property
    def looks_like_real_session(self) -> bool:
        return any(
            any(h in m.name.lower() for h in _SESSION_NAME_HINTS)
            for m in self.cookie_meta
        )


def _domain_in_scope(cookie_domain: str, allowed_domains: set[str]) -> bool:
    """A cookie domain is in scope when it equals or is a subdomain of
    (or a parent of, for leading-dot cookies) an allowed domain."""
    cd = (cookie_domain or "").lower().lstrip(".")
    if not cd:
        return False
    for allowed in allowed_domains:
        a = allowed.lower().lstrip(".")
        if cd == a or cd.endswith("." + a) or a.endswith("." + cd):
            return True
    return False


def load_session_cookies(
    raw_cookies: list[dict[str, Any]],
    *,
    allowed_domains: set[str],
    now: float | None = None,
) -> LoadedSession:
    """Validate + normalise a customer-supplied cookie list.

    ``raw_cookies`` entries accept Playwright/Chrome-export shape:
    {name, value, domain, path?, secure?, httpOnly?, sameSite?,
     expires?/expirationDate?}.

    Out-of-scope, expired, and malformed cookies are skipped (by NAME
    only — values never appear in diagnostics)."""
    now = time.time() if now is None else now
    out = LoadedSession()
    if not isinstance(raw_cookies, list):
        out.errors.append("cookie payload is not a list")
        return out

    for raw in raw_cookies:
        if not isinstance(raw, dict):
            out.skipped.append("<malformed>: not an object")
            continue
        name = str(raw.get("name") or "").strip()
        value = raw.get("value")
        domain = str(raw.get("domain") or "").strip()
        if not name or value is None:
            out.skipped.append(f"{name or '<unnamed>'}: missing name/value")
            continue
        if not domain:
            out.skipped.append(f"{name}: missing domain")
            continue
        if not _domain_in_scope(domain, allowed_domains):
            out.skipped.append(f"{name}: domain {domain} out of scope")
            continue

        # Expiration — accept expires (unix sec) or expirationDate (float).
        expires = raw.get("expires", raw.get("expirationDate"))
        expires_epoch: float | None = None
        if expires is not None:
            try:
                expires_epoch = float(expires)
                if expires_epoch in (-1, 0):  # session cookie sentinels
                    expires_epoch = None
            except (TypeError, ValueError):
                expires_epoch = None
        if expires_epoch is not None and expires_epoch <= now:
            out.skipped.append(f"{name}: expired")
            continue

        path = str(raw.get("path") or "/")
        secure = bool(raw.get("secure"))
        http_only = bool(raw.get("httpOnly", raw.get("httponly")))
        same_site = raw.get("sameSite") or raw.get("samesite")

        # Browser-ready cookie (carries the value — handed to Playwright,
        # never stored by us).
        bc: dict[str, Any] = {
            "name": name, "value": str(value), "domain": domain,
            "path": path, "secure": secure, "httpOnly": http_only,
        }
        if same_site in ("Strict", "Lax", "None"):
            bc["sameSite"] = same_site
        if expires_epoch is not None:
            bc["expires"] = expires_epoch
        out.browser_cookies.append(bc)

        out.cookie_meta.append(SessionCookieMeta(
            name=name, domain=domain, path=path, secure=secure,
            http_only=http_only,
            same_site=same_site if isinstance(same_site, str) else None,
            expires_epoch=expires_epoch,
            value_length=len(str(value)),
        ))
        out.auth_domains.add(domain.lstrip("."))
        if expires_epoch is not None:
            out.earliest_expiry = (
                expires_epoch if out.earliest_expiry is None
                else min(out.earliest_expiry, expires_epoch)
            )

    return out
