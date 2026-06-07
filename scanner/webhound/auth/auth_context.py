# WebHound — scanner/webhound/auth/auth_context.py
# Phase-10 authenticated scanning: the context object that tracks an
# authenticated session and the surface discovered behind it.
#
# TRUST POSTURE (non-negotiable):
#   * Session material (cookie values, storage-state tokens, passwords)
#     is NEVER stored on this object. We keep names, domains, flags,
#     expirations, and counts — never secrets. Reports and logs read
#     from here, so anything stored here is a potential leak.
#   * Authenticated scanning is READ-ONLY. This object records what was
#     *observed* behind auth; nothing here performs actions.

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AuthMode(str, Enum):
    """Customer control over what gets scanned (Task 10)."""

    PUBLIC_ONLY = "public_only"             # no auth (default, unchanged behaviour)
    AUTHENTICATED_ONLY = "authenticated_only"
    COMBINED = "combined"                   # public + authenticated
    DEEP_AUTHENTICATED = "deep_authenticated"  # combined + safe interactions behind auth


class AuthSource(str, Enum):
    """Where the session came from (Task 1)."""

    NONE = "none"
    SESSION_COOKIE = "session_cookie"
    STORAGE_STATE = "storage_state"
    LOGIN_RECORDING = "login_recording"
    TEST_CREDENTIALS = "test_credentials"


# Authenticated page-context labels (Task 8). Superset of the public
# context_engine labels, specialised for behind-login surfaces.
class AuthPageContext(str, Enum):
    CUSTOMER_ACCOUNT = "customer_account"
    BOOKING_PORTAL = "booking_portal"
    MEMBER_AREA = "member_area"
    ADMIN_PORTAL = "admin_portal"
    CHECKOUT = "checkout"
    ORDER_HISTORY = "order_history"
    PROFILE_SETTINGS = "profile_settings"
    AUTHENTICATION_SURFACE = "authentication_surface"
    DASHBOARD = "dashboard"
    OTHER = "other"


@dataclass(frozen=True)
class SessionCookieMeta:
    """Non-secret metadata about one session cookie."""

    name: str
    domain: str
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    expires_epoch: float | None = None       # unix seconds, None = session cookie
    value_length: int = 0                    # length only — never the value

    @property
    def is_expired(self) -> bool:
        return (self.expires_epoch is not None
                and self.expires_epoch <= time.time())


@dataclass
class AuthContext:
    """Tracks an authenticated session + the surface discovered behind it.

    All collections start empty; the orchestrator's authenticated passes
    populate them. ``available`` is False until a session is actually
    loaded, so callers can branch cheaply."""

    mode: AuthMode = AuthMode.PUBLIC_ONLY
    source: AuthSource = AuthSource.NONE
    # Session identity (non-secret).
    cookies: list[SessionCookieMeta] = field(default_factory=list)
    auth_domains: set[str] = field(default_factory=set)   # domains the session is scoped to
    session_expires_epoch: float | None = None            # earliest cookie expiry
    storage_origins: list[str] = field(default_factory=list)  # origins in storageState
    # Discovered authenticated surface (Task 1, 5, 6).
    authenticated_pages: list[str] = field(default_factory=list)
    authenticated_apis: list[str] = field(default_factory=list)
    authenticated_forms: int = 0
    authenticated_routes: list[str] = field(default_factory=list)
    authenticated_third_parties: set[str] = field(default_factory=set)
    page_contexts: dict[str, str] = field(default_factory=dict)  # url -> AuthPageContext value
    # Diagnostics.
    errors: list[str] = field(default_factory=list)

    @property
    def available(self) -> bool:
        """True when a usable session was loaded."""
        return (self.source != AuthSource.NONE
                and (bool(self.cookies) or bool(self.storage_origins))
                and not self.is_expired)

    @property
    def is_expired(self) -> bool:
        return (self.session_expires_epoch is not None
                and self.session_expires_epoch <= time.time())

    @property
    def wants_auth(self) -> bool:
        return self.mode in (
            AuthMode.AUTHENTICATED_ONLY, AuthMode.COMBINED,
            AuthMode.DEEP_AUTHENTICATED,
        )

    @property
    def wants_public(self) -> bool:
        return self.mode in (
            AuthMode.PUBLIC_ONLY, AuthMode.COMBINED,
            AuthMode.DEEP_AUTHENTICATED,
        )

    def record_page(self, url: str, context: AuthPageContext) -> None:
        if url and url not in self.authenticated_pages:
            self.authenticated_pages.append(url)
        if url:
            self.page_contexts[url] = context.value

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe summary for scan metadata. Secret-free by
        construction — only counts, names, domains, flags, expirations."""
        return {
            "mode": self.mode.value,
            "source": self.source.value,
            "available": self.available,
            "expired": self.is_expired,
            "session_expires_epoch": self.session_expires_epoch,
            "auth_domains": sorted(self.auth_domains),
            "cookie_count": len(self.cookies),
            "cookies": [
                {
                    "name": c.name, "domain": c.domain, "path": c.path,
                    "secure": c.secure, "http_only": c.http_only,
                    "same_site": c.same_site,
                    "expires_epoch": c.expires_epoch,
                    "expired": c.is_expired,
                    "value_length": c.value_length,
                }
                for c in self.cookies
            ],
            "storage_origins": list(self.storage_origins),
            "authenticated_page_count": len(self.authenticated_pages),
            "authenticated_api_count": len(self.authenticated_apis),
            "authenticated_form_count": self.authenticated_forms,
            "authenticated_route_count": len(self.authenticated_routes),
            "authenticated_third_parties": sorted(
                self.authenticated_third_parties),
            "page_contexts": dict(self.page_contexts),
            "errors": list(self.errors),
        }
