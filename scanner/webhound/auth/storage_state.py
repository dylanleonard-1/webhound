# WebHound — scanner/webhound/auth/storage_state.py
# Phase-10 Task 3: load a Playwright storageState.json (cookies +
# origin localStorage) into a validated, SECRET-FREE summary plus a
# browser-ready payload for context injection.
#
# storageState is the preferred auth method: the customer records a
# session once (playwright codegen / their own login) and uploads the
# JSON — no credentials reach WebHound. We validate scope and strip
# secrets for everything that lands in AuthContext / reports.

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from webhound.auth.auth_context import SessionCookieMeta
from webhound.auth.session_loader import _domain_in_scope


@dataclass
class LoadedStorageState:
    """Result of loading a storageState payload."""

    # Browser-ready payload (Playwright new_context(storage_state=...)).
    # Carries values; handed to Playwright, never persisted by us.
    storage_state: dict[str, Any] | None = None
    cookie_meta: list[SessionCookieMeta] = field(default_factory=list)
    auth_domains: set[str] = field(default_factory=set)
    origins: list[str] = field(default_factory=list)
    local_storage_key_counts: dict[str, int] = field(default_factory=dict)
    earliest_expiry: float | None = None
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_session(self) -> bool:
        return bool(self.storage_state and (
            self.storage_state.get("cookies")
            or self.storage_state.get("origins")
        ))


def load_storage_state(
    payload: str | dict[str, Any],
    *,
    allowed_domains: set[str],
    now: float | None = None,
) -> LoadedStorageState:
    """Parse + validate a Playwright storageState payload (raw JSON
    string or already-parsed dict).

    Keeps only in-scope, unexpired cookies and in-scope origins.
    Local-storage VALUES are never read into our models — only per-origin
    key counts, so a report can say 'portal.example.com had 4 local-
    storage keys' without exposing tokens."""
    now = time.time() if now is None else now
    out = LoadedStorageState()

    if isinstance(payload, str):
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, ValueError) as exc:
            out.errors.append(f"invalid storageState JSON: {type(exc).__name__}")
            return out
    elif isinstance(payload, dict):
        data = payload
    else:
        out.errors.append("storageState payload must be JSON string or dict")
        return out

    if not isinstance(data, dict):
        out.errors.append("storageState root is not an object")
        return out

    kept_cookies: list[dict[str, Any]] = []
    for raw in data.get("cookies") or []:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "")
        domain = str(raw.get("domain") or "")
        if not name or not domain:
            out.skipped.append(f"{name or '<unnamed>'}: missing name/domain")
            continue
        if not _domain_in_scope(domain, allowed_domains):
            out.skipped.append(f"{name}: domain {domain} out of scope")
            continue
        expires = raw.get("expires")
        expires_epoch: float | None = None
        if expires is not None:
            try:
                expires_epoch = float(expires)
                if expires_epoch in (-1, 0):
                    expires_epoch = None
            except (TypeError, ValueError):
                expires_epoch = None
        if expires_epoch is not None and expires_epoch <= now:
            out.skipped.append(f"{name}: expired")
            continue
        kept_cookies.append(raw)
        same_site = raw.get("sameSite")
        out.cookie_meta.append(SessionCookieMeta(
            name=name, domain=domain, path=str(raw.get("path") or "/"),
            secure=bool(raw.get("secure")),
            http_only=bool(raw.get("httpOnly")),
            same_site=same_site if isinstance(same_site, str) else None,
            expires_epoch=expires_epoch,
            value_length=len(str(raw.get("value") or "")),
        ))
        out.auth_domains.add(domain.lstrip("."))
        if expires_epoch is not None:
            out.earliest_expiry = (
                expires_epoch if out.earliest_expiry is None
                else min(out.earliest_expiry, expires_epoch))

    kept_origins: list[dict[str, Any]] = []
    for origin in data.get("origins") or []:
        if not isinstance(origin, dict):
            continue
        origin_url = str(origin.get("origin") or "")
        host = urlparse(origin_url).hostname or ""
        if host and not _domain_in_scope(host, allowed_domains):
            out.skipped.append(f"origin {origin_url}: out of scope")
            continue
        kept_origins.append(origin)
        if origin_url:
            out.origins.append(origin_url)
            ls = origin.get("localStorage") or []
            out.local_storage_key_counts[origin_url] = (
                len(ls) if isinstance(ls, list) else 0
            )

    out.storage_state = {"cookies": kept_cookies, "origins": kept_origins}
    return out
