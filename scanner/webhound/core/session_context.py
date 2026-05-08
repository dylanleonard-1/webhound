# WebHound — scanner/webhound/core/session_context.py
# Session-aware scanning context: custom headers, cookies, and bearer-token support.
#
# Security constraints:
#   - Bearer tokens are loaded from environment variables only — never from CLI args.
#   - No basic-auth support.
#   - __repr__, to_dict, and to_json always redact secrets.
#   - merged_headers / merged_cookies are for internal HTTP client use only.
#   - Never store plain-text secrets in logs, findings, or reports.

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

# Header names whose values are always redacted in public representations.
_SENSITIVE_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
})

# Pattern matching key names that look like secrets.
_TOKEN_LIKE_PATTERN: re.Pattern[str] = re.compile(
    r"(token|secret|key|auth|pass|cred|bearer)", re.IGNORECASE
)


def _is_sensitive_header(name: str) -> bool:
    """Return True when a header name should always be redacted."""
    lower = name.lower()
    return lower in _SENSITIVE_HEADERS or bool(_TOKEN_LIKE_PATTERN.search(lower))


def _redact(name: str, value: str) -> str:
    """Return the value redacted when the header name is sensitive."""
    return "<redacted>" if _is_sensitive_header(name) else value


def parse_header(raw: str) -> tuple[str, str]:
    """Parse a ``Name: value`` string into (name, value).

    Raises ``ValueError`` when the string does not contain a colon separator
    or the name part is empty.
    """
    if ":" not in raw:
        raise ValueError(
            f"Invalid header format {raw!r}. Expected 'Name: value'."
        )
    name, _, value = raw.partition(":")
    name = name.strip()
    value = value.strip()
    if not name:
        raise ValueError(f"Header name must not be empty in {raw!r}.")
    return name, value


def parse_cookie(raw: str) -> tuple[str, str]:
    """Parse a ``name=value`` string into (name, value).

    Raises ``ValueError`` when the string does not contain ``=`` or the name
    part is empty.
    """
    if "=" not in raw:
        raise ValueError(
            f"Invalid cookie format {raw!r}. Expected 'name=value'."
        )
    name, _, value = raw.partition("=")
    name = name.strip()
    if not name:
        raise ValueError(f"Cookie name must not be empty in {raw!r}.")
    return name, value


class SessionContext:
    """Carries custom headers, cookies, and an optional bearer token for a scan.

    Secrets are **never** exposed through :meth:`__repr__`, :meth:`to_dict`, or
    :meth:`to_json`.  Use :meth:`merged_headers` / :meth:`merged_cookies` only
    inside the HTTP client where the values are needed for actual requests.

    Usage::

        ctx = SessionContext(headers={"X-My-Header": "value"})
        ctx = SessionContext.from_env("WEBHOUND_TOKEN")
        ctx = SessionContext.from_file("session.json")
    """

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        *,
        _bearer_token: str | None = None,
    ) -> None:
        self._headers: dict[str, str] = dict(headers or {})
        self._cookies: dict[str, str] = dict(cookies or {})
        self._bearer_token: str | None = _bearer_token

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls, env_var: str) -> "SessionContext":
        """Load a bearer token from environment variable *env_var*.

        Raises ``ValueError`` when the variable is absent or empty so callers
        receive an explicit error rather than silently scanning without auth.
        """
        token = os.environ.get(env_var, "").strip()
        if not token:
            raise ValueError(
                f"Environment variable {env_var!r} is not set or empty. "
                "Provide the bearer token via that variable."
            )
        return cls(_bearer_token=token)

    @classmethod
    def from_file(cls, path: str | Path) -> "SessionContext":
        """Load session headers and cookies from a JSON file.

        Only ``headers`` and ``cookies`` keys are read.  Passwords, tokens, and
        any other secret fields are intentionally ignored.

        Expected file format::

            {
                "headers": {"X-Custom": "value"},
                "cookies": {"session_id": "abc123"}
            }
        """
        raw = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Session file is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("Session file must contain a JSON object at the top level.")
        headers = data.get("headers") or {}
        cookies = data.get("cookies") or {}
        if not isinstance(headers, dict):
            raise ValueError("Session file 'headers' must be an object.")
        if not isinstance(cookies, dict):
            raise ValueError("Session file 'cookies' must be an object.")
        return cls(headers=headers, cookies=cookies)

    @classmethod
    def merge(cls, *contexts: "SessionContext") -> "SessionContext":
        """Merge multiple contexts; later contexts win on key conflicts."""
        merged_headers: dict[str, str] = {}
        merged_cookies: dict[str, str] = {}
        bearer: str | None = None
        for ctx in contexts:
            merged_headers.update(ctx._headers)
            merged_cookies.update(ctx._cookies)
            if ctx._bearer_token is not None:
                bearer = ctx._bearer_token
        return cls(
            headers=merged_headers,
            cookies=merged_cookies,
            _bearer_token=bearer,
        )

    # ------------------------------------------------------------------
    # Internal use only (HTTP client)
    # ------------------------------------------------------------------

    def merged_headers(self) -> dict[str, str]:
        """Full headers dict including Authorization when a token is set.

        For internal HTTP client use only — never expose this to logs or reports.
        """
        headers = dict(self._headers)
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        return headers

    def merged_cookies(self) -> dict[str, str]:
        """Full cookies dict for internal HTTP client use."""
        return dict(self._cookies)

    # ------------------------------------------------------------------
    # Safe public representations (redacted)
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a redacted dict safe for logging and reports."""
        return {
            "headers": {k: _redact(k, v) for k, v in self._headers.items()},
            "cookies": {k: "<redacted>" for k in self._cookies},
            "bearer_token": "<set>" if self._bearer_token else None,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Return a redacted JSON string safe for logging and reports."""
        return json.dumps(self.to_dict(), indent=indent)

    def __repr__(self) -> str:
        return (
            f"SessionContext("
            f"headers={len(self._headers)}, "
            f"cookies={len(self._cookies)}, "
            f"bearer_token={'<set>' if self._bearer_token else None}"
            f")"
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def has_auth(self) -> bool:
        """True when a bearer token is set or an Authorization header is present."""
        return self._bearer_token is not None or any(
            k.lower() == "authorization" for k in self._headers
        )

    @property
    def is_empty(self) -> bool:
        """True when no headers, cookies, or bearer token are configured."""
        return not self._headers and not self._cookies and not self._bearer_token

    @property
    def header_count(self) -> int:
        return len(self._headers)

    @property
    def cookie_count(self) -> int:
        return len(self._cookies)
