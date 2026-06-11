# WebHound — scanner/webhound/models/target.py
# Target model: the website/URL being scanned, its TLS posture,
# detected technology stack, and the options governing the scan run.

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator, model_validator

from webhound.identity import SCANNER_USER_AGENT


class TargetScope(str, Enum):
    """How broadly the scan is permitted to crawl."""

    SINGLE_PAGE = "single_page"    # Only the exact URL
    SUBDIRECTORY = "subdirectory"  # URL and children under the same path prefix
    FULL_DOMAIN = "full_domain"    # Entire domain
    URL_LIST = "url_list"          # Explicit list of URLs


class TLSInfo(BaseModel):
    """TLS certificate and connection metadata captured during reconnaissance."""

    hostname: str
    port: int = Field(default=443, ge=1, le=65535)
    subject: dict[str, str] = Field(default_factory=dict)
    issuer: dict[str, str] = Field(default_factory=dict)
    not_before: datetime | None = Field(default=None)
    not_after: datetime | None = Field(default=None)
    protocol_version: str | None = Field(default=None, description="e.g. 'TLSv1.3'")
    cipher_suite: str | None = Field(default=None)
    san_names: list[str] = Field(default_factory=list, description="Subject Alt Names")
    is_valid: bool = Field(default=True)
    is_self_signed: bool = Field(default=False)

    @property
    def days_until_expiry(self) -> int | None:
        if self.not_after is None:
            return None
        delta = self.not_after - datetime.now(timezone.utc)
        return max(0, delta.days)

    @property
    def is_expired(self) -> bool:
        if self.not_after is None:
            return False
        return datetime.now(timezone.utc) > self.not_after


class ScanOptions(BaseModel):
    """Tunable parameters controlling crawler behaviour and engine selection."""

    max_depth: int = Field(default=3, ge=1, le=10)
    max_pages: int = Field(default=100, ge=1, le=5000)
    request_timeout_seconds: int = Field(default=30, ge=5, le=120)
    follow_redirects: bool = Field(default=True)
    user_agent: str = Field(default=SCANNER_USER_AGENT)
    # Extra request headers injected on EVERY HTTP + browser request (e.g. a provider
    # trusted-automation bypass like Vercel's `x-vercel-protection-bypass`). Empty by
    # default; populated per-scan by the worker from the website's stored provider
    # secret. Values are NEVER logged.
    extra_http_headers: dict[str, str] = Field(default_factory=dict)
    rate_limit_rps: float = Field(
        default=2.0,
        gt=0.0,
        le=10.0,
        description="Requests per second — capped to prevent DoS-like load.",
    )
    include_subdomains: bool = Field(default=False)
    engines_enabled: list[str] = Field(
        default_factory=list,
        description="Explicit allowlist of engine names to run. Empty = run all.",
    )
    engines_disabled: list[str] = Field(default_factory=list)
    verify_tls: bool = Field(default=True)
    respect_robots_txt: bool = Field(default=True)
    # Phase-4 ASM opt-in. When True the orchestrator runs the asset-
    # discovery pass after the crawl: passive subdomain enumeration
    # (CT-log lookup via crt.sh) + common-prefix DNS probe. Default
    # off so QUICK/STANDARD/DEEP profiles stay unchanged.
    asm_enabled: bool = Field(default=False)
    # Phase-5A Playwright browser pass opt-in. When True the
    # orchestrator drives a headless Chromium against each crawled
    # page to capture fetch/XHR/WebSocket/EventSource/iframe traffic.
    # Default off; ENTERPRISE profile turns it on. Requires the
    # ``playwright`` package + ``playwright install chromium`` on
    # the worker box; missing dependencies degrade gracefully.
    browser_enabled: bool = Field(default=False)
    # Known-vulnerable JS library detection (CVE-by-CDN-URL). Cheap and
    # fully passive (URL parsing only, no fetch), but gated to the
    # thorough profiles so QUICK/STANDARD reports stay focused. Enabled
    # by the DEEP and ENTERPRISE profiles.
    vuln_libs_enabled: bool = Field(default=False)
    # Phase-10 authenticated scanning. ``auth_mode`` is one of
    # public_only / authenticated_only / combined / deep_authenticated
    # (see webhound.auth.AuthMode). Default public_only keeps every
    # existing scan unchanged. Authenticated modes require a loaded
    # session (cookies / storageState / recording) supplied via the
    # SessionContext / orchestrator — and a browser pass to use it.
    auth_mode: str = Field(default="public_only")


class Target(BaseModel):
    """The website being scanned — canonical URL, network context, and scan config."""

    id: UUID = Field(default_factory=uuid4)
    url: str = Field(description="Root URL of the target (scheme + host + optional path).")
    hostname: str = Field(description="Extracted hostname (no scheme, no port).")
    scheme: str = Field(description="'http' or 'https'.")
    port: int | None = Field(default=None, ge=1, le=65535)
    ip_address: str | None = Field(default=None)

    scope: TargetScope = Field(default=TargetScope.FULL_DOMAIN)
    scope_urls: list[str] = Field(
        default_factory=list,
        description="For URL_LIST scope: the explicit list of in-scope URLs.",
    )

    tls_info: TLSInfo | None = Field(default=None)
    technologies: list[str] = Field(
        default_factory=list,
        description="Detected technology fingerprints (e.g. 'WordPress 6.4', 'nginx').",
    )

    scan_options: ScanOptions = Field(default_factory=ScanOptions)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False, "populate_by_name": True}

    @field_validator("scheme")
    @classmethod
    def _normalise_scheme(cls, v: str) -> str:
        v = v.lower().rstrip("://")
        if v not in ("http", "https"):
            raise ValueError(f"Unsupported scheme '{v}'. Must be http or https.")
        return v

    @model_validator(mode="after")
    def _derive_defaults(self) -> "Target":
        """Derive hostname and scheme from URL when not explicitly provided."""
        if not self.hostname and self.url:
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            object.__setattr__(self, "hostname", parsed.hostname or "")
            if not self.scheme:
                object.__setattr__(self, "scheme", parsed.scheme or "https")
        return self

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def base_url(self) -> str:
        """Canonical base URL: scheme://hostname[:port]"""
        if self.port and self.port not in (80, 443):
            return f"{self.scheme}://{self.hostname}:{self.port}"
        return f"{self.scheme}://{self.hostname}"

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> "Target":
        """Quick constructor: derive hostname and scheme from URL automatically."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return cls(
            url=url,
            hostname=parsed.hostname or "",
            scheme=parsed.scheme or "https",
            port=parsed.port,
            **kwargs,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Target":
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, raw: str) -> "Target":
        return cls.model_validate_json(raw)
