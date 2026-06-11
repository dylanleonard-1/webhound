from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Annotated

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_INSECURE_KEYS = {
    "dev-secret-key-change-in-production",
    "change-me-in-production",
}

# The shipped default DATABASE_URL. If production is still pointed at this
# localhost value, the database was never configured — fail fast rather than
# silently trying to reach a non-existent local Postgres.
_DEFAULT_DATABASE_URL = "postgresql+asyncpg://webhound:webhound@localhost:5432/webhound"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Database
    database_url: str = _DEFAULT_DATABASE_URL

    @field_validator("database_url", mode="before")
    @classmethod
    def normalize_db_url(cls, v: object) -> object:
        if isinstance(v, str) and v.startswith("postgresql://"):
            return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Auth
    secret_key: str = "dev-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24  # 24 hours

    # Phase-4.1 encryption-at-rest for provider secrets (Fernet, versioned).
    # Format: "<version>:<fernet-key>,<version>:<fernet-key>" e.g. "1:abc...,2:def..."
    # Generate: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # PROD MUST set this — without it SecretStorageService refuses to store (fail
    # closed). Dev falls back to an EPHEMERAL key (secrets won't survive restart).
    # NEVER evict a key version until every secret on it has been re-encrypted.
    encryption_keys: str = ""
    encryption_active_version: str = ""

    # CORS — override with CORS_ORIGINS env var as JSON array for staging/prod
    # e.g. CORS_ORIGINS='["https://webhoundsecurity.com","https://app.webhoundsecurity.com"]'
    # NoDecode: pydantic-settings would otherwise JSON-decode this list field
    # from the env source before parse_cors_origins runs, crashing on a
    # comma-separated CORS_ORIGINS. Let the before-validator own all parsing
    # (same pattern as admin_emails below).
    cors_origins: Annotated[list[str], NoDecode] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
    ]
    cors_allow_credentials: bool = True

    # Origin regex — matches every Vercel preview deploy for the
    # webhoundsecurity project plus the production webhound.vercel.app
    # subdomain. Override with CORS_ORIGIN_REGEX env var if the project
    # name or Vercel team changes.
    cors_origin_regex: str = (
        r"^https://webhound(-[a-z0-9-]+-webhoundsecurity)?\.vercel\.app$"
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: object) -> list[str]:
        _defaults = ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3001"]
        if isinstance(v, list):
            return v or _defaults
        if not isinstance(v, str) or not v.strip():
            return _defaults
        try:
            parsed = json.loads(v)
            return parsed if isinstance(parsed, list) else _defaults
        except json.JSONDecodeError:
            parts = [s.strip() for s in v.split(",") if s.strip()]
            return parts or _defaults

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 100

    # App
    app_env: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    # Observability — Sentry error monitoring. Empty DSN disables it entirely
    # (so local dev and unconfigured environments are no-ops).
    sentry_dsn: str = ""
    sentry_traces_sample_rate: float = 0.0  # 0 = errors only; raise for perf tracing

    # Worker
    worker_concurrency: int = 2

    # OAuth providers — set via env vars; empty string = provider disabled
    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    # Phase-4.2 Cloudflare provider integration (read-only scopes only; we do NOT
    # request firewall/WAF write access in this foundation). Empty = disabled.
    cloudflare_client_id: str = ""
    cloudflare_client_secret: str = ""
    # Cloudflare OAuth scopes (space-separated). NOTE: Cloudflare's self-managed
    # OAuth clients use DOT notation (e.g. "zone.read"), NOT colon — a colon is
    # rejected as invalid_scope. Env-configurable so the exact identifier can be
    # tuned from Railway without a redeploy. Account id is read from the zone
    # payload, so no account scope is requested.
    cloudflare_oauth_scopes: str = "zone.read"
    # Scanner-access (elevated) OAuth scopes — a SEPARATE re-consent phase from the
    # read-only connect above, requested only when the customer opts into automated
    # scanner allowlisting. Least-privilege: zone read + firewall/WAF write to create
    # the scanner skip rule, plus read-only security telemetry. IDs are the exact
    # dot-notation identifiers from Cloudflare's OAuth scope catalog (/oauth/scopes).
    # NOTE: Cloudflare's catalog has no dedicated zone "Rulesets"/"Rate Limiting"/
    # "Security Events" OAuth scopes — those zone capabilities are umbrella'd under
    # `firewall-services.*` (rules/rate-limit) and `analytics.read` (security events).
    # Space-separated, env-configurable (CLOUDFLARE_SCANNER_OAUTH_SCOPES) so a single
    # ID can be tuned from Railway without a redeploy. Does NOT request DNS/Workers/
    # Billing/Account-edit/Email/admin scopes.
    cloudflare_scanner_oauth_scopes: str = (
        "zone.read "
        "firewall-services.read firewall-services.write "
        "zone-waf.read zone-waf.write "
        "zone-security-center-insights.read "
        "page-shield.read "
        "trust-and-safety.read "
        "analytics.read"
    )
    # Phase-4.3 Vercel provider integration (read-only integration; empty = disabled).
    vercel_client_id: str = ""
    vercel_client_secret: str = ""
    # Public-facing URLs (used in OAuth redirect_uri and post-auth redirects)
    # Production: api_base_url=https://api.webhoundsecurity.com  frontend_url=https://webhoundsecurity.com
    api_base_url: str = "http://localhost:8000"
    frontend_url: str = "http://localhost:3000"

    # Twilio SMS — leave blank in dev to log OTP codes to console
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_from_number: str = ""  # E.164 format, e.g. +15551234567

    # Email / SMTP — leave blank in dev to log verification links to console
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = "noreply@webhoundsecurity.com"
    smtp_from_name: str = "WebHound"

    # Resend (preferred over raw SMTP for production)
    # Sign up at resend.com, add webhoundsecurity.com domain, get API key
    resend_api_key: str = ""
    resend_from_email: str = "auth@webhoundsecurity.com"
    resend_from_name: str = "WebHound"

    # Stripe billing — keys live in env, never in repo
    stripe_secret_key: str = ""              # sk_live_… / sk_test_…
    stripe_publishable_key: str = ""         # pk_live_… / pk_test_… (frontend reads via NEXT_PUBLIC env)
    stripe_webhook_secret: str = ""          # whsec_…, used to verify webhook signatures

    # Dev overrides — must never be set true in production
    dev_allow_unverified_scans: bool = False
    dev_skip_domain_verification: bool = False

    # --- AI summaries (opt-in) -------------------------------------------
    # WEBHOUND_AI_ENABLED=1 switches the summariser from deterministic
    # templates to the live Claude path, which REQUIRES ANTHROPIC_API_KEY.
    # ai_summary.py still reads these via os.getenv at call time; the fields
    # exist so startup validation can fail fast on a half-configured prod.
    webhound_ai_enabled: bool = False
    anthropic_api_key: str = ""

    # --- Admin bypass flags (DANGEROUS) ----------------------------------
    # See apps/api/internal/admin_bypass.py + docs/env.md. Default off, only
    # honoured for verified admins, refused in production unless
    # admin_bypass_allow_in_prod is also set, and every use is audit-logged.
    admin_verify_bypass: bool = False
    admin_quota_bypass: bool = False
    admin_bypass_allow_in_prod: bool = False

    # --- Notifications (outbound alert delivery) -------------------------
    # Master switch. When false, alerts are still recorded in-app but no
    # email/webhook is sent (and the UI must not claim otherwise).
    notifications_enabled: bool = False

    # SMTP failover — used when Resend fails AND this is enabled (see FIX 11).
    smtp_fallback_enabled: bool = False
    smtp_use_tls: bool = True

    # Emails auto-promoted to is_admin on signup, OAuth, and startup backfill.
    # Override with ADMIN_EMAILS env var as JSON array or comma-separated list.
    admin_emails: Annotated[list[str], NoDecode] = ["dmleonard5125@gmail.com"]

    @field_validator("admin_emails", mode="before")
    @classmethod
    def parse_admin_emails(cls, v: object) -> list[str]:
        if isinstance(v, list):
            return [str(e).strip().lower() for e in v if str(e).strip()]
        if not isinstance(v, str) or not v.strip():
            return []
        try:
            parsed = json.loads(v)
            if isinstance(parsed, list):
                return [str(e).strip().lower() for e in parsed if str(e).strip()]
        except json.JSONDecodeError:
            pass
        return [s.strip().lower() for s in v.split(",") if s.strip()]

    @field_validator("app_env")
    @classmethod
    def validate_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"app_env must be one of {allowed}")
        return v

    @field_validator("cors_origin_regex")
    @classmethod
    def validate_cors_origin_regex(cls, v: str) -> str:
        """A malformed CORS_ORIGIN_REGEX would crash request handling at
        runtime (or silently match nothing). Catch it at startup instead."""
        if v:
            try:
                re.compile(v)
            except re.error as exc:
                raise ValueError(f"CORS_ORIGIN_REGEX is not a valid regex: {exc}")
        return v

    @model_validator(mode="after")
    def _validate_production_security(self) -> "Settings":
        # Checks that apply in EVERY environment.
        if self.webhound_ai_enabled and not self.anthropic_api_key:
            raise ValueError(
                "WEBHOUND_AI_ENABLED=1 requires ANTHROPIC_API_KEY to be set — "
                "otherwise the AI summariser silently falls back to templates."
            )
        if self.notifications_enabled and not self._has_email_provider():
            raise ValueError(
                "NOTIFICATIONS_ENABLED=1 requires an email provider: set "
                "RESEND_API_KEY, or SMTP_FALLBACK_ENABLED=1 with SMTP_HOST."
            )
        if self.smtp_fallback_enabled and not self.smtp_host:
            raise ValueError(
                "SMTP_FALLBACK_ENABLED=1 requires SMTP_HOST to be set."
            )

        if self.app_env == "production":
            if self.secret_key in _INSECURE_KEYS:
                raise ValueError(
                    "SECRET_KEY must be changed from the default in production. "
                    "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
                )
            if self.database_url == _DEFAULT_DATABASE_URL:
                raise ValueError(
                    "DATABASE_URL is still the localhost default in production — "
                    "it was never configured."
                )
            if not self.database_url.startswith("postgresql"):
                raise ValueError(
                    "DATABASE_URL must be a postgresql:// URL in production "
                    f"(got scheme of {self.database_url.split('://', 1)[0]!r})."
                )
            if not self.redis_url.startswith(("redis://", "rediss://")):
                raise ValueError(
                    "REDIS_URL must be a redis:// or rediss:// URL in production."
                )
            for name, value in (("API_BASE_URL", self.api_base_url),
                                ("FRONTEND_URL", self.frontend_url)):
                if not value.startswith(("http://", "https://")):
                    raise ValueError(f"{name} must be an absolute http(s) URL in production.")
            if self.dev_allow_unverified_scans:
                raise ValueError(
                    "DEV_ALLOW_UNVERIFIED_SCANS must not be set in production."
                )
            if self.dev_skip_domain_verification:
                raise ValueError(
                    "DEV_SKIP_DOMAIN_VERIFICATION must not be set in production — "
                    "it lets any domain be marked verified, enabling SSRF."
                )
            # Admin bypass flags are security controls. Refuse to boot with one
            # enabled in production unless the operator has explicitly opted in
            # via ADMIN_BYPASS_ALLOW_IN_PROD — a deliberate two-key gesture.
            if (self.admin_verify_bypass or self.admin_quota_bypass) and not self.admin_bypass_allow_in_prod:
                raise ValueError(
                    "ADMIN_VERIFY_BYPASS / ADMIN_QUOTA_BYPASS are enabled in "
                    "production without ADMIN_BYPASS_ALLOW_IN_PROD=1. These skip "
                    "domain verification / quota enforcement; refusing to start."
                )
            # Billing must be fully configured in production. A startup failure
            # here is safe: the new deploy fails its healthcheck and Railway
            # keeps the previous (working) container serving.
            import os as _os
            missing = [
                name for name, present in (
                    ("STRIPE_SECRET_KEY", bool(self.stripe_secret_key)),
                    ("STRIPE_WEBHOOK_SECRET", bool(self.stripe_webhook_secret)),
                    ("STRIPE_PRICE_PRO_MONTHLY", bool(_os.getenv("STRIPE_PRICE_PRO_MONTHLY"))),
                    ("STRIPE_PRICE_SHIELD_MONTHLY", bool(_os.getenv("STRIPE_PRICE_SHIELD_MONTHLY"))),
                    ("STRIPE_PRICE_ENTERPRISE_MONTHLY", bool(_os.getenv("STRIPE_PRICE_ENTERPRISE_MONTHLY"))),
                ) if not present
            ]
            if missing:
                raise ValueError(
                    "Production is missing required Stripe env vars: "
                    + ", ".join(missing)
                )
        else:
            # Non-production: never block startup, but surface misconfigurations
            # that would silently disable a feature the operator clearly wanted.
            import logging as _logging
            _log = _logging.getLogger("apps.api.config")
            if self.admin_verify_bypass or self.admin_quota_bypass:
                _log.warning(
                    "ADMIN bypass flag enabled (verify=%s quota=%s) — admins can "
                    "skip security controls. Never do this in production.",
                    self.admin_verify_bypass, self.admin_quota_bypass,
                )
            if self.secret_key in _INSECURE_KEYS:
                _log.warning("SECRET_KEY is the insecure default — fine for dev, "
                             "must be changed before production.")
        return self

    def _has_email_provider(self) -> bool:
        return bool(self.resend_api_key) or (self.smtp_fallback_enabled and bool(self.smtp_host))


@lru_cache
def get_settings() -> Settings:
    return Settings()
