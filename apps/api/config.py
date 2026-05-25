from __future__ import annotations

import json
from functools import lru_cache
from typing import Annotated

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_INSECURE_KEYS = {
    "dev-secret-key-change-in-production",
    "change-me-in-production",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Database
    database_url: str = "postgresql+asyncpg://webhound:webhound@localhost:5432/webhound"

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

    # Worker
    worker_concurrency: int = 2

    # OAuth providers — set via env vars; empty string = provider disabled
    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
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

    @model_validator(mode="after")
    def _validate_production_security(self) -> "Settings":
        if self.app_env == "production":
            if self.secret_key in _INSECURE_KEYS:
                raise ValueError(
                    "SECRET_KEY must be changed from the default in production. "
                    "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
                )
            if self.dev_allow_unverified_scans:
                raise ValueError(
                    "DEV_ALLOW_UNVERIFIED_SCANS must not be set in production."
                )
            if self.dev_skip_domain_verification:
                raise ValueError(
                    "DEV_SKIP_DOMAIN_VERIFICATION must not be set in production — "
                    "it lets any domain be marked verified, enabling SSRF."
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
