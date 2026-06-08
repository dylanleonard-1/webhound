from __future__ import annotations

import pytest


def test_settings_defaults():
    from apps.api.config import Settings
    s = Settings(
        _env_file=None,
        database_url="postgresql+asyncpg://u:p@db/test",
        redis_url="redis://localhost:6379/0",
    )
    assert s.app_env == "development"
    assert s.debug is False


def test_settings_invalid_app_env():
    from apps.api.config import Settings
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            database_url="postgresql+asyncpg://u:p@db/test",
            redis_url="redis://localhost:6379/0",
            app_env="invalid_env",
        )


def _prod_stripe_env(monkeypatch):
    """Production requires Stripe price IDs (read from env via plans.py)."""
    for tier in ("PRO", "SHIELD", "ENTERPRISE"):
        monkeypatch.setenv(f"STRIPE_PRICE_{tier}_MONTHLY", "price_test")


def test_settings_production_env(monkeypatch):
    _prod_stripe_env(monkeypatch)
    from apps.api.config import Settings
    s = Settings(
        _env_file=None,
        database_url="postgresql+asyncpg://u:p@db/prod",
        redis_url="redis://localhost:6379/0",
        app_env="production",
        secret_key="a" * 64,  # valid non-default key
        stripe_secret_key="sk_live_x",
        stripe_webhook_secret="whsec_x",
    )
    assert s.app_env == "production"


def test_settings_production_requires_stripe(monkeypatch):
    from apps.api.config import Settings
    from pydantic import ValidationError
    for tier in ("PRO", "SHIELD", "ENTERPRISE"):
        monkeypatch.delenv(f"STRIPE_PRICE_{tier}_MONTHLY", raising=False)
    with pytest.raises(ValidationError, match="Stripe env vars"):
        Settings(
            _env_file=None,
            database_url="postgresql+asyncpg://u:p@db/prod",
            redis_url="redis://localhost:6379/0",
            app_env="production",
            secret_key="a" * 64,  # valid key, but Stripe missing
        )


def test_settings_production_rejects_default_secret():
    from apps.api.config import Settings
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="SECRET_KEY must be changed"):
        Settings(
            _env_file=None,
            database_url="postgresql+asyncpg://u:p@db/prod",
            redis_url="redis://localhost:6379/0",
            app_env="production",
            secret_key="dev-secret-key-change-in-production",
        )


def test_settings_production_rejects_dev_scan_bypass():
    from apps.api.config import Settings
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="DEV_ALLOW_UNVERIFIED_SCANS"):
        Settings(
            _env_file=None,
            database_url="postgresql+asyncpg://u:p@db/prod",
            redis_url="redis://localhost:6379/0",
            app_env="production",
            secret_key="a" * 64,
            dev_allow_unverified_scans=True,
        )


# ---------------------------------------------------------------------------
# FIX 2 — startup validation
# ---------------------------------------------------------------------------

def test_settings_production_rejects_default_database_url(monkeypatch):
    """Leaving DATABASE_URL at the shipped localhost default in production means
    it was never configured — fail fast."""
    _prod_stripe_env(monkeypatch)
    from apps.api.config import Settings, _DEFAULT_DATABASE_URL
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="DATABASE_URL is still the localhost default"):
        Settings(
            _env_file=None,
            database_url=_DEFAULT_DATABASE_URL,
            redis_url="redis://localhost:6379/0",
            app_env="production",
            secret_key="a" * 64,
            stripe_secret_key="sk_live_x",
            stripe_webhook_secret="whsec_x",
        )


def test_settings_production_rejects_bad_redis_url(monkeypatch):
    _prod_stripe_env(monkeypatch)
    from apps.api.config import Settings
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="REDIS_URL"):
        Settings(
            _env_file=None,
            database_url="postgresql+asyncpg://u:p@db/prod",
            redis_url="memcached://nope",
            app_env="production",
            secret_key="a" * 64,
            stripe_secret_key="sk_live_x",
            stripe_webhook_secret="whsec_x",
        )


def test_settings_ai_enabled_requires_key():
    """WEBHOUND_AI_ENABLED=1 without ANTHROPIC_API_KEY fails in any env."""
    from apps.api.config import Settings
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="ANTHROPIC_API_KEY"):
        Settings(
            _env_file=None,
            database_url="postgresql+asyncpg://u:p@db/test",
            redis_url="redis://localhost:6379/0",
            webhound_ai_enabled=True,
        )


def test_settings_ai_enabled_with_key_ok():
    from apps.api.config import Settings
    s = Settings(
        _env_file=None,
        database_url="postgresql+asyncpg://u:p@db/test",
        redis_url="redis://localhost:6379/0",
        webhound_ai_enabled=True,
        anthropic_api_key="sk-ant-xxx",
    )
    assert s.webhound_ai_enabled is True


def test_settings_bad_cors_regex_fails():
    from apps.api.config import Settings
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="CORS_ORIGIN_REGEX"):
        Settings(
            _env_file=None,
            database_url="postgresql+asyncpg://u:p@db/test",
            redis_url="redis://localhost:6379/0",
            cors_origin_regex="^https://(unclosed",
        )


def test_settings_notifications_enabled_requires_provider():
    from apps.api.config import Settings
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="NOTIFICATIONS_ENABLED"):
        Settings(
            _env_file=None,
            database_url="postgresql+asyncpg://u:p@db/test",
            redis_url="redis://localhost:6379/0",
            notifications_enabled=True,
        )


def test_settings_notifications_enabled_with_resend_ok():
    from apps.api.config import Settings
    s = Settings(
        _env_file=None,
        database_url="postgresql+asyncpg://u:p@db/test",
        redis_url="redis://localhost:6379/0",
        notifications_enabled=True,
        resend_api_key="re_xxx",
    )
    assert s.notifications_enabled is True


def test_settings_missing_optional_vars_warns_only():
    """Dev with nothing optional configured must NOT raise."""
    from apps.api.config import Settings
    s = Settings(
        _env_file=None,
        database_url="postgresql+asyncpg://u:p@db/test",
        redis_url="redis://localhost:6379/0",
        app_env="development",
    )
    assert s.app_env == "development"


# ---------------------------------------------------------------------------
# FIX 3 — admin bypass prod gate
# ---------------------------------------------------------------------------

def test_settings_production_refuses_bypass_without_override(monkeypatch):
    _prod_stripe_env(monkeypatch)
    from apps.api.config import Settings
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="ADMIN_BYPASS_ALLOW_IN_PROD"):
        Settings(
            _env_file=None,
            database_url="postgresql+asyncpg://u:p@db/prod",
            redis_url="redis://localhost:6379/0",
            app_env="production",
            secret_key="a" * 64,
            stripe_secret_key="sk_live_x",
            stripe_webhook_secret="whsec_x",
            admin_quota_bypass=True,
        )


def test_settings_production_allows_bypass_with_override(monkeypatch):
    _prod_stripe_env(monkeypatch)
    from apps.api.config import Settings
    s = Settings(
        _env_file=None,
        database_url="postgresql+asyncpg://u:p@db/prod",
        redis_url="redis://localhost:6379/0",
        app_env="production",
        secret_key="a" * 64,
        stripe_secret_key="sk_live_x",
        stripe_webhook_secret="whsec_x",
        admin_verify_bypass=True,
        admin_bypass_allow_in_prod=True,
    )
    assert s.admin_verify_bypass is True
