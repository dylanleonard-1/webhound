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
