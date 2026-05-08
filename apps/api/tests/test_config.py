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


def test_settings_production_env():
    from apps.api.config import Settings
    s = Settings(
        _env_file=None,
        database_url="postgresql+asyncpg://u:p@db/prod",
        redis_url="redis://localhost:6379/0",
        app_env="production",
    )
    assert s.app_env == "production"
