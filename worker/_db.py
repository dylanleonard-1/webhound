from __future__ import annotations

import os

_DEFAULT_DB_URL = "postgresql+asyncpg://webhound:webhound@localhost:5432/webhound"


def normalize_async_db_url(url: str) -> str:
    # Railway / Heroku-style DATABASE_URL is `postgresql://...`. SQLAlchemy's
    # async engine needs the asyncpg driver: `postgresql+asyncpg://...`.
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


def get_async_db_url() -> str:
    return normalize_async_db_url(os.getenv("DATABASE_URL", _DEFAULT_DB_URL))
