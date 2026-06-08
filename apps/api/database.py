from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from apps.api.config import get_settings


class Base(DeclarativeBase):
    pass


def _make_engine():
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
    )


# --- Lazy engine / session factory -----------------------------------------
# The engine + sessionmaker are built on FIRST USE rather than at import time.
# SQLAlchemy's create_async_engine does not open a connection, so importing
# this module was already non-blocking — but lazy construction keeps `import
# apps.api.database` (and therefore `apps.api.models`) a pure, side-effect-free
# operation, which is what makes the pure-logic unit tests safe to run under
# `pytest --noconftest`.
#
# KNOWN ISSUE (test reliability): the *application* import path
# (`apps.api.main:app`, the FastAPI lifespan, and any route/integration test
# that pulls it in) opens blocking resources — DB pool checkout, Redis,
# Sentry. Those suites can hang in a sandbox with no Postgres/Redis. Mitigation
# in place: tests that only need pure logic or a private in-memory SQLite engine
# run with `--noconftest -p no:cacheprovider`, and the api conftest backs the
# rate-limit primitives with fakeredis. TODO: make the app lifespan tolerate a
# missing DB/Redis at import so the full suite is hermetic.
_engine = None
_session_factory = None


def _get_engine():
    global _engine
    if _engine is None:
        _engine = _make_engine()
    return _engine


def _get_session_local():
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(_get_engine(), expire_on_commit=False)
    return _session_factory


def __getattr__(name: str):
    # PEP 562 — keep `from apps.api.database import engine / AsyncSessionLocal`
    # working while deferring construction until the attribute is touched.
    if name == "engine":
        return _get_engine()
    if name == "AsyncSessionLocal":
        return _get_session_local()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with _get_session_local()() as session:
        yield session


def get_session_factory():
    """Module-level async sessionmaker for callers outside the request scope
    (the global exception handler, background coroutines from middleware,
    etc.). Returns the same factory `get_db()` uses, so connections are
    routed through the same pool."""
    return _get_session_local()
