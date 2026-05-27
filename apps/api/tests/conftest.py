from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import apps.api.models  # noqa: F401
from apps.api.config import Settings, get_settings
from apps.api.database import Base, get_db
from apps.api.main import app
from apps.api.models.enums import PlanTier
from apps.api.models.user import User
from apps.api.security import get_current_user, hash_password


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session", autouse=True)
def _disable_app_rate_limit():
    """The shared app captures rate_limit_enabled=True at import, but the suite
    fires far more than 100 req/min from the test client's fixed host, so the
    in-memory limiter trips across tests. Disable it on the shared app only —
    the dedicated hardening tests build their own apps to exercise the limiter.
    """
    from apps.api.middleware import RateLimitMiddleware

    for mw in app.user_middleware:
        if mw.cls is RateLimitMiddleware:
            mw.kwargs["enabled"] = False
    app.middleware_stack = app.build_middleware_stack()
    yield


@pytest.fixture(autouse=True)
def _dev_settings():
    """Allow unverified scans in test environment — domain verification is not available in tests."""
    test_settings = Settings(dev_allow_unverified_scans=True)
    with patch("apps.api.services.scan_jobs.get_settings", return_value=test_settings):
        yield


@pytest.fixture(autouse=True)
def _mock_celery_task():
    """Prevent real Celery broker connections in all API tests."""
    mock_result = MagicMock()
    mock_result.id = "test-celery-task-id"
    with patch("apps.api.routers.scan_jobs.run_scan") as mock_task:
        mock_task.delay.return_value = mock_result
        yield mock_task


@pytest.fixture
async def db_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def _test_user(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        # Generous plan so resource-creation tests (websites, scan jobs,
        # deep-profile scans) aren't blocked by free-tier quotas. No test
        # asserts free-tier limits; quota enforcement is covered separately.
        user = User(
            email="test@example.com",
            hashed_password=hash_password("testpassword123"),
            is_active=True,
            plan=PlanTier.ENTERPRISE,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    return user


@pytest.fixture
async def client(db_engine, _test_user):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def _override_get_db():
        async with factory() as session:
            yield session

    async def _override_get_current_user():
        return _test_user

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    app.dependency_overrides.clear()
