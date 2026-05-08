from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import apps.api.models  # noqa: F401
from apps.api.database import Base, get_db
from apps.api.main import app
from apps.api.models.user import User
from apps.api.security import get_current_user, hash_password


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


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
        user = User(
            email="test@example.com",
            hashed_password=hash_password("testpassword123"),
            is_active=True,
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
