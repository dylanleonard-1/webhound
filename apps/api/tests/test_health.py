from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from apps.api.main import app

client = TestClient(app)


def test_health_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_db_returns_ok_with_mocked_db():
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()

    async def override_get_db():
        yield mock_session

    from apps.api.database import get_db
    app.dependency_overrides[get_db] = override_get_db
    try:
        response = client.get("/health/db")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["database"] == "ok"
    finally:
        app.dependency_overrides.clear()


def test_health_db_returns_error_on_db_failure():
    from sqlalchemy.exc import OperationalError

    async def bad_db():
        mock = AsyncMock()
        mock.execute.side_effect = OperationalError("connection refused", None, None)
        yield mock

    from apps.api.database import get_db
    app.dependency_overrides[get_db] = bad_db
    try:
        response = client.get("/health/db")
        assert response.status_code == 200
        data = response.json()
        assert data["database"].startswith("error:")
    finally:
        app.dependency_overrides.clear()
