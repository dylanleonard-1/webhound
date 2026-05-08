"""Auth API tests — register, login, me, ownership enforcement."""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.database import get_db
from apps.api.main import app

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# client fixture with NO auth override — tests real JWT flow
# ---------------------------------------------------------------------------


@pytest.fixture
async def client(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def _override_get_db():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _register(client: AsyncClient, email: str = "user@example.com", password: str = "password123") -> dict:
    r = await client.post("/auth/register", json={"email": email, "password": password})
    return r


async def _login(client: AsyncClient, email: str = "user@example.com", password: str = "password123") -> dict:
    r = await client.post("/auth/login", json={"email": email, "password": password})
    return r


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------


async def test_register_returns_201(client):
    r = await _register(client)
    assert r.status_code == 201


async def test_register_response_fields(client):
    r = await _register(client)
    body = r.json()
    assert "id" in body
    assert body["email"] == "user@example.com"
    assert body["is_active"] is True
    assert "created_at" in body
    assert "password" not in body
    assert "hashed_password" not in body


async def test_register_normalises_email(client):
    r = await _register(client, email="  User@EXAMPLE.COM  ")
    assert r.json()["email"] == "user@example.com"


async def test_register_duplicate_email_rejected(client):
    await _register(client)
    r = await _register(client)
    assert r.status_code == 409


async def test_register_short_password_rejected(client):
    r = await client.post("/auth/register", json={"email": "a@b.com", "password": "short"})
    assert r.status_code == 422


async def test_register_missing_email_rejected(client):
    r = await client.post("/auth/register", json={"password": "password123"})
    assert r.status_code == 422


async def test_register_missing_password_rejected(client):
    r = await client.post("/auth/register", json={"email": "a@b.com"})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------


async def test_login_returns_token(client):
    await _register(client)
    r = await _login(client)
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"
    assert len(body["access_token"]) > 10


async def test_login_wrong_password_rejected(client):
    await _register(client)
    r = await _login(client, password="wrongpassword")
    assert r.status_code == 401


async def test_login_unknown_email_rejected(client):
    r = await _login(client, email="nobody@example.com")
    assert r.status_code == 401


async def test_login_normalises_email(client):
    await _register(client, email="user@example.com")
    r = await _login(client, email="  USER@EXAMPLE.COM  ")
    assert r.status_code == 200
    assert "access_token" in r.json()


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------


async def test_me_returns_user(client):
    await _register(client)
    token = (await _login(client)).json()["access_token"]
    r = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "user@example.com"
    assert body["is_active"] is True


async def test_me_no_token_returns_401(client):
    r = await client.get("/auth/me")
    assert r.status_code == 401


async def test_me_invalid_token_returns_401(client):
    r = await client.get("/auth/me", headers={"Authorization": "Bearer notavalidtoken"})
    assert r.status_code == 401


async def test_me_malformed_bearer_returns_401(client):
    r = await client.get("/auth/me", headers={"Authorization": "Token sometoken"})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Protected routes require authentication
# ---------------------------------------------------------------------------


async def test_get_websites_without_auth_returns_401(client):
    r = await client.get("/websites")
    assert r.status_code == 401


async def test_create_website_without_auth_returns_401(client):
    r = await client.post("/websites", json={"url": "https://example.com"})
    assert r.status_code == 401


async def test_list_scan_jobs_without_auth_returns_401(client):
    r = await client.get("/scan-jobs")
    assert r.status_code == 401


async def test_list_scan_results_without_auth_returns_401(client):
    r = await client.get("/scan-results")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Ownership — users cannot see each other's resources
# ---------------------------------------------------------------------------


async def test_users_only_see_own_websites(client):
    await _register(client, email="alice@example.com", password="password123")
    await _register(client, email="bob@example.com", password="password123")

    alice_token = (await _login(client, email="alice@example.com")).json()["access_token"]
    bob_token = (await _login(client, email="bob@example.com")).json()["access_token"]

    # Alice creates a website
    r = await client.post(
        "/websites",
        json={"url": "https://alice-site.com"},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r.status_code == 201

    # Bob sees 0 websites
    r = await client.get("/websites", headers={"Authorization": f"Bearer {bob_token}"})
    assert r.json()["total"] == 0

    # Alice sees 1 website
    r = await client.get("/websites", headers={"Authorization": f"Bearer {alice_token}"})
    assert r.json()["total"] == 1


async def test_user_cannot_get_others_website(client):
    await _register(client, email="alice@example.com", password="password123")
    await _register(client, email="bob@example.com", password="password123")

    alice_token = (await _login(client, email="alice@example.com")).json()["access_token"]
    bob_token = (await _login(client, email="bob@example.com")).json()["access_token"]

    r = await client.post(
        "/websites",
        json={"url": "https://alice-only.com"},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    website_id = r.json()["id"]

    r = await client.get(
        f"/websites/{website_id}",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert r.status_code == 404


async def test_user_cannot_delete_others_website(client):
    await _register(client, email="alice@example.com", password="password123")
    await _register(client, email="bob@example.com", password="password123")

    alice_token = (await _login(client, email="alice@example.com")).json()["access_token"]
    bob_token = (await _login(client, email="bob@example.com")).json()["access_token"]

    r = await client.post(
        "/websites",
        json={"url": "https://delete-test.com"},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    website_id = r.json()["id"]

    r = await client.delete(
        f"/websites/{website_id}",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert r.status_code == 404
