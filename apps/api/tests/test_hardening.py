"""API hardening and consistency tests — error format, pagination, CORS, headers, rate limit."""
from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.database import get_db

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Fixture: unauthenticated client (no auth override)
# ---------------------------------------------------------------------------


@pytest.fixture
async def anon_client(db_engine):
    from apps.api.main import app

    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def _override():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Standard error format
# ---------------------------------------------------------------------------


async def test_404_error_format(client):
    r = await client.get(f"/websites/{uuid.uuid4()}")
    assert r.status_code == 404
    body = r.json()
    assert "error" in body
    assert body["error"]["code"] == "not_found"
    assert isinstance(body["error"]["message"], str)
    assert isinstance(body["error"]["details"], dict)


async def test_422_validation_error_format(client):
    r = await client.post("/websites", json={"url": "ftp://badscheme.example.com"})
    assert r.status_code == 422
    body = r.json()
    assert body["error"]["code"] == "validation_error"
    assert body["error"]["message"] == "Validation failed."
    assert "errors" in body["error"]["details"]
    assert isinstance(body["error"]["details"]["errors"], list)
    assert len(body["error"]["details"]["errors"]) > 0


async def test_401_error_format(anon_client):
    r = await anon_client.get("/websites")
    assert r.status_code == 401
    body = r.json()
    assert body["error"]["code"] == "unauthorized"
    assert isinstance(body["error"]["message"], str)


async def test_409_error_format(anon_client):
    await anon_client.post(
        "/auth/register", json={"email": "dup409@example.com", "password": "password123"}
    )
    r = await anon_client.post(
        "/auth/register", json={"email": "dup409@example.com", "password": "password123"}
    )
    assert r.status_code == 409
    body = r.json()
    assert body["error"]["code"] == "conflict"


async def test_error_shape_has_all_keys(client):
    r = await client.get(f"/scan-jobs/{uuid.uuid4()}")
    assert r.status_code == 404
    body = r.json()
    assert set(body["error"].keys()) == {"code", "message", "details"}


# ---------------------------------------------------------------------------
# Pagination — has_more / next_offset
# ---------------------------------------------------------------------------


async def test_pagination_has_more_false_when_empty(client):
    r = await client.get("/websites?limit=20&offset=0")
    assert r.status_code == 200
    body = r.json()
    assert body["has_more"] is False
    assert body["next_offset"] is None


async def test_pagination_has_more_true(client):
    for i in range(3):
        await client.post("/websites", json={"url": f"https://page-{i}.example.com"})
    r = await client.get("/websites?limit=2&offset=0")
    body = r.json()
    assert body["has_more"] is True
    assert body["next_offset"] == 2


async def test_pagination_has_more_false_at_end(client):
    for i in range(3):
        await client.post("/websites", json={"url": f"https://end-{i}.example.com"})
    r = await client.get("/websites?limit=10&offset=0")
    body = r.json()
    assert body["has_more"] is False
    assert body["next_offset"] is None


async def test_pagination_next_offset_advances(client):
    for i in range(5):
        await client.post("/websites", json={"url": f"https://adv-{i}.example.com"})
    r = await client.get("/websites?limit=2&offset=2")
    body = r.json()
    # total=5, limit=2, offset=2 → has_more (5 > 4), next_offset=4
    assert body["has_more"] is True
    assert body["next_offset"] == 4


async def test_pagination_fields_present_on_scan_jobs(client):
    r = await client.get("/scan-jobs?limit=10&offset=0")
    assert r.status_code == 200
    body = r.json()
    assert "has_more" in body
    assert "next_offset" in body


async def test_pagination_fields_present_on_notifications(client):
    r = await client.get("/notifications?limit=10&offset=0")
    assert r.status_code == 200
    body = r.json()
    assert "has_more" in body
    assert "next_offset" in body


async def test_pagination_fields_present_on_schedules(client):
    r = await client.get("/scan-schedules?limit=10&offset=0")
    assert r.status_code == 200
    body = r.json()
    assert "has_more" in body
    assert "next_offset" in body


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


async def test_security_headers_on_api_response(client):
    r = await client.get("/health")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert r.headers.get("referrer-policy") == "no-referrer"


async def test_cache_control_no_store_on_api_routes(client):
    r = await client.get("/websites")
    assert r.headers.get("cache-control") == "no-store"


async def test_no_cache_control_on_health(client):
    r = await client.get("/health")
    assert r.headers.get("cache-control") != "no-store"


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


async def test_cors_allowed_origin_returns_header(anon_client):
    r = await anon_client.get(
        "/health", headers={"Origin": "http://localhost:3000"}
    )
    assert r.headers.get("access-control-allow-origin") == "http://localhost:3000"


async def test_cors_disallowed_origin_no_header(anon_client):
    r = await anon_client.get(
        "/health", headers={"Origin": "http://evil.example.com"}
    )
    assert "access-control-allow-origin" not in r.headers


async def test_cors_preflight(anon_client):
    r = await anon_client.options(
        "/websites",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )
    assert r.status_code in (200, 204)
    assert r.headers.get("access-control-allow-origin") == "http://localhost:3000"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


async def test_rate_limit_disabled_by_default(client):
    for _ in range(10):
        r = await client.get("/health")
    assert r.status_code == 200


async def test_rate_limit_returns_429_when_enabled():
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    from apps.api.middleware import RateLimitMiddleware

    async def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    test_app = Starlette(routes=[Route("/", homepage)])
    test_app.add_middleware(
        RateLimitMiddleware, requests_per_minute=2, enabled=True
    )

    async with AsyncClient(
        transport=ASGITransport(app=test_app), base_url="http://test"
    ) as c:
        r1 = await c.get("/")
        r2 = await c.get("/")
        r3 = await c.get("/")

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    body = r3.json()
    assert body["error"]["code"] == "rate_limit_exceeded"
    assert r3.headers.get("retry-after") == "60"


async def test_rate_limit_disabled_passes_through():
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    from apps.api.middleware import RateLimitMiddleware

    async def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    test_app = Starlette(routes=[Route("/", homepage)])
    test_app.add_middleware(
        RateLimitMiddleware, requests_per_minute=1, enabled=False
    )

    async with AsyncClient(
        transport=ASGITransport(app=test_app), base_url="http://test"
    ) as c:
        for _ in range(5):
            r = await c.get("/")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# OpenAPI metadata
# ---------------------------------------------------------------------------


async def test_openapi_title(anon_client):
    r = await anon_client.get("/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    assert spec["info"]["title"] == "WebHound API"


async def test_openapi_has_description(anon_client):
    r = await anon_client.get("/openapi.json")
    spec = r.json()
    assert "description" in spec["info"]
    assert len(spec["info"]["description"]) > 0


async def test_openapi_has_version(anon_client):
    r = await anon_client.get("/openapi.json")
    spec = r.json()
    assert "version" in spec["info"]
