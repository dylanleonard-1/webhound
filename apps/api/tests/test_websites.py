"""Website/domain management API tests."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create(client: AsyncClient, url: str, display_name: str | None = None):
    payload: dict = {"url": url}
    if display_name is not None:
        payload["display_name"] = display_name
    return await client.post("/websites", json=payload)


# ---------------------------------------------------------------------------
# POST /websites — success
# ---------------------------------------------------------------------------


async def test_create_website_returns_201(client):
    r = await _create(client, "https://example.com")
    assert r.status_code == 201


async def test_create_website_response_fields(client):
    r = await _create(client, "https://example.com", display_name="My Site")
    body = r.json()
    assert "id" in body
    assert body["url"] == "https://example.com/"
    assert body["hostname"] == "example.com"
    assert body["scheme"] == "https"
    assert body["display_name"] == "My Site"
    assert body["verification_status"] == "unverified"
    assert "created_at" in body
    assert "updated_at" in body


async def test_create_website_normalizes_url(client):
    r = await _create(client, "HTTP://EXAMPLE.COM/path")
    assert r.status_code == 201
    body = r.json()
    assert body["scheme"] == "http"
    assert body["hostname"] == "example.com"


async def test_create_website_adds_trailing_slash_to_root(client):
    r = await _create(client, "https://example.com")
    body = r.json()
    assert body["url"].endswith("/")


async def test_create_website_without_display_name(client):
    r = await _create(client, "https://example.org")
    assert r.status_code == 201
    assert r.json()["display_name"] is None


# ---------------------------------------------------------------------------
# POST /websites — validation failures
# ---------------------------------------------------------------------------


async def test_create_website_empty_url_rejected(client):
    r = await client.post("/websites", json={"url": ""})
    assert r.status_code == 422


async def test_create_website_invalid_url_rejected(client):
    r = await _create(client, "not-a-url-at-all!!!")
    assert r.status_code in (422, 422)


async def test_create_website_ftp_scheme_rejected(client):
    r = await _create(client, "ftp://files.example.com/pub")
    assert r.status_code == 422


async def test_create_website_file_scheme_rejected(client):
    r = await _create(client, "file:///etc/passwd")
    assert r.status_code == 422


async def test_create_website_javascript_scheme_rejected(client):
    r = await _create(client, "javascript:alert(1)")
    assert r.status_code == 422


async def test_create_website_data_scheme_rejected(client):
    r = await _create(client, "data:text/html,<h1>hi</h1>")
    assert r.status_code == 422


async def test_create_website_localhost_rejected(client):
    r = await _create(client, "http://localhost/admin")
    assert r.status_code == 422
    detail_str = str(r.json()["error"]["details"]).lower()
    assert "localhost" in detail_str


async def test_create_website_loopback_ip_rejected(client):
    r = await _create(client, "http://127.0.0.1/login")
    assert r.status_code == 422


async def test_create_website_private_ip_rejected(client):
    r = await _create(client, "http://192.168.1.1/router")
    assert r.status_code == 422


async def test_create_website_class_a_private_ip_rejected(client):
    r = await _create(client, "http://10.0.0.1/internal")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# POST /websites — duplicate prevention
# ---------------------------------------------------------------------------


async def test_create_website_duplicate_rejected(client):
    await _create(client, "https://example.com")
    r = await _create(client, "https://example.com")
    assert r.status_code == 409


async def test_create_website_different_paths_not_duplicate(client):
    r1 = await _create(client, "https://example.com/")
    r2 = await _create(client, "https://example.com/blog")
    assert r2.status_code == 201
    assert r1.json()["id"] != r2.json()["id"]


# ---------------------------------------------------------------------------
# GET /websites — list
# ---------------------------------------------------------------------------


async def test_list_websites_empty(client):
    r = await client.get("/websites")
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == []
    assert body["total"] == 0
    assert body["limit"] == 20
    assert body["offset"] == 0


async def test_list_websites_returns_created(client):
    await _create(client, "https://example.com")
    r = await client.get("/websites")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["hostname"] == "example.com"


async def test_list_websites_multiple(client):
    await _create(client, "https://alpha.example.com")
    await _create(client, "https://beta.example.com")
    r = await client.get("/websites")
    assert r.json()["total"] == 2


async def test_list_websites_pagination_limit(client):
    for i in range(5):
        await _create(client, f"https://site{i}.example.com")
    r = await client.get("/websites?limit=2")
    body = r.json()
    assert len(body["items"]) == 2
    assert body["total"] == 5
    assert body["limit"] == 2


async def test_list_websites_pagination_offset(client):
    for i in range(4):
        await _create(client, f"https://page{i}.example.com")
    r = await client.get("/websites?limit=2&offset=2")
    body = r.json()
    assert len(body["items"]) == 2
    assert body["total"] == 4


async def test_list_websites_filter_by_verification_status(client):
    await _create(client, "https://unverified.example.com")
    r = await client.get("/websites?verification_status=unverified")
    body = r.json()
    assert body["total"] >= 1
    for item in body["items"]:
        assert item["verification_status"] == "unverified"


async def test_list_websites_filter_verified_returns_empty(client):
    await _create(client, "https://example.com")
    r = await client.get("/websites?verification_status=verified")
    assert r.json()["total"] == 0


async def test_list_websites_hostname_filter(client):
    await _create(client, "https://shop.example.com")
    await _create(client, "https://blog.other.org")
    r = await client.get("/websites?hostname=example.com")
    body = r.json()
    assert all("example.com" in item["hostname"] for item in body["items"])


# ---------------------------------------------------------------------------
# GET /websites/{id}
# ---------------------------------------------------------------------------


async def test_get_website_success(client):
    created = (await _create(client, "https://detail.example.com")).json()
    r = await client.get(f"/websites/{created['id']}")
    assert r.status_code == 200
    assert r.json()["id"] == created["id"]
    assert r.json()["url"] == created["url"]


async def test_get_website_not_found(client):
    r = await client.get("/websites/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


async def test_get_website_invalid_uuid(client):
    r = await client.get("/websites/not-a-uuid")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# PATCH /websites/{id}
# ---------------------------------------------------------------------------


async def test_patch_display_name(client):
    created = (await _create(client, "https://patch.example.com")).json()
    r = await client.patch(
        f"/websites/{created['id']}", json={"display_name": "Patched Name"}
    )
    assert r.status_code == 200
    assert r.json()["display_name"] == "Patched Name"


async def test_patch_clears_display_name(client):
    created = (
        await _create(client, "https://clearname.example.com", display_name="Old")
    ).json()
    r = await client.patch(
        f"/websites/{created['id']}", json={"display_name": None}
    )
    assert r.status_code == 200
    assert r.json()["display_name"] is None


async def test_patch_verification_status(client):
    created = (await _create(client, "https://verify.example.com")).json()
    r = await client.patch(
        f"/websites/{created['id']}", json={"verification_status": "verified"}
    )
    assert r.status_code == 200
    assert r.json()["verification_status"] == "verified"


async def test_patch_website_not_found(client):
    r = await client.patch(
        "/websites/00000000-0000-0000-0000-000000000000",
        json={"display_name": "X"},
    )
    assert r.status_code == 404


async def test_patch_preserves_other_fields(client):
    created = (await _create(client, "https://preserve.example.com")).json()
    r = await client.patch(
        f"/websites/{created['id']}", json={"display_name": "New Name"}
    )
    body = r.json()
    assert body["url"] == created["url"]
    assert body["hostname"] == created["hostname"]


# ---------------------------------------------------------------------------
# DELETE /websites/{id}
# ---------------------------------------------------------------------------


async def test_delete_website_success(client):
    created = (await _create(client, "https://delete.example.com")).json()
    r = await client.delete(f"/websites/{created['id']}")
    assert r.status_code == 204


async def test_delete_website_no_longer_gettable(client):
    created = (await _create(client, "https://gone.example.com")).json()
    await client.delete(f"/websites/{created['id']}")
    r = await client.get(f"/websites/{created['id']}")
    assert r.status_code == 404


async def test_delete_website_not_found(client):
    r = await client.delete("/websites/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


async def test_delete_website_removed_from_list(client):
    created = (await _create(client, "https://listed.example.com")).json()
    await client.delete(f"/websites/{created['id']}")
    r = await client.get("/websites")
    ids = [item["id"] for item in r.json()["items"]]
    assert created["id"] not in ids
