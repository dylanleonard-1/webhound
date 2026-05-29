# WebHound — apps/api/tests/test_active_org_context.py
# Phase-4 slice B: active-org context resolution + orgs router.

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# /orgs — list, create, active echo
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_orgs_list_empty_for_new_user(client) -> None:
    resp = await client.get("/orgs")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"items": [], "total": 0}


@pytest.mark.asyncio
async def test_orgs_create_makes_caller_owner(client) -> None:
    resp = await client.post(
        "/orgs",
        json={"name": "Acme", "slug": "acme",
              "billing_email": "b@acme.test"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["slug"] == "acme"
    assert body["role"] == "owner"
    # And appears in the list.
    listed = (await client.get("/orgs")).json()
    assert listed["total"] == 1
    assert listed["items"][0]["slug"] == "acme"


@pytest.mark.asyncio
async def test_orgs_create_rejects_duplicate_slug(client) -> None:
    await client.post("/orgs",
                       json={"name": "A", "slug": "dup"})
    resp = await client.post("/orgs",
                              json={"name": "B", "slug": "dup"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_active_org_endpoint_no_header_returns_none(client) -> None:
    resp = await client.get("/orgs/active")
    assert resp.status_code == 200
    assert resp.json() == {"active_org_id": None}


@pytest.mark.asyncio
async def test_active_org_endpoint_with_membership_echoes_id(client) -> None:
    created = (await client.post(
        "/orgs", json={"name": "X", "slug": "x"},
    )).json()
    resp = await client.get(
        "/orgs/active",
        headers={"X-Org-Id": created["id"]},
    )
    assert resp.status_code == 200
    assert resp.json()["active_org_id"] == created["id"]


@pytest.mark.asyncio
async def test_active_org_rejects_non_member(client) -> None:
    """A header pointing at an org the caller has no membership in is
    a 403 — never a silent fall-through to None (would leak rows)."""
    bogus = str(uuid.uuid4())
    resp = await client.get(
        "/orgs/active",
        headers={"X-Org-Id": bogus},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_active_org_rejects_malformed_header(client) -> None:
    resp = await client.get(
        "/orgs/active",
        headers={"X-Org-Id": "not-a-uuid"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Scoped list endpoints honour the active-org context end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_websites_list_with_active_org_excludes_other_orgs(
    client,
) -> None:
    # Create two orgs owned by the same caller.
    org_a = (await client.post(
        "/orgs", json={"name": "A", "slug": "a"},
    )).json()
    org_b = (await client.post(
        "/orgs", json={"name": "B", "slug": "b"},
    )).json()
    # Create a website per org — we have to use the model directly here
    # since the website-create router doesn't yet write org_id from
    # X-Org-Id. (That's a follow-up; this test pins the FILTER side.)
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from apps.api.models.user import User
    import sqlalchemy as sa
    from apps.api.models.website import Website
    from apps.api.models.enums import VerificationStatus

    # Pull the test user via the same factory the client uses.
    db = client.cookies   # not actually used; we need the engine
    # Hacky: reach into the dep override to get the session factory.
    from apps.api.main import app
    from apps.api.database import get_db
    factory_override = app.dependency_overrides[get_db]
    async for session in factory_override():
        # Find the test user
        u = await session.scalar(sa.select(User).limit(1))
        for slug, org in (("a-target.test", org_a),
                           ("b-target.test", org_b)):
            session.add(Website(
                user_id=u.id, url=f"https://{slug}/",
                hostname=slug, scheme="https",
                verification_status=VerificationStatus.VERIFIED,
                org_id=uuid.UUID(org["id"]),
            ))
        await session.commit()
        break

    # No header → both visible (legacy semantics)
    resp = await client.get("/websites?limit=10")
    body = resp.json()
    hostnames = {w["hostname"] for w in body["items"]}
    assert "a-target.test" in hostnames
    assert "b-target.test" in hostnames

    # X-Org-Id = org A → only org A's site (+ any legacy NULL sites)
    resp = await client.get(
        "/websites?limit=10",
        headers={"X-Org-Id": org_a["id"]},
    )
    hostnames = {w["hostname"] for w in resp.json()["items"]}
    assert "a-target.test" in hostnames
    assert "b-target.test" not in hostnames


@pytest.mark.asyncio
async def test_scan_jobs_list_with_active_org_filters(client) -> None:
    """End-to-end: the scan_jobs list endpoint honours X-Org-Id."""
    org_a = (await client.post(
        "/orgs", json={"name": "A", "slug": "scja"},
    )).json()
    org_b = (await client.post(
        "/orgs", json={"name": "B", "slug": "scjb"},
    )).json()

    from sqlalchemy.ext.asyncio import async_sessionmaker
    from apps.api.main import app
    from apps.api.database import get_db
    from apps.api.models.user import User
    from apps.api.models.website import Website
    from apps.api.models.scan_job import ScanJob
    from apps.api.models.enums import VerificationStatus, ScanStatus
    import sqlalchemy as sa

    factory_override = app.dependency_overrides[get_db]
    async for session in factory_override():
        u = await session.scalar(sa.select(User).limit(1))
        for slug, org in (("ja.test", org_a), ("jb.test", org_b)):
            w = Website(
                user_id=u.id, url=f"https://{slug}/",
                hostname=slug, scheme="https",
                verification_status=VerificationStatus.VERIFIED,
                org_id=uuid.UUID(org["id"]),
            )
            session.add(w)
            await session.flush()
            session.add(ScanJob(
                website_id=w.id, status=ScanStatus.COMPLETED,
                requested_url=f"https://{slug}/",
                org_id=uuid.UUID(org["id"]),
            ))
        await session.commit()
        break

    # Scoped to org A
    resp = await client.get(
        "/scan-jobs?limit=20",
        headers={"X-Org-Id": org_a["id"]},
    )
    items = resp.json()["items"]
    urls = {it["requested_url"] for it in items}
    assert "https://ja.test/" in urls
    assert "https://jb.test/" not in urls
