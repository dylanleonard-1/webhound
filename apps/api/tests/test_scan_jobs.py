"""Scan job API tests — lifecycle, state machine, filters."""
from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_website(client: AsyncClient, url: str = "https://example.com") -> dict:
    r = await client.post("/websites", json={"url": url})
    assert r.status_code == 201, r.text
    return r.json()


async def _create_job(
    client: AsyncClient,
    website_id: str,
    profile: str = "standard",
    **kwargs,
) -> dict:
    payload = {"website_id": website_id, "profile": profile, **kwargs}
    return await client.post("/scan-jobs", json=payload)


async def _transition(
    client: AsyncClient, job_id: str, status: str, error_message: str | None = None
) -> dict:
    body: dict = {"status": status}
    if error_message:
        body["error_message"] = error_message
    return await client.patch(f"/scan-jobs/{job_id}/status", json=body)


# ---------------------------------------------------------------------------
# POST /scan-jobs — success
# ---------------------------------------------------------------------------


async def test_create_scan_job_returns_201(client):
    w = await _create_website(client)
    r = await _create_job(client, w["id"])
    assert r.status_code == 201


async def test_create_scan_job_response_fields(client):
    w = await _create_website(client)
    r = await _create_job(client, w["id"], "deep")
    body = r.json()
    assert "id" in body
    assert body["website_id"] == w["id"]
    assert body["status"] == "queued"
    assert body["profile"] == "deep"
    assert body["requested_url"] == w["url"]
    assert body["use_latest_baseline"] is False
    assert body["save_baseline"] is True
    assert "created_at" in body
    assert "updated_at" in body
    assert body["started_at"] is None
    assert body["completed_at"] is None
    assert body["error_message"] is None


async def test_create_scan_job_default_profile_is_standard(client):
    w = await _create_website(client)
    r = await _create_job(client, w["id"])
    assert r.json()["profile"] == "standard"


async def test_create_scan_job_status_starts_queued(client):
    w = await _create_website(client)
    r = await _create_job(client, w["id"])
    assert r.json()["status"] == "queued"


async def test_create_scan_job_requested_url_copied_from_website(client):
    w = await _create_website(client, "https://copy-url.example.com")
    r = await _create_job(client, w["id"])
    assert r.json()["requested_url"] == w["url"]


async def test_create_scan_job_custom_baseline_flags(client):
    w = await _create_website(client)
    r = await _create_job(
        client, w["id"], use_latest_baseline=True, save_baseline=False
    )
    body = r.json()
    assert body["use_latest_baseline"] is True
    assert body["save_baseline"] is False


async def test_create_scan_job_all_valid_profiles(client):
    for profile in ("quick", "standard", "deep", "monitor"):
        w = await _create_website(client, f"https://{profile}.example.com")
        r = await _create_job(client, w["id"], profile)
        assert r.status_code == 201
        assert r.json()["profile"] == profile


# ---------------------------------------------------------------------------
# POST /scan-jobs — validation failures
# ---------------------------------------------------------------------------


async def test_create_scan_job_missing_website_returns_404(client):
    r = await _create_job(client, str(uuid.uuid4()))
    assert r.status_code == 404


async def test_create_scan_job_invalid_profile_rejected(client):
    w = await _create_website(client)
    r = await client.post(
        "/scan-jobs", json={"website_id": w["id"], "profile": "turbo"}
    )
    assert r.status_code == 422


async def test_create_scan_job_invalid_uuid_rejected(client):
    r = await client.post(
        "/scan-jobs", json={"website_id": "not-a-uuid", "profile": "standard"}
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# GET /scan-jobs — list
# ---------------------------------------------------------------------------


async def test_list_scan_jobs_empty(client):
    r = await client.get("/scan-jobs")
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == []
    assert body["total"] == 0
    assert body["limit"] == 20
    assert body["offset"] == 0


async def test_list_scan_jobs_returns_created(client):
    w = await _create_website(client)
    await _create_job(client, w["id"])
    r = await client.get("/scan-jobs")
    assert r.json()["total"] == 1


async def test_list_scan_jobs_multiple(client):
    w = await _create_website(client)
    await _create_job(client, w["id"])
    await _create_job(client, w["id"])
    r = await client.get("/scan-jobs")
    assert r.json()["total"] == 2


async def test_list_scan_jobs_filter_by_website_id(client):
    w1 = await _create_website(client, "https://site1.example.com")
    w2 = await _create_website(client, "https://site2.example.com")
    await _create_job(client, w1["id"])
    await _create_job(client, w2["id"])
    r = await client.get(f"/scan-jobs?website_id={w1['id']}")
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["website_id"] == w1["id"]


async def test_list_scan_jobs_filter_by_status(client):
    w = await _create_website(client)
    r1 = await _create_job(client, w["id"])
    r2 = await _create_job(client, w["id"])
    # Transition first job to running
    await _transition(client, r1.json()["id"], "running")

    r = await client.get("/scan-jobs?status=queued")
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["id"] == r2.json()["id"]


async def test_list_scan_jobs_filter_by_profile(client):
    w = await _create_website(client)
    await _create_job(client, w["id"], "quick")
    await _create_job(client, w["id"], "deep")
    r = await client.get("/scan-jobs?profile=quick")
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["profile"] == "quick"


async def test_list_scan_jobs_pagination(client):
    w = await _create_website(client)
    for _ in range(5):
        await _create_job(client, w["id"])
    r = await client.get("/scan-jobs?limit=2&offset=1")
    body = r.json()
    assert len(body["items"]) == 2
    assert body["total"] == 5


async def test_list_scan_jobs_ordered_newest_first(client):
    w = await _create_website(client)
    r1 = (await _create_job(client, w["id"])).json()
    r2 = (await _create_job(client, w["id"])).json()
    listed = (await client.get("/scan-jobs")).json()["items"]
    # Newest (r2) should appear before r1
    ids = [item["id"] for item in listed]
    assert ids.index(r2["id"]) <= ids.index(r1["id"])


# ---------------------------------------------------------------------------
# GET /scan-jobs/{id}
# ---------------------------------------------------------------------------


async def test_get_scan_job_success(client):
    w = await _create_website(client)
    created = (await _create_job(client, w["id"])).json()
    r = await client.get(f"/scan-jobs/{created['id']}")
    assert r.status_code == 200
    assert r.json()["id"] == created["id"]


async def test_get_scan_job_not_found(client):
    r = await client.get("/scan-jobs/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


async def test_get_scan_job_invalid_uuid(client):
    r = await client.get("/scan-jobs/not-a-uuid")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# PATCH /scan-jobs/{id}/cancel
# ---------------------------------------------------------------------------


async def test_cancel_queued_job_succeeds(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    r = await client.patch(f"/scan-jobs/{job['id']}/cancel")
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"


async def test_cancel_queued_job_sets_completed_at(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    r = await client.patch(f"/scan-jobs/{job['id']}/cancel")
    assert r.json()["completed_at"] is not None


async def test_cancel_running_job_succeeds(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    await _transition(client, job["id"], "running")
    r = await client.patch(f"/scan-jobs/{job['id']}/cancel")
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"


async def test_cancel_completed_job_rejected(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    await _transition(client, job["id"], "running")
    await _transition(client, job["id"], "completed")
    r = await client.patch(f"/scan-jobs/{job['id']}/cancel")
    assert r.status_code == 409


async def test_cancel_failed_job_rejected(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    await _transition(client, job["id"], "running")
    await _transition(client, job["id"], "failed", error_message="oops")
    r = await client.patch(f"/scan-jobs/{job['id']}/cancel")
    assert r.status_code == 409


async def test_cancel_already_cancelled_rejected(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    await client.patch(f"/scan-jobs/{job['id']}/cancel")
    r = await client.patch(f"/scan-jobs/{job['id']}/cancel")
    assert r.status_code == 409


async def test_cancel_nonexistent_job(client):
    r = await client.patch("/scan-jobs/00000000-0000-0000-0000-000000000000/cancel")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# PATCH /scan-jobs/{id}/status — transitions
# ---------------------------------------------------------------------------


async def test_status_transition_queued_to_running(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    r = await _transition(client, job["id"], "running")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "running"
    assert body["started_at"] is not None
    assert body["completed_at"] is None


async def test_status_transition_running_to_completed(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    await _transition(client, job["id"], "running")
    r = await _transition(client, job["id"], "completed")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "completed"
    assert body["completed_at"] is not None


async def test_status_transition_running_to_failed_with_message(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    await _transition(client, job["id"], "running")
    r = await _transition(client, job["id"], "failed", error_message="scan crashed")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "failed"
    assert body["error_message"] == "scan crashed"
    assert body["completed_at"] is not None


async def test_status_transition_queued_to_completed_invalid(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    r = await _transition(client, job["id"], "completed")
    assert r.status_code == 409


async def test_status_transition_completed_is_terminal(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    await _transition(client, job["id"], "running")
    await _transition(client, job["id"], "completed")
    r = await _transition(client, job["id"], "running")
    assert r.status_code == 409


async def test_status_transition_failed_is_terminal(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    await _transition(client, job["id"], "running")
    await _transition(client, job["id"], "failed")
    r = await _transition(client, job["id"], "running")
    assert r.status_code == 409


async def test_status_update_not_found(client):
    r = await _transition(
        client, "00000000-0000-0000-0000-000000000000", "running"
    )
    assert r.status_code == 404


async def test_status_update_invalid_status_value(client):
    w = await _create_website(client)
    job = (await _create_job(client, w["id"])).json()
    r = await client.patch(
        f"/scan-jobs/{job['id']}/status", json={"status": "flying"}
    )
    assert r.status_code == 422
