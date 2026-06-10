"""Phase 3.10 trigger — creating a website kicks off onboarding automation.

Guards the gap that left production stuck (the orchestrator existed but nothing
invoked it). Asserts the create endpoint schedules run_automation_for_website
for the new website. The automation itself is covered by its own standalone +
the manual prod validation.
"""
from __future__ import annotations

import pytest

from apps.api.routers import websites as websites_router

pytestmark = pytest.mark.anyio


async def test_create_website_triggers_onboarding_automation(client, monkeypatch):
    captured: list[tuple[str, dict]] = []

    async def _capture(website_id, **kw):
        captured.append((str(website_id), kw))

    monkeypatch.setattr(websites_router, "run_automation_for_website", _capture)
    r = await client.post("/websites", json={"url": "https://trigger-test.example"})
    assert r.status_code == 201, r.text
    wid = r.json()["id"]
    # The TestClient runs BackgroundTasks; the trigger fired for THIS website.
    assert len(captured) == 1
    assert captured[0][0] == wid
    assert "user_id" in captured[0][1] and "org_id" in captured[0][1]
