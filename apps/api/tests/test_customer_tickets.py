"""Customer support ticket endpoint — maps to the existing SupportTicket system,
carries safe context only (no tokens). Run with --noconftest -p no:cacheprovider."""
from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from apps.api.routers import tickets as t

pytestmark = pytest.mark.anyio


class _FakeDB:
    def __init__(self):
        self.committed = False
    async def commit(self):
        self.committed = True


def _patch_create(monkeypatch, captured):
    async def _fake_create(db, *, user, subject, description, category, priority,
                           source_scan_id, author_email):
        captured.update(subject=subject, description=description, category=category,
                        priority=priority, source_scan_id=source_scan_id,
                        author_email=author_email)
        return SimpleNamespace(id="tid", number="WH-42", status="open")
    monkeypatch.setattr(t.support, "create_ticket", _fake_create)


async def test_scan_blocked_ticket_maps_to_question_with_safe_context(monkeypatch):
    captured: dict = {}
    _patch_create(monkeypatch, captured)
    db = _FakeDB()
    user = SimpleNamespace(id=uuid.uuid4(), email="cust@example.com")
    wid, sid = uuid.uuid4(), uuid.uuid4()
    payload = t.CustomerTicketRequest(
        subject="my scan was blocked", description="page 1 only", kind="scan_blocked",
        website_id=wid, scan_id=sid, blocker="vercel")

    res = await t.create_customer_ticket(payload, db, user)

    assert res == {"id": "tid", "number": "WH-42", "status": "open"}
    assert db.committed is True
    # Mapped to a VALID support category; kind preserved in the subject.
    assert captured["category"] == "question"
    assert "scan_blocked" in captured["subject"]
    # Safe context in the body (ids + blocker), and NO secrets/tokens.
    assert "vercel" in captured["description"]
    assert str(sid) in captured["description"]
    assert captured["source_scan_id"] == sid
    for bad in ("token", "secret", "bearer", "cfoc_", "password", "authorization"):
        assert bad not in captured["description"].lower()


async def test_unknown_kind_defaults_to_onboarding_help(monkeypatch):
    captured: dict = {}
    _patch_create(monkeypatch, captured)
    user = SimpleNamespace(id=uuid.uuid4(), email="c@x.com")
    payload = t.CustomerTicketRequest(subject="", kind="nonsense")
    await t.create_customer_ticket(payload, _FakeDB(), user)
    assert "onboarding_help" in captured["subject"]
    assert captured["category"] == "question"
