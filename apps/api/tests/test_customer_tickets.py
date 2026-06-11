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
    notified: dict = {}
    async def _fake_notify(*, ticket_number, subject, body_text):
        notified.update(number=ticket_number, subject=subject, body=body_text)
        return "resend"
    monkeypatch.setattr(t.email_service, "send_staff_ticket_notification", _fake_notify)
    db = _FakeDB()
    user = SimpleNamespace(id=uuid.uuid4(), email="cust@example.com")
    wid, sid = uuid.uuid4(), uuid.uuid4()
    payload = t.CustomerTicketRequest(
        subject="my scan was blocked", description="page 1 only", kind="scan_blocked",
        website_id=wid, scan_id=sid, blocker="vercel", diagnosis="both",
        evidence=["vercel: challenge endpoint '.well-known/vercel/security'",
                  "blocking HTTP status: [403]"])

    res = await t.create_customer_ticket(payload, db, user)

    assert res == {"id": "tid", "number": "WH-42", "status": "open"}
    assert db.committed is True
    assert captured["category"] == "question"
    assert "scan_blocked" in captured["subject"]
    body = captured["description"]
    # Enriched: ids + diagnosis + evidence + logs reference.
    assert str(wid) in body and str(sid) in body
    assert "vercel" in body and "provider diagnosis: both" in body
    assert "blocker evidence:" in body and "challenge endpoint" in body
    assert "logs reference: scan" in body
    assert captured["source_scan_id"] == sid
    # Staff was notified with the same safe body.
    assert notified["number"] == "WH-42"
    # NO secrets/tokens anywhere in the ticket body or the staff email body.
    for blob in (body, notified["body"]):
        for bad in ("token", "secret", "bearer", "cfoc_", "password", "authorization"):
            assert bad not in blob.lower()


async def test_staff_notification_gated_by_flag_and_provider(monkeypatch):
    from apps.api.services import email as em
    base = dict(admin_emails=["staff@webhound.com"], frontend_url="https://x",
                resend_from_email="f@x", resend_from_name="W")
    # disabled -> no send
    monkeypatch.setattr(em, "get_settings",
                        lambda: SimpleNamespace(notifications_enabled=False, resend_api_key="k",
                                                smtp_host="", **base))
    assert await em.send_staff_ticket_notification(ticket_number="WH-1", subject="s", body_text="b") is None
    # enabled but NO provider configured -> no send
    monkeypatch.setattr(em, "get_settings",
                        lambda: SimpleNamespace(notifications_enabled=True, resend_api_key="",
                                                smtp_host="", **base))
    assert await em.send_staff_ticket_notification(ticket_number="WH-1", subject="s", body_text="b") is None


async def test_unknown_kind_defaults_to_onboarding_help(monkeypatch):
    captured: dict = {}
    _patch_create(monkeypatch, captured)
    user = SimpleNamespace(id=uuid.uuid4(), email="c@x.com")
    payload = t.CustomerTicketRequest(subject="", kind="nonsense")
    await t.create_customer_ticket(payload, _FakeDB(), user)
    assert "onboarding_help" in captured["subject"]
    assert captured["category"] == "question"
