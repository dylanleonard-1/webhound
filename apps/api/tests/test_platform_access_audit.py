"""Phase-2 Platform Access — audit events: catalog + emission + no secrets.
Run with --noconftest -p no:cacheprovider.
"""
from __future__ import annotations

import apps.api.services.platform_access as pa
import apps.api.services.provider_oauth as provider_oauth


def test_audit_catalog_complete():
    assert pa.PA_PROVIDER_DETECTED in pa.AUDIT_EVENTS
    assert pa.PA_ACCESS_REQUIRED in pa.AUDIT_EVENTS
    assert pa.PA_VERIFICATION_SUCCESS in pa.AUDIT_EVENTS
    assert pa.PA_VERIFICATION_FAILED in pa.AUDIT_EVENTS
    assert pa.PA_TICKET_CREATED in pa.AUDIT_EVENTS
    assert pa.PA_VERCEL_INSTRUCTIONS_SHOWN in pa.AUDIT_EVENTS
    # All namespaced consistently.
    assert all(e.startswith("platform.") for e in pa.AUDIT_EVENTS)


def _capture(monkeypatch):
    calls = []

    def _fake(db, event, website, *, provider, user_id, org_id, status, reason=None):
        calls.append({"event": event, "provider": provider, "status": status,
                      "reason": reason})

    monkeypatch.setattr(provider_oauth, "audit_event", _fake)
    return calls


def test_pa_audit_passes_through(monkeypatch):
    calls = _capture(monkeypatch)
    pa.pa_audit(None, pa.PA_TICKET_CREATED, object(), user_id="u", org_id="o",
                status="created", reason="vercel", provider="vercel")
    assert calls == [{"event": "platform.ticket.created", "provider": "vercel",
                      "status": "created", "reason": "vercel"}]


def test_record_access_events_emits_detected_required_and_verification(monkeypatch):
    calls = _capture(monkeypatch)
    view = {"provider": "cloudflare", "access_required": True, "verification": "failed"}
    emitted = pa.record_access_events(None, object(), view, user_id="u", org_id="o")
    events = [c["event"] for c in calls]
    assert pa.PA_PROVIDER_DETECTED in events
    assert pa.PA_ACCESS_REQUIRED in events
    assert pa.PA_VERIFICATION_FAILED in events
    assert set(emitted) == set(events)


def test_record_access_events_success_path(monkeypatch):
    calls = _capture(monkeypatch)
    view = {"provider": "cloudflare", "access_required": False, "verification": "success"}
    pa.record_access_events(None, object(), view, user_id="u", org_id="o")
    events = [c["event"] for c in calls]
    assert pa.PA_VERIFICATION_SUCCESS in events
    assert pa.PA_ACCESS_REQUIRED not in events


def test_audit_reason_carries_only_provider_name_never_secret(monkeypatch):
    calls = _capture(monkeypatch)
    pa.pa_audit(None, pa.PA_PROVIDER_DETECTED, object(), user_id="u", org_id="o",
                status="detected", reason="cloudflare", provider="cloudflare")
    blob = str(calls).lower()
    for forbidden in ("token", "secret", "bearer", "password", "authorization"):
        assert forbidden not in blob
