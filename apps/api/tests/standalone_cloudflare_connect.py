# Standalone (DB-free) verification of the Cloudflare connect orchestration audit
# trail — Phase 4.2 end-to-end wiring. The DB-backed pytest tests
# (test_cloudflare_integration.py) cover the persistence/encryption invariants but
# need a live Postgres + conftest fixtures; this script instead mocks the DB layer
# so it runs anywhere (no DB, no alembic) and proves the NEW audit events fire and
# that no secret ever reaches an audit event.
#
# Run:  PYTHONPATH=scanner .venv-api/Scripts/python.exe \
#         apps/api/tests/standalone_cloudflare_connect.py
from __future__ import annotations

import asyncio

from apps.api.services import cloudflare as cf

TOKEN = "cf-ACCESS-PLAINTEXT-tok-SECRET"
REFRESH = "cf-REFRESH-PLAINTEXT-tok-SECRET"
ACTIVE = [{"id": "z1", "name": "example.com", "status": "active",
           "account": {"id": "a1"}, "plan": {"name": "Pro"}}]
UNRELATED = [{"id": "zu", "name": "attacker.com", "status": "active", "account": {"id": "x"}}]


class _FakeConn:
    pass


class _FakeWebsite:
    id = "11111111-1111-1111-1111-111111111111"
    hostname = "www.example.com"
    user_id = "22222222-2222-2222-2222-222222222222"
    org_id = "33333333-3333-3333-3333-333333333333"


class _FakeDB:
    async def flush(self):
        return None


class _FakeSecret:
    id = "44444444-4444-4444-4444-444444444444"


def _install_mocks(zones):
    """Patch every DB/HTTP-touching dependency; capture emitted audit events."""
    events: list[tuple[str, str, str | None]] = []
    store_calls: list[str] = []

    async def fake_exchange(code):
        return {"access_token": TOKEN, "refresh_token": REFRESH,
                "scope": "zone:read"}

    async def fake_fetch(token):
        return zones

    async def fake_get_or_create(db, website, user_id, org_id):
        return _FakeConn()

    async def fake_store_secret(db, **kw):
        store_calls.append(kw.get("secret_type", ""))
        # The plaintext token must be passed here (this is the ONLY sink) but must
        # never leak into an audit event — asserted below.
        assert kw.get("plaintext") in (TOKEN, REFRESH)
        return _FakeSecret()

    def fake_audit(db, event, website, *, user_id, org_id, status, reason=None):
        events.append((event, status, reason))

    async def fake_mark_verified(db, website, *, provider, evidence, actor_user_id, org_id):
        return None

    async def fake_trusted(db, website, *, provider, evidence, user_id, org_id):
        return None

    cf._exchange_code = fake_exchange
    cf._fetch_zones = fake_fetch
    cf._get_or_create = fake_get_or_create
    cf.store_secret = fake_store_secret
    cf._audit = fake_audit
    cf.get_key_management = lambda: type("K", (), {"is_configured": True})()
    cf.verify_service.mark_verified_via_provider = fake_mark_verified
    cf.ta_service.start_provider_oauth_access = fake_trusted
    return events, store_calls


def _no_secret_in_events(events) -> bool:
    blob = " ".join(f"{e}|{s}|{r}" for e, s, r in events)
    return TOKEN not in blob and REFRESH not in blob


async def _run():
    failures = []

    # ── Success path: active owning zone -> token stored + full audit trail ──
    events, store_calls = _install_mocks(ACTIVE)
    res = await cf.complete_connection(
        _FakeDB(), website=_FakeWebsite(), code="auth-code",
        user_id="22222222-2222-2222-2222-222222222222",
        org_id="33333333-3333-3333-3333-333333333333")
    emitted = [e for e, _, _ in events]

    def check(cond, msg):
        if not cond:
            failures.append(msg)

    check(res.get("matched") is True, "success: expected matched=True")
    check(cf.CF_CALLBACK_RECEIVED in emitted, "success: cloudflare.oauth.callback.received not emitted")
    check(cf.CF_OAUTH_COMPLETED in emitted, "success: cloudflare.oauth.completed not emitted")
    check(cf.CF_TOKEN_STORED in emitted, "success: cloudflare.token.stored not emitted")
    check(cf.CF_ZONE_MATCHED in emitted, "success: cloudflare.zone.matched not emitted")
    check(cf.CF_CONNECTED in emitted, "success: cloudflare.connected not emitted")
    # token.stored must come AFTER the token is actually persisted.
    if cf.CF_TOKEN_STORED in emitted:
        check("oauth_access_token" in store_calls, "success: access token not stored via 4.1")
    check(_no_secret_in_events(events), "success: a secret leaked into an audit event")
    # callback.received is the FIRST event (records arrival before any exchange).
    check(emitted and emitted[0] == cf.CF_CALLBACK_RECEIVED,
          "success: callback.received should be the first audit event")

    # ── No-zone path: unrelated zone -> token discarded, NOT stored ──
    events2, store_calls2 = _install_mocks(UNRELATED)
    res2 = await cf.complete_connection(
        _FakeDB(), website=_FakeWebsite(), code="auth-code",
        user_id="22222222-2222-2222-2222-222222222222",
        org_id="33333333-3333-3333-3333-333333333333")
    emitted2 = [e for e, _, _ in events2]
    check(res2.get("matched") is False, "no_zone: expected matched=False")
    check(cf.CF_CALLBACK_RECEIVED in emitted2, "no_zone: callback.received not emitted")
    check(cf.CF_ZONE_NOT_FOUND in emitted2, "no_zone: cloudflare.zone.not_found not emitted")
    check(cf.CF_TOKEN_STORED not in emitted2, "no_zone: token.stored must NOT fire on no-match")
    check(store_calls2 == [], "no_zone: token must NOT be stored on no-match")
    check(_no_secret_in_events(events2), "no_zone: a secret leaked into an audit event")

    if failures:
        print("FAIL: Cloudflare connect standalone")
        for f in failures:
            print("  -", f)
        raise SystemExit(1)
    print("PASS: Cloudflare connect standalone — 14 checks "
          "(callback.received, oauth.completed, token.stored, zone.matched, "
          "connected; no-zone discards token; no secret in any audit event)")


if __name__ == "__main__":
    asyncio.run(_run())
