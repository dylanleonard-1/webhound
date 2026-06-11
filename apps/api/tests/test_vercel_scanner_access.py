"""Phase 4.3 scanner-access — Vercel orchestration (DB via in-memory SQLite, Vercel
HTTP mocked). Honest states: active / pending_permissions / blocked_non_bypassable /
failed; disconnect reverses; never a token in logs/audit; never fakes active.
"""
from __future__ import annotations

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.models.admin_audit_log import AdminAuditLog
from apps.api.models.enums import (
    PlanTier,
    ProviderConnectionStatus,
    TrustedAccessStatus,
    VerificationStatus,
)
from apps.api.models.provider_connection import ProviderConnection
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.services import trusted_access as ta_service
from apps.api.services import vercel_rules as v_rules
from apps.api.services import vercel_scanner_access as vsa

pytestmark = pytest.mark.anyio

TOKEN = "v-FIREWALL-PLAINTEXT-tok"


@pytest.fixture
async def db_session(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as s:
        yield s


async def _connected_site(db, email, host):
    u = User(email=email, hashed_password="x", is_active=True, plan=PlanTier.ENTERPRISE)
    db.add(u)
    await db.flush()
    w = Website(user_id=u.id, org_id=u.id, url=f"https://{host}", hostname=host,
                scheme="https", verification_status=VerificationStatus.VERIFIED)
    db.add(w)
    await db.flush()
    conn = ProviderConnection(
        website_id=w.id, org_id=u.id, user_id=u.id, provider="vercel",
        account_id="team_x", zone_id="prj_x", zone_name=host,
        connection_status=ProviderConnectionStatus.CONNECTED.value, connection_metadata={})
    db.add(conn)
    await db.flush()
    await ta_service.start_provider_oauth_access(db, w, provider="vercel", user_id=u.id, org_id=u.id)
    return u, w, conn


def _ens(**over):
    async def ensure(tok, pid, tid=None):
        return {"created": [v_rules.REF], "updated": [], "existing": [],
                "firewall_provisioned": True, "attack_mode": over.get("attack_mode", False)}
    return ensure


def _ver(verified=True, attack_mode=False):
    async def verify(tok, pid, tid=None):
        return {"bypass": verified, "verified": verified, "attack_mode": attack_mode}
    return verify


async def _audit_text(db):
    rows = await db.scalars(sa.select(AdminAuditLog))
    return " ".join(repr(x.detail) for x in rows)


async def test_apply_active_promotes_trusted_access(db_session, monkeypatch):
    u, w, conn = await _connected_site(db_session, "vsa1@x.com", "example.com")
    monkeypatch.setattr(v_rules, "ensure_bypass_rule", _ens())
    monkeypatch.setattr(v_rules, "verify_bypass_rule", _ver(verified=True))
    res = await vsa.apply_scanner_bypass(
        db_session, website=w, access_token=TOKEN, project_id="prj_x", team_id="team_x",
        user_id=u.id, org_id=u.id)
    assert res["applied"] and res["status"] == "active"
    ta = await ta_service.get_trusted_access(db_session, w)
    assert ta.access_status == TrustedAccessStatus.ACTIVE.value
    assert conn.connection_metadata["scanner_access"]["rule_ref"] == v_rules.REF
    assert TOKEN not in await _audit_text(db_session)


async def test_apply_pending_permissions_stays_pending(db_session, monkeypatch):
    u, w, _ = await _connected_site(db_session, "vsa2@x.com", "example.com")

    async def forbidden(tok, pid, tid=None):
        raise v_rules.VercelRuleError("forbidden", http_status=403)
    monkeypatch.setattr(v_rules, "ensure_bypass_rule", forbidden)
    res = await vsa.apply_scanner_bypass(
        db_session, website=w, access_token=TOKEN, project_id="prj_x", team_id="team_x",
        user_id=u.id, org_id=u.id)
    assert not res["applied"] and res["status"] == "pending_permissions"
    ta = await ta_service.get_trusted_access(db_session, w)
    # NEVER faked active, and not failed — honest pending.
    assert ta.access_status == TrustedAccessStatus.PENDING.value


async def test_apply_blocked_non_bypassable_is_limited_not_active(db_session, monkeypatch):
    u, w, _ = await _connected_site(db_session, "vsa3@x.com", "example.com")
    monkeypatch.setattr(v_rules, "ensure_bypass_rule", _ens(attack_mode=True))
    monkeypatch.setattr(v_rules, "verify_bypass_rule", _ver(verified=True, attack_mode=True))
    res = await vsa.apply_scanner_bypass(
        db_session, website=w, access_token=TOKEN, project_id="prj_x", team_id="team_x",
        user_id=u.id, org_id=u.id)
    assert res["status"] == "blocked_non_bypassable" and "customer_action" in res
    ta = await ta_service.get_trusted_access(db_session, w)
    assert ta.access_status == TrustedAccessStatus.LIMITED.value  # NOT active


async def test_apply_verify_failure_marks_failed(db_session, monkeypatch):
    u, w, _ = await _connected_site(db_session, "vsa4@x.com", "example.com")
    monkeypatch.setattr(v_rules, "ensure_bypass_rule", _ens())
    monkeypatch.setattr(v_rules, "verify_bypass_rule", _ver(verified=False))
    res = await vsa.apply_scanner_bypass(
        db_session, website=w, access_token=TOKEN, project_id="prj_x", team_id="team_x",
        user_id=u.id, org_id=u.id)
    assert not res["applied"] and res["status"] == "failed"
    ta = await ta_service.get_trusted_access(db_session, w)
    assert ta.access_status == TrustedAccessStatus.FAILED.value


async def test_apply_firewall_not_initialized_is_pending_not_failed(db_session, monkeypatch):
    u, w, conn = await _connected_site(db_session, "vsa7@x.com", "example.com")

    async def unavailable(tok, pid, tid=None):
        raise v_rules.VercelFirewallUnavailableError("not init", http_status=404)
    monkeypatch.setattr(v_rules, "ensure_bypass_rule", unavailable)
    res = await vsa.apply_scanner_bypass(
        db_session, website=w, access_token=TOKEN, project_id="prj_x", team_id="team_x",
        user_id=u.id, org_id=u.id)
    assert not res["applied"] and res["status"] == "pending_firewall_setup"
    assert "customer_action" in res
    ta = await ta_service.get_trusted_access(db_session, w)
    # Honest: PENDING (a one-time dashboard step), NOT failed, NOT fake-active.
    assert ta.access_status == TrustedAccessStatus.PENDING.value
    assert conn.connection_metadata["scanner_access"]["firewall_status"] == "not_initialized"


async def test_apply_no_project_is_failed(db_session, monkeypatch):
    u, w, _ = await _connected_site(db_session, "vsa5@x.com", "example.com")
    res = await vsa.apply_scanner_bypass(
        db_session, website=w, access_token=TOKEN, project_id=None, team_id="team_x",
        user_id=u.id, org_id=u.id)
    assert res["status"] == "failed" and res["reason"] == "no_project"


async def test_disconnect_removes_rule_and_reverts(db_session, monkeypatch):
    u, w, conn = await _connected_site(db_session, "vsa6@x.com", "example.com")
    monkeypatch.setattr(v_rules, "ensure_bypass_rule", _ens())
    monkeypatch.setattr(v_rules, "verify_bypass_rule", _ver(verified=True))
    await vsa.apply_scanner_bypass(
        db_session, website=w, access_token=TOKEN, project_id="prj_x", team_id="team_x",
        user_id=u.id, org_id=u.id)

    removed_calls = {}

    async def fake_remove(tok, pid, tid=None):
        removed_calls["args"] = (pid, tid)
        return {"removed": [v_rules.REF]}
    monkeypatch.setattr(v_rules, "remove_bypass_rule", fake_remove)
    monkeypatch.setattr(vsa, "_load_access_token", lambda db, wid: _coro(TOKEN))

    res = await vsa.disconnect_scanner_bypass(db_session, website=w, user_id=u.id, org_id=u.id)
    assert res["removed"] == [v_rules.REF] and removed_calls["args"] == ("prj_x", "team_x")
    ta = await ta_service.get_trusted_access(db_session, w)
    assert ta.access_status == TrustedAccessStatus.PENDING.value  # reverted
    assert "scanner_access" not in (conn.connection_metadata or {})
    assert TOKEN not in await _audit_text(db_session)


async def _coro(value):
    return value


_SCANNER_IPS = ["152.55.180.27"]


async def test_ip_access_forbidden_is_pending_manual_setup(db_session, monkeypatch):
    u, w, conn = await _connected_site(db_session, "vip1@x.com", "example.com")
    import apps.api.config as _cfg
    monkeypatch.setattr(_cfg, "scanner_outbound_ips", lambda: list(_SCANNER_IPS))

    async def forbidden(tok, pid, tid, ips):
        raise v_rules.VercelBypassForbiddenError("forbidden", http_status=403)
    monkeypatch.setattr(v_rules, "ensure_ip_system_bypass", forbidden)

    res = await vsa.apply_ip_scanner_access(
        db_session, website=w, access_token=TOKEN, project_id="prj_x", team_id="team_x",
        user_id=u.id, org_id=u.id)
    assert res["status"] == "pending_manual_setup" and res["ticketable"] is True
    assert res["scanner_ips"] == _SCANNER_IPS and "152.55.180.27" in res["customer_action"]
    ta = await ta_service.get_trusted_access(db_session, w)
    assert ta.access_status == TrustedAccessStatus.PENDING.value  # honest: never active
    assert conn.connection_metadata["scanner_access"]["method"] == "manual_ip_bypass"
    assert TOKEN not in await _audit_text(db_session)
    # The status view surfaces the guided manual setup (IP + steps + ticketable).
    from apps.api.services import vercel_scanner_state as _vstate
    view = await _vstate.scanner_access_view(db_session, w)
    assert view["status"] == "pending_manual_setup" and view["scanner_ips"] == _SCANNER_IPS
    assert view["ticketable"] is True and "152.55.180.27" in view["next_action"]


async def test_ip_access_success_is_configured_not_active(db_session, monkeypatch):
    u, w, conn = await _connected_site(db_session, "vip2@x.com", "example.com")
    import apps.api.config as _cfg
    monkeypatch.setattr(_cfg, "scanner_outbound_ips", lambda: list(_SCANNER_IPS))

    async def ens(tok, pid, tid, ips):
        return {"created": list(ips), "existing": []}
    async def ver(tok, pid, tid, ips):
        return {"present": list(ips), "missing": [], "verified": True}
    monkeypatch.setattr(v_rules, "ensure_ip_system_bypass", ens)
    monkeypatch.setattr(v_rules, "verify_ip_system_bypass", ver)

    res = await vsa.apply_ip_scanner_access(
        db_session, website=w, access_token=TOKEN, project_id="prj_x", team_id="team_x",
        user_id=u.id, org_id=u.id)
    assert res["applied"] and res["status"] == "configured"
    ta = await ta_service.get_trusted_access(db_session, w)
    # Rule created, but coverage UNPROVEN -> NEVER active until a scan validates.
    assert ta.access_status == TrustedAccessStatus.PENDING.value
    assert conn.connection_metadata["scanner_access"]["method"] == "ip_system_bypass"
    assert conn.connection_metadata["scanner_access"]["scanner_ips"] == _SCANNER_IPS


async def test_disconnect_removes_ip_bypass(db_session, monkeypatch):
    u, w, conn = await _connected_site(db_session, "vip3@x.com", "example.com")
    import apps.api.config as _cfg
    monkeypatch.setattr(_cfg, "scanner_outbound_ips", lambda: list(_SCANNER_IPS))
    removed_args = {}

    async def fake_remove_ip(tok, pid, tid, ips):
        removed_args["ips"] = list(ips)
        return {"removed": list(ips)}
    monkeypatch.setattr(v_rules, "remove_ip_system_bypass", fake_remove_ip)
    monkeypatch.setattr(vsa, "_load_access_token", lambda db, wid: _coro(TOKEN))
    # WAF removal path is a no-op here (firewall 404); stub it to avoid network.
    async def fake_remove_waf(tok, pid, tid=None):
        return {"removed": []}
    monkeypatch.setattr(v_rules, "remove_bypass_rule", fake_remove_waf)

    res = await vsa.disconnect_scanner_bypass(db_session, website=w, user_id=u.id, org_id=u.id)
    assert removed_args.get("ips") == _SCANNER_IPS
    assert _SCANNER_IPS[0] in res["removed"]
    ta = await ta_service.get_trusted_access(db_session, w)
    assert ta.access_status == TrustedAccessStatus.PENDING.value


_SECRET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"  # 32-char fake bypass secret


async def test_store_protection_bypass_configures_not_active(db_session):
    u, w, conn = await _connected_site(db_session, "vsa8@x.com", "example.com")
    res = await vsa.store_protection_bypass(
        db_session, website=w, secret=_SECRET, user_id=u.id, org_id=u.id)
    # NEVER fake active on store — coverage is only proven by a scan.
    assert res["status"] == "configured"
    ta = await ta_service.get_trusted_access(db_session, w)
    assert ta.access_status == TrustedAccessStatus.PENDING.value
    # Secret round-trips (decrypts) for the worker hot path, and is never in the audit log.
    assert await vsa.load_protection_bypass(db_session, w.id) == _SECRET
    assert _SECRET not in await _audit_text(db_session)
    # Disconnect revokes it.
    await vsa.disconnect_scanner_bypass(db_session, website=w, user_id=u.id, org_id=u.id)
    assert await vsa.load_protection_bypass(db_session, w.id) is None
