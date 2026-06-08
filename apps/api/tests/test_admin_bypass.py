"""FIX 3 — admin security-bypass hardening.

Covers apps/api/internal/admin_bypass.py:
  * disabled by default
  * normal (non-admin) users can never bypass
  * admins are refused in production without the explicit override
  * a *use* of the bypass writes an admin-audit row
  * with the flag off, the gate returns False so normal verification/quota run
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.internal import admin_bypass
from apps.api.models.admin_audit_log import AdminAuditLog
from apps.api.models.user import User
from apps.api.models.enums import PlanTier
from apps.api.security import hash_password


def _settings(**over):
    base = dict(
        app_env="development",
        admin_quota_bypass=False,
        admin_verify_bypass=False,
        admin_bypass_allow_in_prod=False,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _user(is_admin: bool) -> User:
    return User(
        id=__import__("uuid").uuid4(),
        email=("admin" if is_admin else "user") + "@example.com",
        hashed_password=hash_password("x" * 12),
        is_active=True,
        is_admin=is_admin,
        plan=PlanTier.FREE,
    )


# --- pure gate ------------------------------------------------------------

def test_bypass_disabled_by_default():
    with patch.object(admin_bypass, "get_settings", return_value=_settings()):
        assert admin_bypass.quota_bypass_allowed(_user(True)) is False
        assert admin_bypass.verify_bypass_allowed(_user(True)) is False


def test_normal_user_cannot_bypass_even_when_flag_set():
    with patch.object(admin_bypass, "get_settings",
                      return_value=_settings(admin_quota_bypass=True, admin_verify_bypass=True)):
        assert admin_bypass.quota_bypass_allowed(_user(is_admin=False)) is False
        assert admin_bypass.verify_bypass_allowed(_user(is_admin=False)) is False


def test_admin_can_bypass_in_dev_when_flag_set():
    with patch.object(admin_bypass, "get_settings",
                      return_value=_settings(admin_quota_bypass=True)):
        assert admin_bypass.quota_bypass_allowed(_user(True)) is True


def test_admin_refused_in_prod_without_override():
    with patch.object(admin_bypass, "get_settings",
                      return_value=_settings(app_env="production", admin_quota_bypass=True,
                                             admin_bypass_allow_in_prod=False)):
        assert admin_bypass.quota_bypass_allowed(_user(True)) is False


def test_admin_allowed_in_prod_with_override():
    with patch.object(admin_bypass, "get_settings",
                      return_value=_settings(app_env="production", admin_quota_bypass=True,
                                             admin_bypass_allow_in_prod=True)):
        assert admin_bypass.quota_bypass_allowed(_user(True)) is True


# --- audit emission (needs a real session) --------------------------------

@pytest.mark.anyio
async def test_consume_quota_bypass_writes_audit_row(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    admin = _user(True)
    async with factory() as db:
        db.add(admin)
        await db.commit()

        async def _noop(*a, **k):
            return None

        with patch.object(admin_bypass, "get_settings",
                          return_value=_settings(admin_quota_bypass=True)), \
             patch("apps.api.internal.audit.publish_event", _noop):
            used = await admin_bypass.consume_quota_bypass(db, admin)
        assert used is True

        rows = (await db.execute(
            sa.select(AdminAuditLog).where(AdminAuditLog.action == "admin.bypass.quota")
        )).scalars().all()
        assert len(rows) == 1
        assert rows[0].actor_email == admin.email


@pytest.mark.anyio
async def test_consume_quota_bypass_disabled_writes_nothing(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    admin = _user(True)
    async with factory() as db:
        db.add(admin)
        await db.commit()
        with patch.object(admin_bypass, "get_settings", return_value=_settings()):
            used = await admin_bypass.consume_quota_bypass(db, admin)
        assert used is False
        rows = (await db.execute(sa.select(AdminAuditLog))).scalars().all()
        assert rows == []
