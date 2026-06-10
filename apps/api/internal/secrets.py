from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.internal.rbac import require_admin
from apps.api.models.encrypted_secret import EncryptedSecret
from apps.api.models.enums import AdminRole, SecretStatus
from apps.api.models.user import User
from apps.api.services.key_management import get_key_management

router = APIRouter(prefix="/internal/secrets", tags=["internal-secrets"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_Admin = Annotated[User, Depends(require_admin(AdminRole.ADMIN))]


@router.get("/status")
async def secret_management_status(db: _DB, actor: _Admin) -> dict:
    """Phase-4.1 security-review-gate status. Metadata ONLY — admins do not see
    raw secrets (no ciphertext, no plaintext) by design."""
    kms = get_key_management()
    total = await db.scalar(select(func.count()).select_from(EncryptedSecret)) or 0
    active = await db.scalar(
        select(func.count()).select_from(EncryptedSecret)
        .where(EncryptedSecret.status == SecretStatus.ACTIVE.value)) or 0
    return {
        "encryption_at_rest_active": kms.is_configured,
        "ephemeral_key": kms.is_ephemeral,
        "active_key_version": kms.active_version if kms.is_configured else None,
        "key_versions": kms.key_versions,
        "key_rotation_supported": True,
        "algorithm": "Fernet (AES-128-CBC + HMAC-SHA256, authenticated)",
        "secret_count_total": int(total),
        "secret_count_active": int(active),
    }
