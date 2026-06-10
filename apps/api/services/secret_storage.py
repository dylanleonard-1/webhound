# WebHound — apps/api/services/secret_storage.py
# Phase 4.1 — SecretStorageService. The ONLY sanctioned way to persist provider
# secrets (OAuth access/refresh tokens, API keys, credentials). It always
# encrypts via KeyManagementService and never stores or logs plaintext. All
# provider integrations (4.2+) must store through this — no token columns
# anywhere else.

from __future__ import annotations

import logging
from datetime import datetime, timezone

import sqlalchemy as sa
from cryptography.fernet import InvalidToken
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.admin_audit_log import AdminAuditLog
from apps.api.models.encrypted_secret import EncryptedSecret
from apps.api.models.enums import SecretClassification, SecretStatus
from apps.api.models.user import User
from apps.api.platform.observability.structured_logging import redact
from apps.api.services.key_management import UnknownKeyVersionError, get_key_management

logger = logging.getLogger(__name__)

# Audit event names (admin_audit_log). NEVER carry plaintext.
SECRET_CREATED = "secret.created"
SECRET_ROTATED = "secret.rotated"
SECRET_REVOKED = "secret.revoked"
SECRET_ACCESS_DENIED = "secret.access.denied"
SECRET_FAILED_ACCESS = "secret.failed_access"


class SecretRevokedError(RuntimeError):
    """Attempt to reveal a revoked secret."""


def _actor_marker(actor) -> str:
    if isinstance(actor, User):
        return f"user:{actor.id}"
    if isinstance(actor, str) and actor:
        return actor  # e.g. "system:scan-worker"
    return "system"


def _record(db: AsyncSession, action: str, secret: EncryptedSecret, *,
            actor=None, reason: str | None = None) -> None:
    """Append a secret.* audit row to admin_audit_log. Reuses the existing audit
    table + redaction; NEVER includes plaintext or ciphertext."""
    detail = {
        "resource_type": secret.resource_type,
        "secret_type": secret.secret_type,
        "classification": secret.classification,
        "key_version": secret.key_version,
        "status": secret.status,
        "org_id": str(secret.org_id) if secret.org_id else None,
        "website_id": str(secret.website_id) if secret.website_id else None,
        "actor": _actor_marker(actor),
        "reason": reason,
    }
    db.add(AdminAuditLog(
        actor_user_id=actor.id if isinstance(actor, User) else None,
        actor_email=actor.email if isinstance(actor, User) else None,
        action=action,
        target_type="secret",
        target_id=str(secret.id),
        detail=redact(detail),
    ))


async def store_secret(
    db: AsyncSession, *, resource_type: str, secret_type: str, plaintext: str,
    classification: SecretClassification = SecretClassification.LEVEL_3_CONFIDENTIAL,
    org_id=None, user_id=None, website_id=None, metadata: dict | None = None,
    actor=None,
) -> EncryptedSecret:
    """Encrypt + persist a secret. Raises SecretsNotConfiguredError (fail closed)
    if no encryption key is configured. Plaintext is never stored or logged."""
    kms = get_key_management()
    key_version, ciphertext = kms.encrypt(plaintext)
    cls = classification.value if isinstance(classification, SecretClassification) else classification
    secret = EncryptedSecret(
        org_id=org_id, user_id=user_id, website_id=website_id,
        resource_type=resource_type, secret_type=secret_type, classification=cls,
        key_version=key_version, ciphertext=ciphertext,
        # Redact metadata on store — never let a careless caller stash a token here.
        secret_metadata=redact(metadata or {}),
        status=SecretStatus.ACTIVE.value,
    )
    db.add(secret)
    await db.flush()
    _record(db, SECRET_CREATED, secret, actor=actor)
    return secret


async def get_active_secret(
    db: AsyncSession, *, resource_type: str, secret_type: str,
    org_id=None, website_id=None,
) -> EncryptedSecret | None:
    """Owner-scoped lookup of the active secret (tenant isolation: the caller
    passes the authorized org/website)."""
    conds = [
        EncryptedSecret.resource_type == resource_type,
        EncryptedSecret.secret_type == secret_type,
        EncryptedSecret.status == SecretStatus.ACTIVE.value,
    ]
    if org_id is not None:
        conds.append(EncryptedSecret.org_id == org_id)
    if website_id is not None:
        conds.append(EncryptedSecret.website_id == website_id)
    return await db.scalar(
        sa.select(EncryptedSecret).where(*conds)
        .order_by(EncryptedSecret.created_at.desc()).limit(1))


async def reveal_secret(db: AsyncSession, secret: EncryptedSecret, *, actor=None) -> str:
    """Decrypt + return PLAINTEXT — the only legitimate plaintext lifetime. The
    caller MUST NOT log the return value. Hot path: bump access counter, no audit
    row per access (full audit is reserved for create/rotate/revoke + denials)."""
    if secret.status != SecretStatus.ACTIVE.value:
        _record(db, SECRET_ACCESS_DENIED, secret, actor=actor, reason="revoked")
        raise SecretRevokedError(str(secret.id))
    kms = get_key_management()
    try:
        plaintext = kms.decrypt(secret.key_version, secret.ciphertext)
    except (UnknownKeyVersionError, InvalidToken) as exc:
        _record(db, SECRET_FAILED_ACCESS, secret, actor=actor, reason=type(exc).__name__)
        raise
    secret.last_accessed_at = datetime.now(timezone.utc)
    secret.access_count = (secret.access_count or 0) + 1
    return plaintext


async def rotate_secret(db: AsyncSession, secret: EncryptedSecret, *, actor=None) -> EncryptedSecret:
    """Re-encrypt under the active key version (no provider/customer reconnect)."""
    kms = get_key_management()
    plaintext = kms.decrypt(secret.key_version, secret.ciphertext)  # current version
    key_version, ciphertext = kms.encrypt(plaintext)                # active version
    secret.key_version = key_version
    secret.ciphertext = ciphertext
    secret.rotated_at = datetime.now(timezone.utc)
    await db.flush()
    _record(db, SECRET_ROTATED, secret, actor=actor)
    return secret


async def revoke_secret(db: AsyncSession, secret: EncryptedSecret, *, actor=None) -> EncryptedSecret:
    """Revoke + wipe the ciphertext — nothing decryptable remains."""
    secret.status = SecretStatus.REVOKED.value
    secret.revoked_at = datetime.now(timezone.utc)
    secret.ciphertext = ""
    await db.flush()
    _record(db, SECRET_REVOKED, secret, actor=actor)
    return secret
