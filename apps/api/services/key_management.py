# WebHound — apps/api/services/key_management.py
# Phase 4.1 — KeyManagementService: versioned authenticated encryption (Fernet)
# for secrets at rest. Proven library only (cryptography.fernet) — NO custom
# crypto. Keys come from env (never hardcoded). Supports key versioning +
# rotation: each ciphertext records the key version that produced it, so old
# secrets keep decrypting after a new active key is added.
#
# Trust boundary: the key lives in the deploy env (same boundary as
# DATABASE_URL), so this protects against DATABASE-DUMP exposure (attacker gets
# the DB but not the env) — NOT full-environment compromise.

from __future__ import annotations

import logging
from functools import lru_cache

from cryptography.fernet import Fernet

from apps.api.config import get_settings

logger = logging.getLogger(__name__)

_EPHEMERAL_VERSION = "dev-ephemeral"


class SecretsNotConfiguredError(RuntimeError):
    """No encryption key configured (production) — refuse to encrypt (fail closed)."""


class UnknownKeyVersionError(KeyError):
    """A ciphertext references a key version we no longer hold — fail closed.

    Operational rule: NEVER evict a key version until every secret encrypted
    under it has been re-encrypted to the active version."""


class KeyManagementService:
    """Encrypt/decrypt with versioned Fernet keys. Stateless apart from the keys."""

    def __init__(self, keys: dict[str, Fernet], active_version: str | None):
        self._keys = keys
        self._active = active_version

    @property
    def is_configured(self) -> bool:
        return bool(self._keys) and self._active in self._keys

    @property
    def active_version(self) -> str:
        if not self.is_configured:
            raise SecretsNotConfiguredError(
                "No encryption key configured. Set ENCRYPTION_KEYS (+ optional "
                "ENCRYPTION_ACTIVE_VERSION) before storing secrets.")
        assert self._active is not None
        return self._active

    @property
    def key_versions(self) -> list[str]:
        return list(self._keys.keys())

    @property
    def previous_versions(self) -> list[str]:
        return [v for v in self._keys if v != self._active]

    @property
    def is_ephemeral(self) -> bool:
        return _EPHEMERAL_VERSION in self._keys

    def encrypt(self, plaintext: str) -> tuple[str, str]:
        """Return (key_version, ciphertext). Raises SecretsNotConfiguredError if
        no key is configured (fail closed)."""
        version = self.active_version
        token = self._keys[version].encrypt(plaintext.encode("utf-8"))
        return version, token.decode("ascii")

    def decrypt(self, key_version: str, ciphertext: str) -> str:
        f = self._keys.get(key_version)
        if f is None:
            raise UnknownKeyVersionError(key_version)
        # NO ttl — stored secrets must decrypt regardless of age. (Fernet raises
        # cryptography.fernet.InvalidToken on tamper/wrong-key; callers handle it.)
        return f.decrypt(ciphertext.encode("ascii")).decode("utf-8")


def _parse_keys(raw: str) -> dict[str, Fernet]:
    keys: dict[str, Fernet] = {}
    for pair in (raw or "").split(","):
        pair = pair.strip()
        if not pair:
            continue
        version, sep, key = pair.partition(":")
        if not sep or not version.strip() or not key.strip():
            raise ValueError("ENCRYPTION_KEYS must be '<version>:<fernet-key>,...'")
        keys[version.strip()] = Fernet(key.strip().encode("ascii"))
    return keys


def _build() -> KeyManagementService:
    settings = get_settings()
    keys = _parse_keys(settings.encryption_keys)
    if keys:
        active = (settings.encryption_active_version or "").strip() or next(iter(keys))
        if active not in keys:
            raise ValueError(
                f"ENCRYPTION_ACTIVE_VERSION '{active}' is not present in ENCRYPTION_KEYS")
        return KeyManagementService(keys, active)
    if settings.app_env == "production":
        # Fail closed — do NOT generate an ephemeral key in prod. An ephemeral
        # key would make every stored secret undecryptable garbage after the next
        # restart (silent credential loss). The service boots, but encrypt()
        # raises until ENCRYPTION_KEYS is configured.
        logger.error(
            "ENCRYPTION_KEYS not set in production — secret storage is DISABLED "
            "(fail closed). Configure ENCRYPTION_KEYS before shipping any provider "
            "integration.")
        return KeyManagementService({}, None)
    # Dev/test only — ephemeral key, loudly flagged.
    logger.warning(
        "ENCRYPTION_KEYS not set — using an EPHEMERAL dev key. Stored secrets "
        "will NOT survive a process restart. Set ENCRYPTION_KEYS for persistence.")
    return KeyManagementService(
        {_EPHEMERAL_VERSION: Fernet(Fernet.generate_key())}, _EPHEMERAL_VERSION)


@lru_cache(maxsize=1)
def get_key_management() -> KeyManagementService:
    return _build()
