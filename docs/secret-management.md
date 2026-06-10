# Secret Management & Encryption at Rest (Phase 4.1)

The secure-storage foundation that must exist before any provider OAuth/API
credential is stored (Cloudflare 4.2, Vercel, Shopify, Wix, Squarespace, future
SSO). No real provider connection ships until this is active.

## Classification (`enums.SecretClassification`)
- **L1 public** — provider names, domains, scanner identity. Not stored here.
- **L2 sensitive** — customer metadata, provider account ids.
- **L3 confidential** — OAuth access/refresh tokens, API keys → **encrypted here**.
- **L4 restricted** — encryption/signing/JWT/infra keys → live in **env**, never in this table.

## Architecture
- **`services/key_management.py` — `KeyManagementService`**: versioned authenticated
  encryption via **Fernet** (`cryptography`, AES-128-CBC + HMAC-SHA256). Proven
  library only — no custom crypto. `encrypt() → (key_version, ciphertext)`;
  `decrypt(version, ciphertext)` (no TTL — secrets decrypt regardless of age).
- **`models/encrypted_secret.py` — `EncryptedSecret`**: stores **ciphertext + the
  key version**, owner (org/user/website), resource/secret type, classification,
  non-secret metadata, status, access counter. **Never plaintext.**
- **`services/secret_storage.py` — `SecretStorageService`**: `store_secret`,
  `get_active_secret`, `reveal_secret`, `rotate_secret`, `revoke_secret`. The
  **only** sanctioned path to persist a provider secret.

## Trust boundary (state this honestly)
The encryption key lives in the deploy **environment** (Railway env, same trust
boundary as `DATABASE_URL`). So encryption-at-rest protects against
**database-dump exposure** — an attacker who obtains the DB but not the env
cannot read tokens. It does **not** protect against full-environment compromise
(if you have the env you have the key). A future KMS/HSM would raise that bound.

## Key configuration
```
ENCRYPTION_KEYS="1:<fernet-key>"            # "<version>:<key>,<version>:<key>"
ENCRYPTION_ACTIVE_VERSION="1"               # optional; defaults to the first
# generate a key:
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
- **Prod fails closed**: with no keys set, `store_secret` raises
  `SecretsNotConfiguredError` (it does NOT invent an ephemeral key — that would
  make stored secrets undecryptable after a restart). Dev uses an ephemeral key
  with a loud warning (secrets don't survive restart).

## Key rotation
1. Add a new key as a new version and set it active:
   `ENCRYPTION_KEYS="1:<old>,2:<new>"`, `ENCRYPTION_ACTIVE_VERSION="2"`.
2. Existing secrets keep decrypting via their stored `key_version`.
3. `rotate_secret(secret)` re-encrypts a secret to the active version (no
   provider/customer reconnect, no token recreation).
4. **Operational rule: never remove an old key version until every secret on it
   has been re-encrypted** — `decrypt` on an unknown version fails closed
   (`UnknownKeyVersionError` + `secret.failed_access`), never returns garbage.

## No-plaintext rules
- `reveal_secret()`'s return value is the **only** plaintext lifetime — callers
  must never log it.
- Metadata is `redact()`-ed on store (so a careless caller can't stash a token).
- Status/response payloads are explicit metadata allowlists — never the model
  object (no ciphertext in responses). Admins see metadata, not raw secrets.

## Audit (`admin_audit_log`, reused)
`secret.created` / `secret.rotated` / `secret.revoked` / `secret.access.denied` /
`secret.failed_access` — with actor (user or `system:*`), resource/secret type,
classification, `key_version`, timestamps. **Never** the value. Hot-path reads
bump `access_count` + `last_accessed_at` instead of one audit row per access.

## How integrations (4.2+) consume it
```python
await store_secret(db, resource_type="cloudflare", secret_type="oauth_access_token",
                   plaintext=token, org_id=org_id, metadata={"scopes": [...]}, actor=user)
s = await get_active_secret(db, resource_type="cloudflare",
                            secret_type="oauth_access_token", org_id=org_id)
token = await reveal_secret(db, s, actor="system:cloudflare-sync")  # do NOT log
```

## Migration path
There are no pre-existing stored provider tokens (the social-login OAuth flow
uses tokens once and discards them), so there is nothing to migrate. The store
always encrypts; rotation re-encrypts in place. A future unencrypted→encrypted
backfill would read plaintext, `store_secret`, and delete the plaintext row.
