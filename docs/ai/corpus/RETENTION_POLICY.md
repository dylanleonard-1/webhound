# Retention & Data-Hygiene Policy

Defines how long corpus items live, their PII risk, and — most importantly — what
must **never** enter the corpus.

## Retention classes
| Class | Meaning | Typical sources |
|-------|---------|-----------------|
| `permanent` | Keep indefinitely; durable reference. | standards/specs (OWASP, CSP/CORS), research papers |
| `long` | Keep long-term; refresh on version change. | official vendor/provider docs, official repo snapshots |
| `short` | Keep briefly; low durability. | transient notes, run logs |
| `ttl` | Expires at `ttl_expires_at`; purge after. | threat-feed payloads, volatile indicators |

Normalized derivatives inherit their raw source's class and are purged when the raw
source expires.

## PII risk classes
| Class | Meaning | Handling |
|-------|---------|----------|
| `none` | No personal data. | default target for all corpus content |
| `possible` | Might contain incidental PII. | review/scrub before promoting beyond raw |
| `high` | Likely PII. | **do not ingest** without explicit approval + minimization |

## NEVER enter the corpus (hard prohibitions)
- **API keys, tokens, credentials, cookies, session data.**
- **Customer secrets / customer-private data.**
- **Payment / Stripe / billing data.**
- **Private or un-anonymized scan artifacts** (raw customer scan payloads).
- **Repo secrets** (`.env`, key files) or **personal files outside the WebHound
  workspace**.
- **Executable live malicious payloads** — malicious JS/malware is studied as
  **inert text / synthetic fixtures** only (Phase 7), never runnable samples.

WebHound already has primitives to enforce hygiene — reuse them, don't reinvent:
`scanner/webhound/telemetry/redaction.py` (redaction), `encrypted_secret` model,
`docs/secret-management.md`.

## Operational rules
- Default every item to `pii_risk_class: none`; anything higher needs review.
- Logs (`corpus/logs/`) are `short`/`ttl` and **scrubbed** — never log secret
  values.
- `ttl` items must set `ttl_expires_at`; a purge pass removes expired raw +
  dependent normalized chunks + graph nodes.
- Deprecation: superseded sources get `verification_status: deprecated` (kept for
  provenance/history, excluded from active retrieval).
