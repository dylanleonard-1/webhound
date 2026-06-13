# `corpus/raw/internal/` — WebHound internal knowledge (trusted_local)

**Purpose:** WebHound's own durable knowledge — architecture notes, decision
records, engine rationale, incident write-ups — captured as evidence for the
knowledge layer.

**Allowed:** internal docs/decisions/notes authored for WebHound; sanitized
summaries of behavior. Prefer **pointers** to in-repo docs (`docs/`, `docs/ai/`)
and code paths over copies, to avoid drift.

**Prohibited (critical):** secrets/keys/tokens, customer data, raw/un-anonymized
scan artifacts, payment data, anything from outside the WebHound repo/workspace.
See [`RETENTION_POLICY`](../../docs/ai/corpus/RETENTION_POLICY.md).

**Source authority:** `trusted_local` — authoritative for WebHound's *own* design
and decisions (not a substitute for Tier A external standards).

**Ingestion expectations:** Phase 3+ (knowledge library) / later; **empty now**.

**Retention expectations:** `long`/`permanent` for decisions; `short` for
transient notes. PII risk should be `none` (sanitize before entry).
