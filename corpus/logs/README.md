# `corpus/logs/` — Ingestion / normalization run logs

Operational logs from (future) ingestion and normalization runs: what was fetched,
normalized, skipped, deduped, or rejected, with timestamps and counts.

**Allowed:** run metadata, source URLs (token-free), counts, errors, decisions.

**Prohibited (critical):** API keys/tokens (never log secret VALUES), customer
data, full raw payloads, PII. Logs are scrubbed by policy
([`RETENTION_POLICY`](../../docs/ai/corpus/RETENTION_POLICY.md)); WebHound already
has a redaction primitive (`scanner/webhound/telemetry/redaction.py`) to reuse.

**Source authority:** n/a (operational logs, not evidence).

**Ingestion expectations:** written by Phase-5 ingestion tooling; **empty now**.

**Retention expectations:** `short`/`ttl` — rotate; logs are not durable evidence.
