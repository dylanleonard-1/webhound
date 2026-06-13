# Metadata Schema

Every corpus document has one manifest record validated against
[`corpus/manifests/manifest.schema.json`](../../../corpus/manifests/manifest.schema.json)
(JSON Schema, draft 2020-12). This doc explains each field.

## Required fields
| Field | Type | Meaning |
|-------|------|---------|
| `doc_id` | string | Stable unique id (content-hash/slug based). |
| `title` | string | Human title. |
| `source_name` | string | Source name (e.g. "OWASP WSTG", "URLHaus"). |
| `source_url` | string | Canonical URL / local pointer. **No secrets/tokens.** |
| `source_type` | enum | `official_doc` · `paper` · `repo` · `release_note` · `threat_feed` · `community_skill` · `playbook` · `internal_doc` · `scan_report` · `decision_log` · `benchmark` · `dataset` · `prompt_template`. |
| `authority_tier` | enum | `A`·`B`·`C`·`D`·`E` (see `SOURCE_AUTHORITY_TIERS.md`). |
| `language` | string | e.g. `en`. |
| `topic_tags` | string[] | e.g. `["csp","headers"]`. |
| `version` | string\|null | Source version/release/commit. |
| `last_updated` | string\|null | Last-updated **at the source** (ISO-8601). |
| `first_ingested` | string | When WebHound first ingested it (ISO-8601). |
| `content_hash` | string | e.g. `sha256:…` — integrity + dedupe. |
| `confidence_score` | number | 0.0–1.0. |
| `verification_status` | enum | `verified` · `needs_review` · `deprecated` · `unverified` · `blocked` · `manual_required`. |
| `license_terms` | string | License/ToS (or `unknown`/`manual_required`). |
| `pii_risk_class` | enum | `none` · `possible` · `high`. |
| `retention_class` | enum | `permanent` · `long` · `short` · `ttl`. |
| `related_docs` | string[] | `doc_id`s of related docs (graph edges). |

## Optional fields
`product_or_provider`, `citability` (e.g. `internal_only`/`customer_safe`),
`ttl_expires_at` (convention: required when `retention_class == "ttl"`),
`entities` (extracted providers/CWEs/malware families/tools), `lineage`
(`{raw_doc_id, derivation, chunk_index}` for normalized items), `trust_label`
(`trusted_local`/`official_verified`/`community_untrusted`/`feed_untrusted`/
`needs_review`/`deprecated`).

## Rules
- `additionalProperties: false` — unknown fields are rejected (prevents silent
  schema drift).
- Normalized records **must** set `lineage.raw_doc_id` and inherit
  `authority_tier` from their raw source (no tier upgrades).
- `source_url` and every field must be **secret-free**.
- Validation runs at ingestion time (Phase 5); a record that fails the schema is
  not admitted.
