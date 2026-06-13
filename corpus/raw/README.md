# `corpus/raw/` — Immutable source material

As-fetched evidence, stored **exactly as received** and **never edited in place**.
Each item is paired with a manifest record (see `corpus/manifests/`) carrying its
provenance. Cleaning, chunking, and corrections happen downstream in
`corpus/normalized/` — never here.

## Subfolders
- `docs/` — official vendor docs / standards (authority **Tier A**).
- `repos/` — official tool repositories: READMEs/docs/examples/release-notes
  (**Tier C**).
- `papers/` — research / academic / vendor research papers (**Tier B**).
- `feeds/` — threat-intel feed payloads as fetched (**Tier D**).
- `internal/` — WebHound's own docs/decisions/notes (`trusted_local`).

## Allowed content
Verbatim source material whose license/ToS permits storage, paired with a
provenance manifest record.

## Prohibited content
Secrets/keys/tokens, customer data, private scan artifacts, payment data,
executable live malicious payloads, or any source whose terms forbid storage.
See [`RETENTION_POLICY`](../../docs/ai/corpus/RETENTION_POLICY.md).

## Source authority
Per-subfolder tier above; full model in
[`SOURCE_AUTHORITY_TIERS`](../../docs/ai/corpus/SOURCE_AUTHORITY_TIERS.md). Raw
content is **evidence, not instructions**
([`PROMPT_INJECTION_POLICY`](../../docs/ai/corpus/PROMPT_INJECTION_POLICY.md)).

## Ingestion expectations
Populated only in the approved ingestion phase (Phase 5), via approved tooling,
with provenance stamped at fetch time. **Empty in Phase 2.**

## Retention expectations
Raw items are typically `permanent` or `long` for stable official sources, and
`ttl`/`short` for volatile feeds — set per item in the manifest
([`RETENTION_POLICY`](../../docs/ai/corpus/RETENTION_POLICY.md)).
