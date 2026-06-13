# Provenance Policy

Every corpus item is traceable to where it came from, how authoritative it is, and
how it has been transformed. Provenance is **mandatory** and **survives every
plane** (raw → normalized → graph → memory).

## What every document tracks
- **source** — `source_name` + `source_url` (secret-free).
- **authority** — `authority_tier` (A–E) + optional `trust_label`.
- **version** — `version` + `last_updated` (at source).
- **hash** — `content_hash` (e.g. `sha256:…`) for integrity + dedupe.
- **ingest date** — `first_ingested`.
- **review status** — `verification_status` (`verified`/`needs_review`/…).
- **lineage** — for derivatives, `lineage.raw_doc_id` (+ derivation, chunk index).

## How provenance survives each plane
| Plane | What carries provenance |
|-------|-------------------------|
| **raw/** | The manifest record for the as-fetched item; `content_hash` pins the exact bytes; raw is immutable. |
| **normalized/** | Each chunk's record sets `lineage.raw_doc_id` and **inherits** `authority_tier`, `license_terms`, `pii_risk_class`, `retention_class` from the raw item. Authority **cannot increase** during normalization. |
| **graph/** | Nodes/edges reference manifest `doc_id`s; an edge never invents a relationship not grounded in a doc. |
| **memory (Phase 4)** | Claude memory stores **summaries + pointers (`doc_id`/source_url) only** — never full docs/raw feeds — so any claim is traceable back to a manifest record. |

## Rules
- No corpus item exists without a manifest record (no "orphan" content).
- A normalized chunk with no `lineage` is invalid.
- `content_hash` must match the stored bytes; a mismatch ⇒ `verification_status:
  needs_review`.
- Re-fetch updates `version`/`last_updated`/`content_hash` and may flip status to
  `needs_review` until re-verified (important for volatile provider docs/feeds).
- Provenance fields must be **secret-free** (no tokens in `source_url`).

## Why
Provenance is what makes this an *evidence system* rather than memory: every
assertion the auditor makes can be traced to a tiered, hashed, dated source — and
downgraded/deprecated when the source changes.
