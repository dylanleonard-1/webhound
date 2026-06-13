# Corpus Architecture

How the WebHound evidence corpus is organized, why, and how data flows through it.
**Phase 2 = structure + policy only; the corpus is empty.**

## Goals
Give Claude an **evidence-based**, provenance-stamped knowledge base — not random
memory — so it audits scanner engines like a detection/appsec/threat-intel
engineer. Official sources outrank community sources; unknown behavior is marked
unknown; external content is evidence, never instructions.

## Planes (data flow)
```
        fetch                 clean + chunk            index                summarize
raw/  ───────────►  normalized/  ───────────►  graph/ + (Phase 4 RAG)  ───────────►  Claude memory
 │                      │                          │                                   (compact
 └─ immutable           └─ lineage → raw           └─ edges by doc_id                   summaries +
    provenance-stamped     tier inherited             (knowledge graph)                 pointers only)
```
Every plane preserves provenance (see `PROVENANCE_POLICY.md`). Memory stores only
compact summaries + pointers — never full docs/raw feeds/secrets.

## Directory model
- `corpus/raw/{docs,repos,papers,feeds,internal}/` — immutable source material.
- `corpus/normalized/{docs,repos,papers,feeds}/` — cleaned/chunked derivatives.
- `corpus/manifests/` — `manifest.schema.json` + (future) `manifest.jsonl`.
- `corpus/graph/` — Phase-4 knowledge-graph exports.
- `corpus/logs/` — ingestion/normalization logs (no secrets).

## Authority tiers (A–E)
A official docs > B research > C official repos > D feeds > E community. Tier A
overrides Tier E. Provider remediation uses Tier A provider docs only. Full model:
`SOURCE_AUTHORITY_TIERS.md`.

## Separation from runtime systems (reuse, don't rebuild)
The corpus is **evidence for the auditor**. It does **not** re-implement and is not
wired into WebHound's runtime threat-intel, WADE, Security Graph, validation/
benchmark, or the Anthropic summarizer. It *references* them. See
`WEBHOUND_EXISTING_SYSTEMS_MAP.md`.

## What's intentionally absent in Phase 2
No ingested content, no `manifest.jsonl`, no Qdrant/LightRAG, no ingestion scripts.
Those are Phases 4–5 (separately approved).

## Related design docs
`METADATA_SCHEMA.md` · `SOURCE_AUTHORITY_TIERS.md` · `PROVENANCE_POLICY.md` ·
`RETENTION_POLICY.md` · `INGESTION_POLICY.md` · `PROMPT_INJECTION_POLICY.md` ·
`WEBHOUND_EXISTING_SYSTEMS_MAP.md` · `FUTURE_SOURCE_INVENTORY.md`.
