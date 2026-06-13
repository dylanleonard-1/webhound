# Claude Memory Policy

Plane 5 of the RAG architecture. Claude memory stores **compact, durable summaries +
pointers ONLY** — never full documents, raw feeds, customer data, or secrets. Memory
is an index into the corpus/knowledge, not a copy of it.

## Allowed in memory
- Durable **project decisions** (e.g. the AI-knowledge-layer decision record).
- **Architecture summaries** (short).
- **Manifest `doc_id` pointers** into the corpus.
- **Playbook paths** (`knowledge/playbooks/...`).
- **Engine-audit status** (which engines reviewed, outcome headline).
- **Summarized false-positive lessons** (1–3 lines + pointer to the FP note).
- **Roadmap / phase status** (which phase is done/approved).

## NEVER in memory (hard prohibitions)
- Secrets, **API keys, tokens**, credentials, cookies, session data.
- **Customer data**, raw/un-anonymized **scan payloads**, private screenshots.
- **Payment / billing** data.
- **Raw malicious payloads** (inert references only).
- **Full vendor docs** (link + summary only).
- **Unreviewed scraped content** (`needs_review` / `*_untrusted`).

## Memory record format
```json
{
  "memory_id": "string (stable id)",
  "summary": "1-5 line durable summary (no secrets/customer data)",
  "related_manifest_doc_ids": ["corpus manifest doc_ids this summarizes"],
  "related_paths": ["repo-relative paths, e.g. knowledge/.../note.md"],
  "authority_tier": "A|B|C|D|E|trusted_local",
  "created_at": "ISO-8601",
  "updated_at": "ISO-8601",
  "review_status": "verified|needs_review|deprecated",
  "retention_class": "permanent|long|short|ttl"
}
```
`scripts/ai/export_memory_summary.py` emits records in this shape from local
knowledge (summary + pointers only) to demonstrate the policy.

## Provenance + freshness
- Every memory summary points to the `doc_id`(s)/path(s) it derives from, so any
  claim is traceable.
- When a source is deprecated/changed, the summary is flagged `needs_review` or
  `deprecated` — memory never silently outlives its evidence.

## AI gating
Any future step that *generates* memory summaries via an LLM uses the existing
`WEBHOUND_AI_ENABLED` + `ANTHROPIC_API_KEY` gate. Phase 4 scripts do **not** call an
LLM; `export_memory_summary.py` builds records deterministically from local files.
