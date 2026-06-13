# `corpus/graph/` — Knowledge-graph artifacts

Exported knowledge-graph artifacts (nodes/edges linking sources → documents →
chunks → entities → playbooks/findings). **Built in Phase 4** (RAG/graph layer).

> **Distinct from the Security Graph.** WebHound's `scanner/webhound/graph/`
> ("Security Graph Engine") is a **per-scan, runtime** evidence graph of findings.
> This corpus graph is the **long-term knowledge graph** of evidence/sources. They
> are separate stores; at most a read-only bridge connects them. See
> [`WEBHOUND_EXISTING_SYSTEMS_MAP`](../../docs/ai/corpus/WEBHOUND_EXISTING_SYSTEMS_MAP.md).

**Allowed:** derived graph exports referencing manifest `doc_id`s; no raw content
duplication; no secrets.

**Prohibited:** customer data, secrets, per-scan runtime data (that belongs to the
Security Graph).

**Status:** **empty in Phase 2** (design only).

**Retention:** derived/rebuildable; regenerated from `normalized/` + `manifests/`.
