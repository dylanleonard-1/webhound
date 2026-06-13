# Security Graph Bridge (read-only, one-way)

Defines the **only** approved relationship between WebHound's existing per-scan
Security Graph and the new Knowledge Layer. **Phase 4 documents this; it builds no
bridge code and changes no scanner behavior.**

## Two different graphs
- **Security Graph** — `scanner/webhound/graph/` ("Phase-20 Security Graph Engine").
  A **per-scan, runtime** evidence graph of one scan's findings/entities
  (deterministic; includes `THIRD_PARTY_DOMAIN` nodes). Owned by the scanner.
- **Knowledge Graph** — `corpus/graph/` (+ LightRAG). The **long-term** graph of
  sources/documents/chunks/entities/playbooks. Owned by the Knowledge Layer.

These are **separate stores** and stay separate.

## APPROVED relationship (later phase)
- **Read-only, one-way:** the Security Graph may **export read-only summaries** into
  the Knowledge Layer (corpus/knowledge) — e.g. "this scan saw third-party domain X
  / finding type Y" as evidence the Knowledge Layer can reason over.
- Direction is strictly **Security Graph → Knowledge Layer**. Exports are sanitized
  (no secrets, no customer-identifying data) and provenance-stamped.

## NOT approved (now or implied by this doc)
- The Knowledge Layer **changing scanner decisions** (what's a finding).
- The Knowledge Layer **changing severity** or **auto-suppressing** findings.
- The Knowledge Layer **controlling WADE** (baselines, drift, suppression).
- Any **write-back** from the Knowledge Layer into the runtime Security Graph or
  scanner pipeline.

Those capabilities are explicitly deferred. Phase 8 (knowledge enrichment) will, at
most, be **suggest-only** against findings — and even that is a separate approval.

## Phase-4 stance
No bridge code, no scanner/graph/WADE changes. This is the contract the later export
work must honor: **read-only, one-way, sanitized, provenance-stamped.**
