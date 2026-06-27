# Academy Master Knowledge Graph — `_graph/`

Machine-readable population of the structures defined by the Phase 0 constitution
(`docs/academy/PHASE_0_ACADEMY_CONSTITUTION.md`). Human narrative lives in
`docs/academy/PHASE_1_KNOWLEDGE_GRAPH.md`.

## Files
- `domains.json` — the complete domain set (62), grouped, with Phase-1 additions flagged.
- `nodes.json` — graph nodes: domain nodes + **leaf concept** nodes with full Phase-0-superset metadata.
- `edges.json` — typed edges (`requires` / `recommends` / `reinforces` / `relatedTo`).

## Enumerated vs scaffolded (honest, per Phase 0 anti-bloat doctrine)
- **Fully enumerated to leaf depth (status `enumerated`):** three exemplar verticals —
  (1) `identity → authentication → kerberos → kdc → tgt → service-ticket → pac → kerberos-attacks`,
  (2) `sox → icfr → coso → itgc → logical-access/provisioning/access-reviews → audit-evidence (ToD/ToE → samples → exceptions) → itgc-sox-testing`,
  (3) `networking → ip → dns → dns-srv → active-directory → dc-locator`.
- **Scaffolded (`scaffolded` / `enumerated-partial`):** all other domains exist as domain nodes;
  their Module→Chapter→Lesson decomposition is described in the Phase 1 doc tree and is
  **generated to leaf depth later** using the pattern below — NO structural redesign required.

## Machine-enforceable pattern (so the rest can be generated safely)
A future leaf-generation pass MUST, for each new concept node, satisfy these invariants
(enforceable by a validator script — the same checks already run in Phase 1 validation):
1. `id` matches `<domain>.<volume>.<chapter>.<slug>`, kebab, unique, never reused.
2. `domain` ∈ `domains.json`; `difficulty` ∈ L1..L5; `bloom` ∈ the Phase 0 verb set.
3. Every `prereq`/edge endpoint resolves to an existing node or domain id (no dangling).
4. The `requires` subgraph stays **acyclic** (DAG) — a cycle is a content-design bug.
5. `outcomes` use Bloom verbs and meet the difficulty Bloom-floor (Phase 0 §21/§22).
6. Required fields present (see `nodes.json.fieldSemantics`); `volatility` + `reviewBy` set.
7. No published node is an orphan (reachable from some volume/track).

## Validation
Run the Phase 1 checks (JSON parse + endpoint resolution + `requires` cycle check):
the script is documented in `docs/academy/PHASE_1_KNOWLEDGE_GRAPH.md` §9. Last run:
**62 domains · 41 nodes (30 leaf concepts) · 42 edges (35 requires) · 0 unresolved · 0 cycles.**
