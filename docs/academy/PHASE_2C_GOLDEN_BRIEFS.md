# Phase 2C — Golden Lesson Design Program

**WebHound Enterprise Security Academy** · the 10 canonical reference Lesson Design Briefs for the SOX / ITGC / Audit foundation track.

> **Architecture is FROZEN at Academy Core v1.0.** This phase writes **briefs, not lessons** — no educational content, no academy/curriculum/graph/folder redesign. Each brief conforms to the Phase 2B Lesson Design Brief schema and **passes the gate validator**.
> **Governed by** Phase 0 (constitution), Phase 1 (`_graph/`), Phase 2A (`lesson-schema.ts`), Phase 2B (`lesson-brief-schema.ts`, `lesson-brief.schema.json`, `validate-brief.mjs`).
> **Files:** `apps/web/src/lib/academy/_content/golden-briefs/1-1-*.json … 1-10-*.json` (10 briefs). Validate all with `npm run academy:validate-golden`.

These briefs are the **permanent pattern**. Any future foundation lesson is authored by copying the nearest golden brief and adapting it; any new authoring tool is measured against them. They are reference implementations, deliberately richer than the minimum the schema requires.

---

## The set — 10 golden briefs

| # | Lesson | Maps to graph node | Real / scaffolded | Profile · Difficulty · ★Interview |
|---|--------|--------------------|-------------------|-----------------------------------|
| 1.1 | What Is an Enterprise? | `enterprise-business.foundations.intro.what-is-an-enterprise` | scaffolded (domain real) | concept-foundation · L1 · ★2 |
| 1.2 | Business Processes | `enterprise-business.foundations.processes.business-processes` | scaffolded (domain real) | concept-foundation · L1 · ★2 |
| 1.3 | Enterprise Risk | `risk.foundations.overview.enterprise-risk` | scaffolded (domain real) | concept-standard · L2 · ★3 |
| 1.4 | Internal Controls | `coso.foundations.controls.internal-controls` | scaffolded (domain real) | concept-standard · L2 · ★4 |
| 1.5 | Sarbanes–Oxley (SOX) | `sox.foundations.overview.what-is-sox` | **real leaf** | concept-standard · L2 · ★4 |
| 1.6 | IT General Controls | `itgc.foundations.overview.itgc-overview` | **real leaf** | concept-deep · L3 · ★5 |
| 1.7 | Active Directory Fundamentals | `active-directory.foundations.overview.ad-basics` | **real leaf** | concept-standard · L2 · ★4 |
| 1.8 | Test of Design | `audit-evidence.testing.tod-toe` | **real leaf** (ToD half) | control-audit · L3 · ★5 |
| 1.9 | Test of Operating Effectiveness | `audit-evidence.testing.tod-toe` | **real leaf** (ToE half) | control-audit · L3 · ★5 |
| 1.10 | Audit Evidence | `audit-evidence.foundations.evidence.what-is-audit-evidence` | scaffolded (domain real) | control-audit · L3 · ★4 |

Five briefs map to **real Phase 1 leaf nodes**; five map to **scaffolded leaves under real domains** (`enterprise-business`, `risk`, `coso`, `audit-evidence`). The validator confirms each scaffolded id sits under a real domain and emits an informational warning — it does not fail. **No graph file was modified.**

---

## Schema handling — did we extend the brief schema? Yes, additively.

The task's enriched dimensions (Mental Model, Educational Boundaries, Teaching Strategy, industry/audit context, advanced vocab, average-vs-exceptional interview answers, per-diagram complexity/objective) do not all fit the original 15 sections. Rather than overload existing fields or break the freeze, Phase 2C adds **one optional, backward-compatible field** to the brief:

- **`enrichment?`** (optional) on `LessonDesignBrief`, with sub-objects: `mentalModel`, `educationalBoundaries {inScope, outOfScope, deferredToFuture}`, `teachingStrategy {order, whyThisSequence, analogyPoints, mandatoryDiagramsAt}`, `industryContext[] {industry, scenario}`, `auditContext {internalAudit, externalAudit, compliance, executive}`, `vocabAdvanced[]`, `interviewAnswers {averageAnswer, exceptionalAnswer}`, `diagramDetail[] {kind, complexity, learningObjective}`.
- **`LabIntent`** widened additively with `'thought-exercise'` and `'case-study'` (all pre-existing values unchanged).

**Why this is not an architecture change:**
- `enrichment` is **optional**. Every brief written against the original schema — including `lesson-brief.example.json` — still validates unchanged (the validator emits a warning noting it is a legacy/minimal brief, then PASSes).
- The validator only checks enrichment **when present**; golden briefs include it in full, so they are held to the higher bar.
- The 15 core sections and their gates are **untouched**; enrichment sits *alongside* them, never replaces them.
- Widening an enum with new members is backward-compatible: existing values remain valid.

Updated files: `lesson-brief-schema.ts` (types), `lesson-brief.schema.json` (draft-07 mirror), `validate-brief.mjs` (enrichment gates + directory mode), `package.json` (`academy:validate-golden`).

Where the requested concepts live in the schema:
- **Mental Model** → `enrichment.mentalModel` (the one thing to remember in 5 years).
- **Educational Boundaries** → `enrichment.educationalBoundaries` (IN / OUT / deferred-to-future), reinforced by `purpose` and `misconceptions`.
- **Teaching Strategy** → `enrichment.teachingStrategy` (order + why + analogies + mandatory diagrams).
- **Enterprise/Industry Context** → `enrichment.industryContext` + the core `businessContext`/`enterpriseContext`.
- **Audit Context** → `enrichment.auditContext` (IA / EA / Compliance / Exec).
- **Interview Intelligence** → core `interviewIntel` + `enrichment.interviewAnswers` (average vs exceptional).
- **Vocabulary Intelligence** → core `vocabIntel` (core/supporting/business/audit/risk/acronyms/confused) + `enrichment.vocabAdvanced`.
- **Diagram Intelligence** → core `diagramNeeds` + `enrichment.diagramDetail` (complexity + per-diagram objective).
- **Lab Intelligence** → core `labIntel` with the widened intent vocabulary.
- **Cross-Lesson Intelligence** → core `crossLinks` (previous/future/related/domains/vocab/interviewTopics) + `prerequisites`.
- **Writing Guidance** → core `writingGuidance.instructions`.

---

## Validation

| Check | Command | Result |
|-------|---------|--------|
| All 10 golden briefs | `npm run academy:validate-golden` | **10/10 PASS** (each with only the scaffolded-node info warning where applicable) |
| Legacy 1.1 example (no enrichment) | `npm run academy:validate-brief` | **PASS** (warns enrichment absent — proves backward compatibility) |
| Graph undisturbed | `npm run academy:validate-graph` | **PASS (0 errors, 0 warnings)** |
| Types | `tsc --noEmit` | **clean** |
| Lint | `eslint` on `.ts`/`.mjs` | **clean** |

Per-brief: 1.1 ✅ · 1.2 ✅ · 1.3 ✅ · 1.4 ✅ · 1.5 ✅ · 1.6 ✅ · 1.7 ✅ · 1.8 ✅ · 1.9 ✅ · 1.10 ✅.

---

## FINAL CROSS-BRIEF REVIEW (brutally honest)

The test: do these 10 read like one textbook written by one expert, in the right order, with vocabulary defined before reuse, and could a competent author generate outstanding lessons from the briefs **alone**?

### Vocabulary progression — PASS (term defined before reuse)
The set builds a single, spiralling vocabulary. Each core term is introduced in exactly one lesson and reused downstream:

- **enterprise / department / value creation** — defined 1.1, reused 1.2+.
- **business process / control point / Segregation of Duties (SoD)** — defined 1.2; SoD then reinforced as a *risk response* (1.3), a *preventive control* (1.4), and an *access concern* (1.6, 1.7). One canonical definition (1.2); every later use is explicitly a reinforcement.
- **risk / inherent vs residual / appetite** — defined 1.3, reused by 1.4 (controls move inherent→residual) and 1.5 (risk of material misstatement).
- **control / objective / preventive-detective / key control / RCM / COSO (named)** — defined 1.4; RCM and key-control reused in 1.6, 1.8, 1.9.
- **SOX / ICFR / 302 / 404 / material weakness / PCAOB** — defined 1.5; material-weakness reused in 1.8 (design gap severity) and PCAOB in 1.10 (evidence scrutiny).
- **ITGC / application control / logical access / reliance / IPE** — defined 1.6 (IPE introduced precisely in 1.10 where it is needed and tied back to 1.6).
- **Active Directory / OU / security group / least privilege** — defined 1.7, reused as test subjects in 1.8–1.9.
- **ToD / walkthrough / design gap** — defined 1.8; **ToE / sample / population / attribute testing / exception** — defined 1.9; **audit evidence / sufficiency / appropriateness / reliability** — defined 1.10.

### Ordering vs graph prerequisites — PASS, with 3 documented, intentional deviations
The brief prerequisite chain is strictly linear (1.1→1.2→1.3→1.4→1.5→1.6→1.7→1.8→1.9, with 1.10 requiring the 1.8/1.9 node). Three places where the **track order deliberately differs from the raw graph**, each justified and documented (not a contradiction, because no graph edge is violated — the divergences concern *scaffolded* nodes or audience-appropriate prerequisite strength):

1. **Internal Controls (1.4) before SOX (1.5).** The graph sequences the *specific* COSO node `coso.framework.components.coso-five-components` **after** SOX (`coso-five-components` ⇽ `icfr` ⇽ `what-is-sox`). The golden 1.4 is the **generic** internal-control concept, mapped to a **distinct scaffolded node** `coso.foundations.controls.internal-controls`. Generic controls are genuinely more foundational than the law that mandates them, so 1.4 precedes 1.5; the deeper COSO-five-components lesson still comes later, honoring the graph edge. **No edge violated.**
2. **ITGC (1.6) prerequisites.** The graph's `itgc-overview` formally requires `icfr` + `coso-five-components`. The foundation track sets 1.6's required prerequisites to `what-is-sox` (1.5) + generic `internal-controls` (1.4) and lists `icfr` as recommended — the audience-appropriate foundations — while the deeper formal prerequisites are reached later in the curriculum.
3. **Active Directory (1.7) and DNS.** The graph's `ad-basics` *requires* `dns-overview`. This is an **engineer's** prerequisite. The audit foundation track treats AD conceptually (accounts/groups/lifecycle) and marks DNS **optional**, with explicit writing guidance "do not assume networking." Defensible: an IT auditor reasons about *who can access what*, not DNS replication.

### Structural notes (documented, intentional)
4. **1.8 and 1.9 share one graph node.** The graph has a single combined node `audit-evidence.testing.tod-toe`; the golden set splits it into two briefs (Test of Design, Test of Operating Effectiveness) because they are distinct, separately-interviewed skills and the pair is the spine of audit fieldwork. Both briefs reference the same `graphNodeId` — a 1→2 authoring enrichment, **not** a graph change.
5. **Audit Evidence (1.10) placed last.** "What is evidence" could arguably precede testing. It is positioned as the **capstone consolidation**: 1.8–1.9 generate evidence, and 1.10 then sets the sufficiency/appropriateness/reliability bar and ties reliability back to ITGCs (the IPE callback). Placing it last lets it unify the whole testing arc rather than front-loading an abstraction.

### Gaps & overlaps — none material
Every adjacent pair has a clean handoff and each brief's `educationalBoundaries.deferredToFuture` names what the next lesson covers, preventing scope creep:
- 1.3→1.4 (risk → the controls that treat it), 1.5→1.6 (law → the IT controls it relies on), 1.6→1.7 (logical access concept → its AD implementation), 1.8→1.9 (design → operation), 1.9→1.10 (testing → evidence quality). No two briefs teach the same thing; recurring terms (SoD, RCM) are deliberate **spiral reinforcement** from a single canonical definition, not overlap.

### Issue found and FIXED during review
- **1.5 (SOX) forward-referenced "ITGC" before 1.6 defines it.** The brief's industry/audit context used the acronym the learner doesn't have yet. **Fix applied:** added a writing-guidance instruction to 1.5 to introduce ITGC *only as a forward pointer to 1.6* and keep IT relevance at the "controls over the systems that hold financial data" level. Re-validated → still PASS.

### One-textbook verdict — YES
The 10 share one voice and one method: a recurring **manufacturing** worked example carried end-to-end, **WHY before HOW**, **business before technology**, acronyms defined at first use, no assumed networking, and a spiralling vocabulary. Difficulty rises smoothly (L1→L3) and Bloom climbs remember→understand→apply→analyze→evaluate. The intentional graph deviations are documented above so a future author knows they are choices, not mistakes.

### Could another author generate outstanding lessons from these briefs alone? — YES, for this track
Each brief specifies purpose, audience, measurable outcomes, the mental model, explicit in/out boundaries, a teaching order *with rationale*, where diagrams become mandatory and what each must show, realistic industry scenarios, the four audit views, average-vs-exceptional interview answers, and detailed writing guidance. That is enough for a competent author to write a strong, on-voice lesson without further direction. The residual dependency is the **shared voice corpus** (the Phase 2B critical review's recommendation 2C-1): these 10 briefs now *are* that corpus for the foundation track — they are the worked examples future authoring is calibrated against.
