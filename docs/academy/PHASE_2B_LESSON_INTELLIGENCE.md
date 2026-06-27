# Phase 2B — Lesson Intelligence Engine ("Author Brain")

**WebHound Enterprise Security Academy** · the design contract every lesson must pass *before* a single word of content is written.

> **Architecture is FROZEN at Academy Core v1.0.** This phase does **not** redesign the academy, modify curriculum, change the knowledge graph, reorganize folders, or touch routes/runtime. It adds an **upstream authoring layer**: the *Lesson Design Brief* — a planning artifact that decides **what a lesson must accomplish** before Phase 2A decides **what shape it takes**.
> **Governed by** Phase 0 (`PHASE_0_ACADEMY_CONSTITUTION.md`), Phase 1 (`PHASE_1_KNOWLEDGE_GRAPH.md`, `_graph/`), Phase 1.5 enums (`_graph/types.ts`), and Phase 2A (`PHASE_2A_CONTENT_ENGINE.md`, `_content/lesson-schema.ts`). **Reuses** existing enums — introduces **no** new vocabularies.
> **Implementable companion (standalone — not imported by routes):** `apps/web/src/lib/academy/_content/`
> · `lesson-brief-schema.ts` — typed `LessonDesignBrief` (15 sections) + `BRIEF_GATES`
> · `lesson-brief.schema.json` — JSON Schema (draft-07) mirror
> · `lesson-brief.example.json` — a complete, **passing** brief for Lesson 1.1 *"What Is an Enterprise?"*
> · `validate-brief.mjs` — the quality-gate validator (pure Node, `npm run academy:validate-brief`)

**Where the brief sits in the chain:** Graph Node → **Lesson Design Brief (Phase 2B)** → Lesson (Phase 2A `lesson-schema.ts`) → published content.
The brief answers *"what must this lesson accomplish, for whom, and why?"* The Phase 2A schema answers *"what is the shape of the finished lesson?"* One feeds the other: brief fields map directly onto `LessonMetadata`, `learningObjectives`, `difficulty`, `profile`, and the conditional-section triggers.

---

## Deliverable 1 — The Lesson Design Brief standard (15 sections)

Every section below is **mandatory in structure**. For each: its **purpose** and **what good looks like**. The machine-enforceable source of truth is `_content/lesson-brief-schema.ts`; this table is its human form.

| # | Section | Purpose | What good looks like |
|---|---------|---------|----------------------|
| 1 | **Lesson Identity** | Pin the lesson to the curriculum and the graph. `lessonId`, `graphNodeId`, Volume, Module, Chapter, Lesson title, Version. | `graphNodeId` resolves to a real graph node (or a scaffolded domain); `lessonId` follows `<domain>.<volume>.<chapter>.<slug>`; semver set. |
| 2 | **Purpose** | State *why this lesson exists* before any content. `whyExists`, `whyLearnerNeeds`, `futureDependents`, `businessProblem`. | A clear business/threat reason; names the downstream lessons that depend on it; not a restatement of the title. |
| 3 | **Target Audience** | Who this is for and at what level. `primaryRoles`, `level` (`Difficulty`). | Concrete roles (help-desk, IAM analyst, IT auditor, CISO), not "everyone"; level matches difficulty band. |
| 4 | **Prerequisite Knowledge** | What the learner must/should/could know first — **pulled from graph edges**. `required` / `recommended` / `optional` (graph node ids). | `required` ← `requires` edges, `recommended` ← `recommends`, `optional` ← `relatedTo`. Empty arrays only for genuine entry leaves. |
| 5 | **Learning Outcomes** | The measurable contract that drives assessment. Each: `verb`, `statement`, `bloom`. | 1–4 outcomes, each a Bloom **action** verb (never "understand"), each independently testable. |
| 6 | **Business Context** | Which business functions this serves. `departments`, `note`. | Names the real departments (Finance/HR/Manufacturing/IT/Security/Exec/Audit/Compliance) and *why they care*. |
| 7 | **Enterprise Context** | Where the concept lives and who is accountable. `whereItLives`, `owner`, `maintainer`, `auditor`. | Distinguishes **owner** (accountable) from **maintainer** (operates) from **auditor** (assures). |
| 8 | **Interview Intelligence** | Make the lesson interview-relevant. `probability` (★1–5), `likelyQuestions`, `traps`, `strongAnswerTraits`, `weakAnswerTraits`, `followUps`. | Real questions a hiring manager asks; named traps; what separates a strong from a weak answer. |
| 9 | **Vocabulary Intelligence** | The controlled terms the lesson teaches and reuses. `core`, `supporting`, `business`, `audit`, `risk`, `acronyms`, `commonConfusion`. | `core` non-empty; acronyms expanded; `commonConfusion` names the term pairs learners mix up. |
| 10 | **Misconception Intelligence** | Pre-empt the wrong mental models. List of `{misconception, correction}`. | Each misconception is one learners *actually* hold, with a crisp correction. |
| 11 | **Diagram Intelligence** | Decide visuals *by need*, not decoration. List of `{kind, why}` (`kind` ∈ Phase 2A `DiagramKind`). | Each diagram justified by the idea it makes concrete; or an explicit, justified empty list. |
| 12 | **Lab Intelligence** | Decide hands-on intent. `type` ∈ `none`/`guided`/`enterprise`/`scenario`/`capstone`, `why`. | `none` is a valid, justified choice for pure-concept lessons; otherwise the lab matches the difficulty. |
| 13 | **Cross-Link Intelligence** | Wire the lesson into the web of knowledge. `previous`, `future`, `related`, `domains`, `vocab`, `interviewTopics`. | Mirrors graph edges; `previous`/`future` enable continuity; lateral `related` aids navigation. |
| 14 | **Difficulty Intelligence** | Set effort and cognitive level. `bloom`, `difficulty` (`L1–L5`), `studyMinutes`, `readingMinutes`, `labMinutes`, `reviewMinutes`. | Bloom and difficulty agree; times are realistic and consistent with the profile and lab choice. |
| 15 | **Writing Guidance** | Steer the author's hand. `profile` (Phase 2A `LessonProfile`), `instructions`. | Profile drives Phase 2A conditional sections; instructions encode doctrine ("business before tech", "WHY before HOW"). |

---

## Deliverable 2 — Reusable schema + example (companion files)

- **TypeScript:** `lesson-brief-schema.ts` exports `LessonDesignBrief` and its 15 section interfaces, importing `Difficulty`, `BloomLevel`, `Volatility`, `Score1to5` from `_graph/types` and `LessonProfile`, `DiagramKind` from `lesson-schema` — **no duplicated enums**. It also exports `BRIEF_GATES` (the human list of gate rules).
- **JSON Schema:** `lesson-brief.schema.json` (draft-07) mirrors the TS shape for tooling/CI use.
- **Example:** `lesson-brief.example.json` — a complete brief for **Lesson 1.1 "What Is an Enterprise?"** (`graphNodeId: enterprise-business.foundations.intro.what-is-an-enterprise`). It is a genuine entry leaf (empty prerequisites), `concept-foundation` profile, and **passes all gates**.

---

## Deliverable 3 — The Lesson Generation Pipeline

The official, ordered path from graph to published lesson. Each stage has one job and a clear handoff.

| Stage | Input → Output | What happens |
|-------|----------------|--------------|
| **0. Graph Node** | `_graph/{nodes,edges}.json` | The node and its edges are the seed: id, domain, difficulty hints, `requires`/`recommends`/`relatedTo` neighbors. |
| **1. Lesson Design Brief** | Node → `LessonDesignBrief` | **Phase 2B.** Author (or generator) fills all 15 sections. Prerequisites/cross-links derive from edges. Decides outcomes, audience, vocab, diagrams, lab, voice. |
| **2. Quality Gates** | Brief → PASS/BLOCKED | **Phase 2B.** `validate-brief.mjs` runs. **BLOCKED stops the pipeline here.** Nothing downstream runs until the brief passes. |
| **3. Lesson Generation** | Brief → Phase 2A `Lesson` | Brief maps onto `lesson-schema.ts`: identity→`metadata`, outcomes→`learningObjectives`, `profile`→tiered `SECTION_RULES`, difficulty→`difficulty`. CORE + profile-selected sections are written. |
| **4. Diagram Generation** | `diagramNeeds` → `DiagramRef[]` | Only the diagrams the brief justified are produced; each anchored to the idea it explains. |
| **5. Lab Generation** | `labIntel` → lab section | Produced only if `labIntel.type !== 'none'`, at the intent level chosen. |
| **6. Flashcards** | `vocabIntel` + outcomes → `FlashcardItem[]` | Spaced-repetition cards drawn from the brief's controlled vocabulary and outcomes. |
| **7. Interview Questions** | `interviewIntel` → `InterviewItem[]` | Generated when `interviewIntel.probability ≥ 3` (aligns with Phase 2A's `interviewProb≥3` conditional). |
| **8. Knowledge Checks** | outcomes + misconceptions → `QuizItem[]` | Retrieval-practice items test the outcomes and target the named misconceptions. |
| **9. Review** | Lesson → reviewed Lesson | Editorial + factual review against `references`, `reviewBy`, and the brief's intent. |
| **10. Publish** | reviewed Lesson → live | Versioned, `reviewBy` set per `volatility`. |

**Reconciliation with the Phase 2A workflow:** Phase 2A already defines stages 3–10 (the lesson-shaping engine). Phase 2B inserts stages 1–2 **in front** of it and makes them a hard precondition. The brief is the missing "specification" step — Phase 2A turns a spec into a lesson; Phase 2B writes the spec.

---

## Deliverable 4 — Quality Gates (the block)

`validate-brief.mjs` is a pure-Node validator (no deps, no network, no app imports — same pattern as `_graph/validate.mjs`). It **exits non-zero** on any gate failure, so it can sit in CI or a pre-generation hook and *physically block* lesson generation on an incomplete brief.

**Run:** `npm run academy:validate-brief` (defaults to the 1.1 example) · `node src/lib/academy/_content/validate-brief.mjs <path>` for any brief.

**The gates** (all must pass):

1. `identity.graphNodeId` present (and resolves to a graph node, or a scaffolded domain → warning)
2. `purpose.whyExists` + `businessProblem` present
3. `purpose.futureDependents` is an array (empty ⇒ warning: confirm terminal leaf)
4. `prerequisites` has `required`/`recommended`/`optional` arrays
5. `outcomes` ≥ 1, each Bloom-verbed + measurable (literal "understand" verb **fails**)
6. `businessContext.departments` non-empty
7. `enterpriseContext` `owner`/`maintainer`/`auditor`/`whereItLives` present
8. `interviewIntel.probability` is an integer 1–5
9. `vocabIntel.core` non-empty
10. `diagramNeeds` ≥ 1, **or** empty with a warning to confirm
11. `labIntel.type` is a valid intent
12. `difficultyIntel` has valid `bloom` + `difficulty` + non-negative times (`studyMinutes` ≥ 1)
13. `writingGuidance.profile` valid + ≥ 1 instruction

**Result on the 1.1 example:** `✓ PASS — all quality gates satisfied. Lesson generation unblocked.` (exit 0), with one informational warning that the leaf node is not yet enumerated under the real `enterprise-business` domain (scaffolded — acceptable). A deliberately broken copy of the brief was confirmed to exit **1** with the failing gates named.

---

## Deliverable 5 — Critical Review: can an AI now write like one expert over years?

**Honest verdict: the brief is necessary but not yet sufficient.** It guarantees *coverage and structure* — every lesson will now plan its audience, outcomes, vocab, misconceptions, and voice before being written, which alone eliminates the most common failure (mechanically-correct but contextless lessons). What it does **not** yet guarantee is the *felt continuity of a single expert author across 5,000 lessons*. Five concrete gaps:

1. **Voice & style are under-specified.** `writingGuidance` captures per-lesson intent but there is no Academy-wide **voice/style guide** and no **few-shot exemplar corpus** of "this is how a WebHound lesson reads." Without shared exemplars, tone drifts lesson-to-lesson and author-to-author.
2. **Cross-lesson continuity is by id, not by memory.** `crossLinks.previous`/`futureDependents` reference *ids*, but the generator can't actually *recall what the prior lesson said*. True continuity ("as we saw in 1.1…") needs the **prior lesson's summary embedded in the brief**, not just its id.
3. **Briefs are hand-authored — that does not scale to 5,000.** Today a human writes each brief. To cover the full graph, briefs must be **auto-generated from the graph** (edges → prerequisites/cross-links, node metadata → difficulty/interview probability) and then human-refined. Otherwise Phase 2B becomes the bottleneck it was meant to remove.
4. **No factual-accuracy / freshness loop.** `volatility` + `reviewBy` exist on the brief but nothing *enforces* re-review when a `volatile` topic ages, and nothing checks claims against `references` at generation time. Expert authors keep content current; the engine currently can't.
5. **No anti-repetition / contradiction check.** Nothing compares a new lesson against already-published lessons, so the corpus can drift into repetition or self-contradiction — the opposite of "one expert who remembers everything they wrote."

### Recommended Phase 2C improvements

- **2C-1 Voice corpus:** add a `VOICE_GUIDE.md` + 3–5 gold-standard exemplar lessons; feed them as few-shot context to every generation.
- **2C-2 Embedded continuity:** extend the brief with a `priorSummaries: {nodeId, summary}[]` field auto-filled from published upstream lessons, so the generator writes *with memory*.
- **2C-3 Brief auto-generation:** a `generate-brief.mjs` that emits a draft brief from a graph node (prerequisites/cross-links from edges, difficulty/interview from node metadata) for human refinement — turning Phase 2B from hand-craft into scalable scaffolding.
- **2C-4 Freshness loop:** a `reviewBy`-driven report (and CI gate) that flags overdue `volatile`/`stable` lessons, plus a generation-time claims-vs-`references` check.
- **2C-5 Retrieval de-dup:** before publish, retrieve the N nearest published lessons (the brain/HNSW index already exists) and check the draft for repetition/contradiction.

Net: with the brief + gates in place, an AI can now produce **consistently complete, contextual, interview-aware** lessons. To make them feel authored by **one expert over years**, Phase 2C must add **shared voice, embedded memory, auto-scaffolding, freshness enforcement, and corpus-level de-duplication**.
