# Golden Lesson Certification Checklist

**WebHound Enterprise Security Academy — permanent publication gate.**

Every lesson MUST pass **all P1 items** and have **no unresolved P2 items** before it may be certified "Golden Lesson Reference." Derived from the Phase 0 constitution, the Phase 2A content engine, and the Lesson 1.1 editorial review. Items marked **[machine]** can be checked by a script (the validator pattern in `_content/`); items marked **[editor]** require human editorial judgment.

A lesson is **certifiable** only when:
1. every **P1** box is checked, and
2. every **P2** box is checked or has a written, accepted waiver in the lesson's editorial review, and
3. a senior-editor publication verdict (§F) is recorded.

Priorities: **P1** blocks certification · **P2** must be resolved or waived · **P3** quality polish.

---

## A. Schema & structural conformance

- [ ] **A1 [machine] P1** — Lesson JSON parses and conforms to `lesson-schema.ts` (`Lesson` interface); a no-cast tsc structural check passes.
- [ ] **A2 [machine] P1** — All 12 CORE sections present (`metadata` satisfied by the top-level object; the other 11 present in `sections[]`). `CORE_SECTIONS` ⊆ lesson.
- [ ] **A3 [machine] P1** — Every `sections[].key` is a valid `SectionKey`; no duplicates.
- [ ] **A4 [machine] P2** — Section set matches the declared `profile` (core + recommended + only-justified conditionals); no all-46 bloat.
- [ ] **A5 [machine] P1** — `metadata.graphNodeId` is set; resolves to a real graph node, or to a scaffolded leaf under a real domain (documented).
- [ ] **A6 [machine] P1** — `metadata` complete: id, title, domain, difficulty, bloom, profile, estMinutes, version (semver), status, authors, reviewBy (ISO date), volatility.
- [ ] **A7 [machine] P2** — `tsc --noEmit` and `eslint` clean on any TS touched; `npm run academy:validate-golden` and `academy:validate-graph` still PASS.

## B. Pedagogy (Phase 0 doctrine)

- [ ] **B1 [editor] P1** — **WHY before HOW**: the lesson motivates the concept before mechanics (`whyThisExists` is substantive, not a restated title).
- [ ] **B2 [editor] P1** — **One core idea** (`coreConcept`) — a single, clearly stated mental model the learner keeps.
- [ ] **B3 [machine] P1** — `objectives` are 1–4, each Bloom-verbed and measurable; **no "understand X"** as a verb.
- [ ] **B4 [machine] P1** — `quiz` has ≥2 retrieval items; **every** `quiz[].outcomeRef` traces to a stated objective (no orphan items).
- [ ] **B5 [editor] P2** — Bloom level of objectives/quiz is consistent with `metadata.difficulty`.
- [ ] **B6 [editor] P2** — `commonMisunderstandings` names ≥1 real misconception with a correction.
- [ ] **B7 [editor] P3** — Cognitive load managed: dense sections chunked with sub-headings; one analogy carried, not many competing.

## C. Vocabulary & accuracy

- [ ] **C1 [editor] P1** — **Define before use**: every term and loaded everyday word (e.g. "control") is glossed or defined at first use; nothing assumes unstated knowledge.
- [ ] **C2 [editor] P1** — **No term owned by a later lesson** is used as if known (respect the curriculum vocab progression; forward-pointers are allowed only as explicit "you'll learn this later").
- [ ] **C3 [machine] P2** — Every glossary/`vocabulary` term is either defined in `definitions` or glossed inline; no term is merely named.
- [ ] **C4 [machine] P1** — Every acronym is expanded at first use.
- [ ] **C5 [editor] P1** — No factual or technical errors; simplifications are flagged, not stated as absolutes.
- [ ] **C6 [editor] P2** — Security/audit/governance/risk statements are accurate and map to recognized frameworks (e.g. COSO, Three Lines) where relevant.

## D. Business realism & context

- [ ] **D1 [editor] P1** — Concepts are tied to a concrete business reason; a reader could state "why this matters to the business."
- [ ] **D2 [editor] P2** — Industry examples are realistic and, where a real company is referenced, **public and generic only** — no invented confidential processes.
- [ ] **D3 [editor] P3** — A recurring worked example is carried through and reused across lessons for continuity.

## E. Assets, craft & accessibility

- [ ] **E1 [machine] P1** — Every `diagrams[]` entry has `kind` (valid `DiagramKind`), `title`, `altText`, and a versionable `src`.
- [ ] **E2 [editor] P2** — Each diagram has a production-ready spec (purpose · learning objective · caption · implementation description) in the companion doc.
- [ ] **E3 [editor] P3** — Diagram artwork rendered from `src` (or explicitly noted as a pending downstream step in the verdict).
- [ ] **E4 [editor] P1** — Alt text is descriptive and conveys the diagram's meaning (Phase 0 §28), not just its title.
- [ ] **E5 [editor] P2** — Consistent voice, tense, and terminology throughout; abbreviations anchored at first co-location.
- [ ] **E6 [editor] P2** — Beginner-appropriate to the declared level; tone welcoming; no unstated prerequisite knowledge (e.g. no assumed networking for a business-foundation lesson).
- [ ] **E7 [machine] P1** — `references` lists authoritative sources for factual claims; `revisionHistory` records semver + `reviewBy`.
- [ ] **E8 [editor] P3** — A lab/exercise appropriate to the level reinforces understanding (thought-exercise at L1; hands-on where the node has `lab=true`).
- [ ] **E9 [editor] P2** — Interview prep (when present) gives strong vs weak answers and a path to an exceptional answer.

## F. Source-consistency & verdict

- [ ] **F1 [editor] P1** — Faithful to the lesson's **golden brief** (mental model, outcomes, boundaries, writing guidance).
- [ ] **F2 [editor] P1** — Consistent with the **constitution** (Phase 0) and the **content engine** (Phase 2A) rules.
- [ ] **F3 [machine] P1** — Does **not** modify the knowledge graph, curriculum, or architecture.
- [ ] **F4 [editor] P1** — A senior-editor **publication verdict** is recorded against a recognized bar (Cisco Press / Microsoft Learn / SANS / O'Reilly): pass, or an explicit gap list.
- [ ] **F5 [editor] P1** — If certified, the stamp is recorded in `metadata.certification` + `metadata.status` + `revisionHistory`, and the certification scope (and any pending production steps) is stated honestly.

---

## How to use

1. Run the machine checks (`academy:validate-golden`, `academy:validate-graph`, `tsc`, `eslint`, and the lesson conformance check).
2. A senior editor works the **[editor]** items and writes per-category notes (see `LESSON_1_1_EDITORIAL_REVIEW.md` as the worked template).
3. Resolve all P1; resolve or waive all P2 (waivers written into the review).
4. Record the publication verdict (§F4).
5. Certify only if genuinely earned — **do not auto-certify**. A weak lesson stays uncertified with a gap list.

## Certification register

| Lesson | Version | Status | Certified | Notes |
|--------|---------|--------|-----------|-------|
| 1.1 What Is an Enterprise? | 1.1.0 | published | ✅ Golden Lesson Reference v1.0 | Diagram artwork rendering pending (specs complete). Tag `golden-lesson-v1.0` on #44 merge. |
