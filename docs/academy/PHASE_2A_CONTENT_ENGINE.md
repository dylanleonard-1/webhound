# Phase 2A — Educational Standards & Content Generation Engine

**WebHound Enterprise Security Academy** · the permanent publishing standard every future lesson conforms to.

> **Architecture is LOCKED.** This phase does **not** redesign the academy, reorganize curriculum, rename volumes/phases, or change the knowledge graph/routes. It defines the **engine** — the rules, schema, and workflow that turn a Phase 1 graph node into a publishable lesson — not lessons themselves.
> **Governed by** Phase 0 (`PHASE_0_ACADEMY_CONSTITUTION.md`) + Phase 1 (`PHASE_1_KNOWLEDGE_GRAPH.md`, `_graph/`). **Reuses** Phase 1.5 enums/types (`_graph/types.ts`).
> **Implementable companion:** `apps/web/src/lib/academy/_content/` — `lesson-schema.ts` (typed `Lesson` + tiered `SECTION_RULES`), `lesson-template.json` (blank), `lesson-example.template.json` (filled example, **not** real content). Each lesson links to its graph node via `graphNodeId`.

---

## Deliverable 1 — Lesson Generation Standard (the 46-section template)

The lesson is the atom (Phase 0 §8). The Academy defines **46 sections** (metadata + 45 content sections). **Critically — and this is the headline of the readiness review (Deliverable 10) — not all 46 are required on every lesson.** They are tiered: **CORE** (always), **RECOMMENDED** (unless a reason not to), **CONDITIONAL** (only when the section's rule is met, driven by the lesson `profile`). The machine-readable registry is `_content/lesson-schema.ts → SECTION_RULES`; the table below is its human form.

**For every section: `why` it exists · `omit-when` · `quality` bar · `depth` · `example`.** (Condensed; the schema file is the enforceable source.)

### CORE sections (every published lesson, L1–L5)
| Section | Why | Omit when | Quality bar / depth | Good example |
|--------|-----|-----------|----------------------|--------------|
| **metadata** | machine-routability, graph link, lifecycle | never | all required fields valid; `graphNodeId` resolves; semver+reviewBy set | the typed header in `lesson-example.template.json` |
| **learningObjectives** | the contract; drives assessment | never | 1–4, Bloom-verbed, meet difficulty Bloom-floor; no "understand X" | "Differentiate authN from authZ in an enterprise access flow." |
| **whyThisExists** | WHY-before-HOW doctrine (Phase 0 §0.4) | never | 1 paragraph; states threat-model/business reason | "Mixing authN/authZ causes real access-control failures…" |
| **coreConcept** | the one core idea (Phase 0 one-idea rule) | never | exactly one idea, chunked; dual-coded if structural | "AuthN first (who?), then authZ (what may you do?)." |
| **definitions** | reduce extraneous load | never | every new term defined before use | concise, source-anchored definitions |
| **vocabulary** | controlled terms (Phase 0 §9) | never | glossary-linked; acronyms expanded | links to canonical glossary entries |
| **knowledgeCheck** | retrieval practice / testing effect | never | ≥2 low-stakes recall items with rationale | "Which comes first, authN or authZ?" |
| **commonMisunderstandings** | jargon-danger field | never | ≥1; names the confusion explicitly | "MFA is authZ → no, MFA strengthens authN." |
| **chapterSummary** | consolidation | never | compresses the idea + "what this unlocks" | 2–3 sentences |
| **relatedLessons** | navigation; from graph edges | never | derived from `related/reinforces` edges | links to graph node ids |
| **references** | accuracy/trust (Phase 0 §17) | when no factual claims | authoritative sources only (NIST/ISO/PCAOB/vendor) | "NIST SP 800-63" |
| **revisionHistory** | versioning (Phase 0 §18/§19) | never | semver entries + reviewBy | "0.1.0 — initial" |

### RECOMMENDED sections
| Section | Why | Omit when | Depth |
|--------|-----|-----------|------|
| **executiveSummary** | fast orientation for busy learners | tiny L1 atoms | 2–4 sentences |
| **flashcards** | spaced repetition (Phase 0 §12.4) | rarely | 3–8 cards |

### CONDITIONAL sections (rule-driven by `profile`/band/domain)
`howItWorks` (mechanism exists, most L2+) · `enterpriseArchitecture` (structural; concept-deep/procedure) · `enterpriseWorkflow` (process/lifecycle; procedure/control-audit) · `historicalBackground` (when history aids; e.g. SOX, Kerberos) · **industry examples** `exampleMicrosoft/LinuxOSS/Cloud/Manufacturing/Financial/Healthcare/Government` (**pick the 1–3 RELEVANT, never all seven**) · **perspectives** `Security/Governance/Risk/Audit/Operations/Leadership` (**include the relevant ones, not all six by rote**) · `commonMistakes`/`bestPractices` (most L2+) · `realWorldCaseStudy` (required L3+; may reuse a shared case study) · `enterpriseChecklist` (procedure/control-audit) · `auditChecklist`/`evidence` (required control-audit) · `implementationWalkthrough` (required procedure) · `monitoring`/`validation` (when verifiable) · `handsOnLab`/`practicalExercise` (required when graph node `lab=true`) · `reflectionQuestions` (L2+) · `scenarioExercise`/`whiteboardExercise` (required L3+ / design concepts) · `interviewQuestions` (required when node `interviewProb≥3` OR difficulty≥L3).

Each conditional section's exact rule is in `SECTION_RULES`; each profile's default conditional set is in `PROFILE_DEFAULT_SECTIONS`.

## Deliverable 2 — Diagram Standards

Aligns with Phase 0 §10 (diagram-as-code, fixed visual grammar, alt text, durability-first). Eleven kinds, each with purpose / required elements / when-not-to-use:

| Kind | Purpose | Required elements | When NOT to use |
|------|---------|-------------------|-----------------|
| **architecture** | component/system structure | components, trust boundaries, data stores, labeled connections | for a pure sequence (use process-flow) |
| **process-flow** | ordered steps | start/end, steps, decisions, direction | for static structure |
| **network** | topology | zones/segments, devices, links, boundaries | for app logic |
| **identity-flow** | authN/authZ exchanges | actor, IdP/KDC, resource, token/ticket hops | for org structure |
| **timeline** | events over time | axis, events, durations (RTO/RPO, incident) | for non-temporal relationships |
| **risk-matrix** | likelihood × impact | axes, cells, plotted risks | for process |
| **control-matrix** | risk→control→test mapping | rows (risk), cols (control/test/evidence) | for flow |
| **decision-tree** | branching choices | root, conditions, leaves | for parallel flows (use swimlane) |
| **audit-workflow** | audit lifecycle | phases, control owner/auditor lanes, evidence points | for technical data flow |
| **enterprise-data-flow** | data movement (DFD) | external entities, processes, stores, trust boundaries | for physical topology |
| **swimlane** | cross-actor responsibility | lanes per actor/dept, handoffs | single-actor procedures |

**Style/color/naming (house grammar):** consistent shapes (actor=rounded, system=rect, data-store=cylinder, trust-boundary=dashed); color from Phase 0/WebHound tokens, **never color-only meaning** (accessibility); diagram ids `<kind>.<lesson-slug>.<n>`; sources are diagram-as-code (Mermaid) committed under `_content/diagrams/<domain>/…`; every diagram has a caption + `altText`.

## Deliverable 3 — Lab Standards

Per Phase 0 §11. Required structure (the `handsOnLab`/`practicalExercise` sections render this): **objective · prerequisites · required environment · safety/blast-radius class · enterprise scenario · step-by-step · validation ("how you know you succeeded") · troubleshooting · cleanup · reflection · enterprise discussion.**
- **Safety classes:** `conceptual` (paper/spreadsheet — like the existing PCA labs), `sandboxed` (isolated VM/cloud sandbox), `live-but-consented` (only systems the learner controls — mirrors WebHound's consent ethic). **Never** unauthorized action against third-party systems; offensive technique only in sandboxes with an ethics/legal preface.
- **Faded guidance:** worked → completion → independent across a chapter (Phase 0 §13).
- **Difficulty & grading:** lab difficulty tracks the lesson band; graded by **objective validation checks** (declarative, self-verifying) + a rubric for open-ended steps. Reproducible/declarative environments preferred so labs survive and self-grade at scale.

## Deliverable 4 — Quiz Standards

Per Phase 0 §12 (formative-first, outcome-aligned, Bloom-matched). Encoded in `QuizItem` (`type`, `bloom`, `prompt`, `answer`, `rationale`, `outcomeRef`).
- **Types:** recall · multiple-choice · multi-select · scenario · short-answer.
- **Difficulty distribution (per lesson knowledge-check):** ~50% at-level, ~30% one below (reinforce prereqs), ~20% one above (stretch). Summative chapter/volume quizzes weight toward at-level + scenario.
- **Bloom mapping:** item Bloom must match the outcome it tests — **forbid testing Analyze/Evaluate outcomes with recall MCQs** (Phase 0 §12.3).
- **Explanations:** every item has a rationale (right *and* wrong) — feedback is the learning.
- **Scoring/thresholds:** formative = ungated practice; summative gate = **≥80%** to advance, with mastery defined as also passing the scenario item(s); `outcomeRef` guarantees coverage (every outcome ≥1 item; no orphan items).
- **Review:** spaced re-surfacing of missed items (ties to flashcards).

## Deliverable 5 — Flashcard Standards

Encoded in `FlashcardItem`: **front · back · difficulty · tags · memoryAid · commonConfusion · related (cross-refs)**.
- Front = a single retrieval prompt; back = the crisp answer (no essays).
- `commonConfusion` captures the trap (e.g. "SOC = System and Organization Controls, not Security Operations Center").
- `related` links graph node/glossary ids for elaboration and graph-aware review.
- Spaced-repetition scheduled (Phase 0 §12.4). 3–8 cards/lesson typical.

## Deliverable 6 — Interview Standards

Every lesson that qualifies (node `interviewProb≥3` or difficulty≥L3) generates interview material — `InterviewItem`: **category (hr/technical/scenario/whiteboard/behavioral) · question · strongAnswer · weakAnswerExample · followUps**.
- **STAR** for behavioral (Situation-Task-Action-Result) in the strong answer.
- **Strong-answer rubric:** correct + concise + states the *why* + honest about uncertainty + audience-appropriate (dual-audience, Phase 0 §2).
- **Weak-answer examples** are included deliberately so learners recognize the anti-pattern.
- **Follow-ups** model the interviewer pushing deeper. (This generalizes the existing `/academy/pca-risk` interview prep to every lesson.)

## Deliverable 7 — Case Study Standards

`realWorldCaseStudy` (and shared studies under `_content/case-studies/`): **company background · business problem · technical environment · timeline · decisions made · risks · controls · outcome/lessons learned · discussion questions.**
- Realistic but **fictional-or-sanitized** (no fabricated attribution of real breaches without citation).
- **Shareable:** a case study can be authored once and referenced by multiple lessons (a SOX-failure case feeds ITGC, change-mgmt, and audit-evidence lessons) — avoids per-lesson duplication and maintenance cost.
- Ends in discussion questions tied to the lesson's outcomes.

## Deliverable 8 — Content Quality Standards (measurable)

Per Phase 0 §15–§17. **Measurable gates** (lint-enforceable):
- **Reading level:** working-professional (≈ Grade 10–13 Flesch-Kincaid); flag jargon walls.
- **Explanation depth:** core concept ≥ a defined minimum; no "stub" published.
- **Vocabulary completeness:** every domain term glossary-linked; acronyms expanded on first use.
- **Diagram requirement:** structural/relational concepts **must** have ≥1 diagram with alt text.
- **Cross-links:** `relatedLessons` non-empty and resolves to graph nodes.
- **Citations:** factual claims sourced to authoritative refs.
- **Technical accuracy:** passes technical review against sources/environment.
- **Enterprise realism:** examples reflect real enterprise practice, not toy scenarios.

**Content review checklist:** WHY present · objectives Bloom-valid at band · one core idea · CORE sections present · conditional sections match profile rule · ≥2 retrieval items · diagram if structural (alt text) · lab+validation if node `lab=true` · vocabulary glossary-linked · citations + `reviewBy`/`volatility` · `graphNodeId` resolves · passes technical + educational review.

## Deliverable 9 — Lesson Generation Workflow

The pipeline (ties to Phase 0 §16 editorial, §20 publishing, §18 version control):

```
Graph Node (Phase 1)
  → Draft            (author fills the schema for the node's profile)
  → Technical Review (accuracy vs sources/environment — Phase 0 §17)
  → Educational Review (clarity, objectives/Bloom, structure, load — §15)
  → Diagram Review   (grammar, alt text, durability — §10)
  → Lab Review       (safety class, validation checks, reproducibility — §11)
  → Interview Review (rubric, weak-answer realism — Del. 6)
  → Final QA         (automated: schema valid, CORE sections present, graphNodeId
                      resolves, outcomes meet Bloom-floor, links resolve, quiz
                      outcomeRefs valid, diagram alt text present)
  → Publish          (status→published; merge→build→deploy, same CI/CD as the app)
  → Revision Tracking (reviewBy/volatility queue drives re-review — §19)
```
Each stage records who/when/verdict on the lesson; nothing publishes without technical + educational review **and** the automated Final-QA gate. Solo/AI-assisted reality: drafting can be AI-accelerated into the schema; the **review gates are the human-governed quality guarantee** (and several can be tooling-automated — Final QA especially).

## Deliverable 10 — Phase 2 Readiness Review (challenged, not rubber-stamped)

**Verdict: READY to begin lesson authoring — but ONLY with the tiered template below.** Approving a literal "all 46 sections for every lesson" rule would be a mistake.

### Key challenge 1 — the 46-section template bloats simple lessons (the big one)
A rigid 46-section requirement would force an L1 atom like "AuthN vs AuthZ" to carry seven industry examples, six stakeholder perspectives, a case study, a whiteboard exercise, audit checklists, and evidence sections — producing shallow filler, crushing production throughput, and **directly violating Phase 0's anti-bloat doctrine (§0.6) and one-idea rule (§8)**.

**Proposal (encoded in `lesson-schema.ts`): tiered, profile-based sections.**
- **CORE (12, always):** metadata, learningObjectives, whyThisExists, coreConcept, definitions, vocabulary, knowledgeCheck, commonMisunderstandings, chapterSummary, relatedLessons, references, revisionHistory.
- **RECOMMENDED (2):** executiveSummary, flashcards.
- **CONDITIONAL (32):** included only when the section's `rule` fires, driven by the lesson **`profile`** (`concept-foundation`/`concept-standard`/`concept-deep`/`procedure`/`control-audit`/`leadership`), the **difficulty band**, and **graph metadata** (`lab`, `interviewProb`).
- **The rule for choosing:** start from `PROFILE_DEFAULT_SECTIONS[profile]`, then apply each conditional section's `rule` (e.g. add `handsOnLab` iff the graph node has `lab=true`; add `auditChecklist`+`evidence` iff `profile=control-audit`; pick the **1–3 relevant** industry examples, not all seven; include only the **relevant** perspectives). Result: an L1 atom ships ~14 sections; an L3 control-audit lesson ships ~25; nothing ships 46-by-rote.

### Other gaps surfaced (honest)
- **Accessibility:** added as a hard requirement — alt text on every diagram, no color-only meaning, keyboard/screen-reader-friendly rendering (Phase 0 §28). Encoded via `DiagramRef.altText` (required field).
- **Localization:** content is separated from presentation (typed records), so i18n is additive later; **flagged as out-of-scope for 2A** but unblocked.
- **Reusable diagram source format:** standardized on **diagram-as-code (Mermaid)** committed under `_content/diagrams/` — versionable, reviewable, durable (vs screenshots).
- **Shared vs per-lesson case studies/labs:** case studies and labs are **shareable artifacts** (authored once under `_content/case-studies/` & `_content/labs/`, referenced by many lessons) — prevents duplication and halves maintenance.
- **Review-staffing realism (solo/AI-assisted):** the seven review stages are unrealistic as seven *people* for a solo author. Resolution: collapse to **(a) automated Final-QA gate** (does most structural checking), **(b) one technical pass**, **(c) one editorial pass** — AI may draft and even pre-review, humans sign off. The pipeline stages remain as *checks*, not mandatory separate staff.
- **Quiz answer leakage:** committing answers in JSON is fine for authoring/repo but the renderer must not ship answers to the client pre-submission — **flagged for the Phase 2B renderer**, not a content concern.

### Conclusion
With the tiered template, shareable artifacts, accessibility baked in, and a realistic 3-gate review, the Academy is ready to author lessons at quality **and** at sustainable throughput. The engine — not heroics — is what will keep thousands of future lessons consistent and correct.

---

## Appendix — files added this phase
- `apps/web/src/lib/academy/_content/lesson-schema.ts` — typed `Lesson` + `SECTION_RULES` + `LessonProfile` + sub-models (reuses `_graph/types.ts`).
- `apps/web/src/lib/academy/_content/lesson-template.json` — blank skeleton.
- `apps/web/src/lib/academy/_content/lesson-example.template.json` — filled example (template, not real content).
- `apps/web/src/lib/academy/_content/README.md` — how to author.
- This document.

*Phase 2A builds the press, not the books. Every Phase 2B+ lesson is poured into this mold — tiered so simple stays simple, rigorous so nothing important is skipped.*
