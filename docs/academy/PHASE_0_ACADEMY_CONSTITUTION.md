# Phase 0 — The Academy Constitution

**WebHound Enterprise Security Academy** · *The Complete Enterprise Cybersecurity University*

> **Document status:** Foundational / governing. This is the operating-system document for the Academy. It defines **architecture, standards, and process** — it contains **no lesson content**. Every future volume, chapter, lesson, lab, assessment, and capstone is subordinate to this document. Where a future artifact conflicts with Phase 0, Phase 0 wins until Phase 0 is formally amended (see §19 Revision Workflow).
>
> **Audience:** curriculum architects, authors, technical reviewers, editors, and the tooling that ingests/renders content.
> **Companion implementation:** the live academy already stores content as **typed TypeScript data records** under `apps/web/src/lib/academy/...`. Phase 0’s machine-usable sections (§25–§29, Appendices) define the schema those records evolve into.
> **Version:** 1.0.0 · **Applies to:** all subject domains listed in the Scope Charter (§5.1).

---

## How to read this document

The constitution is organized into seven parts plus a deliberately-placed **Part 0** that argues with the brief before accepting it. Each of the 30 mandated sections answers five questions in prose, not bullet-skeletons:

1. **Why** the standard exists (the failure it prevents).
2. **How world-class universities** handle it (MIT, CMU, Stanford, Harvard).
3. **How enterprise training** handles it (Microsoft Learn, Cisco Networking Academy, SANS, ISC², Fortune-500 onboarding, military training pipelines).
4. **Why our approach is superior** (or at least deliberately chosen, with tradeoffs).
5. **How it scales to thousands of lessons** without collapsing under its own weight.

A reader should be able to open any section, understand the principle, and immediately know what it means for the file they are about to author.

---

# PART 0 — Recommended Architecture & Where We Diverge From the Brief

The brief asks for "the most comprehensive enterprise cybersecurity university ever," organized into linear **Volumes → Chapters → Lessons**, governed by 30 standards. That is a strong instinct, and most of it is right. But "most comprehensive ever" is also the single most dangerous phrase in curriculum design, and a constitution that simply nods along would be malpractice. This part states the Academy’s strongest architectural opinions and is binding on the sections that follow.

### 0.1 Diverge: a **competence graph**, not a linear bookshelf

The implied model — Volume 1, Chapter 1, Lesson 1, read in order — is how a *textbook* is printed, not how *expertise* is built. Linear ordering assumes one true path through knowledge. Enterprise security has many: an auditor, a SOC analyst, a cloud engineer, and a GRC lead share a core but diverge fast.

**Decision:** the canonical data model is a **directed acyclic competence graph** (§24). Lessons declare prerequisites; "volumes" and "tracks" are *views* over the graph, not the substrate. We still publish ordered reading paths (humans want a path), but the path is a curated traversal of the graph, not the source of truth. This is how Khan Academy’s knowledge map, Carnegie Mellon’s cognitive-tutor mastery model, and competency-based programs (Western Governors University) actually work — and it is strictly more flexible than a bookshelf. Tradeoff: graphs are harder to author and require tooling to prevent cycles and orphans (§24 makes this enforceable).

### 0.2 Diverge: **mastery-based progression**, not seat-time/coverage

Universities optimize for *coverage in a semester*; that is an artifact of the calendar, not of learning. The Academy optimizes for **demonstrated competence**. A learner advances when they can *do* the thing, verified by assessment (§12) and practical exercise (§13), not when they have scrolled past the content. This is the SANS/GIAC and military-pipeline philosophy (you don’t leave the range until you qualify) and it is superior because security failures are competence failures, not attendance failures. Tradeoff: requires robust assessment, which is more expensive to author than prose.

### 0.3 Adopt explicitly: a **spiral curriculum** (Bruner)

Topics are not "done" when first taught. Identity appears at Foundation (what is an account), recurs at Practitioner (JML lifecycle, access reviews), and again at Professional (federation, conditional access, identity threat detection). Each pass deepens and re-contextualizes. The spiral is how Harvard CS50 revisits abstraction and how Cisco revisits the OSI model across courses. The metadata model (§26) must therefore let multiple lessons legitimately share a concept tag at different depths.

### 0.4 Adopt explicitly: the **"WHY before HOW"** doctrine

The brief’s instinct that learners must understand *why*, not just *how*, is correct and is elevated here to a doctrine (§2). Every lesson must establish the **threat model / business reason** before procedure. "Configure conditional access" is worthless without "why standing privilege is the dominant breach vector." This is the difference between training (repeat the steps) and education (transfer to novel situations). Bloom’s taxonomy makes this measurable: we will not accept a lesson whose outcomes top out at *Remember/Understand* when the role demands *Apply/Analyze/Evaluate*.

### 0.5 Ground everything in **learning science**, not folklore

The constitution commits to the evidence base, not to intuition:

- **Cognitive Load Theory (Sweller):** working memory is tiny; lessons that dump everything fail. Hence chunking (§7), the worked-example effect (§13), and strict scope-per-lesson (§8).
- **Retrieval practice & the testing effect (Roediger/Karpicke):** recall strengthens memory more than re-reading. Hence mandatory low-stakes retrieval in every lesson (§8/§12), not just end-of-chapter exams.
- **Spaced repetition:** flashcards (already in the repo) are first-class, scheduled, and graph-linked (§12.4), not an afterthought.
- **Dual coding (Mayer/Paivio):** words + visuals beat words alone — hence diagram standards (§10) are mandatory, not decorative.
- **Dreyfus model of skill acquisition:** Novice → Advanced Beginner → Competent → Proficient → Expert maps to our difficulty levels (§21) better than vague "beginner/advanced."
- **Desirable difficulties (Bjork):** some struggle improves retention; we deliberately design productive difficulty into labs rather than smoothing everything.

### 0.6 Honest risks of "the most comprehensive ever"

A constitution that promises infinite comprehensiveness is writing a check the maintenance budget cannot cash. We name the risks and design against them:

- **Staleness.** Security moves fast (Entra renames, new CVE classes, cloud console redesigns). A 5,000-lesson corpus where 20% is wrong is *worse* than a 1,000-lesson corpus that is correct, because it destroys trust. **Mitigation:** every lesson carries a `reviewBy` date and a `volatility` rating (§17, §26); high-volatility content is quarantined from "evergreen" claims and surfaced for review first.
- **Scope sprawl / never shipping.** "Comprehensive" can become an excuse never to publish. **Mitigation:** mastery-graph + thin vertical slices — ship a *complete path to one competence* before broadening. Depth-first beats breadth-first for shippability.
- **Maintenance cost compounding.** Diagrams and labs rot fastest and cost most. **Mitigation:** prefer durable conceptual diagrams over screenshot-heavy click-paths; isolate volatile procedures into clearly-marked, easily-replaceable lesson blocks.
- **Single-author bottleneck / inconsistency.** **Mitigation:** the standards in §15–§17 and the schema in the Appendices exist precisely so many authors (human or AI-assisted) produce uniform output.

### 0.7 What we keep from the brief

The Volume/Chapter/Lesson vocabulary is retained as the **primary human-facing reading structure** because it is familiar and navigable (Cisco Press / Microsoft Press readers expect it). We simply refuse to make it the *only* truth. We keep the 30 standards, the WHY-not-HOW goal, the ambition, and the typed-data implementation. Everything below reconciles the brief’s structure with the graph-and-mastery substrate argued here.

> **Net position:** Linear *views* for humans; a *competence graph* underneath; *mastery* gates progression; *learning science* governs design; *honesty about volatility* protects trust. The 30 sections now operationalize this.

---

# PART I — FOUNDATIONS

## 1. Academy Vision

**Why this exists.** Without a single, sharp vision, a curriculum becomes a pile of topics. The vision is the tie-breaker for every later decision: when two designs are both defensible, the one that better serves the vision wins.

**The vision.** The WebHound Enterprise Security Academy exists to take a motivated learner from *foundational IT literacy* to *defensible professional competence across the enterprise security lifecycle* — governance, identity, infrastructure, cloud, engineering, operations, audit, and leadership — by teaching the **why behind the how**, verified by doing, and kept honest about a fast-moving field. The graduate is not someone who has *read* about security; they are someone who can walk into an enterprise, reason about its risks, operate its controls, evaluate evidence, and explain their reasoning to both engineers and executives.

**How universities frame it.** Elite programs publish a *graduate profile* — "a CMU graduate can…", "an MIT EECS graduate can…". The profile, not the course list, is the product. We adopt the graduate-profile framing (see §22 Learning Outcomes) as the measurable expression of the vision.

**How enterprise framing differs and what we borrow.** Microsoft Learn and Cisco organize around **role-based paths** ("Security Operations Analyst," "Network Engineer") tied to job outcomes and certifications. SANS organizes around **job-task analysis** — what does this role actually do on Tuesday? We borrow both: the vision resolves into role outcomes (§22) and job-task-derived competencies (§24), so the Academy is accountable to real work, not abstract topics.

**Why superior.** A coverage-driven academy can be "comprehensive" and still produce people who can’t do the job. An outcome-and-task-driven vision is falsifiable: we can test whether a graduate can actually perform.

**How it scales.** The vision is domain-agnostic. Adding "OT/ICS Security" later doesn’t change the vision; it adds a region to the competence graph that the same standards govern.

## 2. Educational Philosophy

**Why this exists.** Standards without a philosophy are arbitrary. The philosophy explains *what kind of learning* we are trying to cause, so the standards are coherent rather than a committee’s grab-bag.

**The five pillars.**

1. **WHY before HOW (threat-model-first).** Every unit of instruction opens with the business/risk reason it exists. Procedure is earned, not assumed. This is the doctrine from §0.4.
2. **Understanding over memorization, but memory is load-bearing.** We reject rote-only training, *and* we reject the romantic idea that "understanding" removes the need to know facts cold. An incident responder must *understand* attacker tradecraft *and* have the port numbers, log locations, and command syntax in fast memory. We teach for transfer and drill for fluency.
3. **Learn by doing, fail safely.** Competence is demonstrated in labs (§11) and exercises (§13), in environments where mistakes teach instead of breaching. This mirrors flight simulators and SANS ranges.
4. **Honesty and intellectual integrity.** We mark uncertainty, cite primary sources, distinguish vendor marketing from fact, and never fabricate (§17). A security curriculum that bluffs is training people to bluff.
5. **Dual-audience fluency.** The enterprise security professional must speak to *machines and engineers* and to *executives and auditors*. Every professional-level lesson cultivates both the technical and the communicate-the-risk muscle.

**Universities vs enterprise.** Universities lean conceptual (the *why*); bootcamps and vendor training lean procedural (the *how*) and decay fast when products change. The Academy’s philosophy deliberately fuses them — conceptual spine, procedural muscle — which is exactly the gap most security education leaves open.

**Scale.** A philosophy is cheap to hold and expensive to violate; it scales infinitely because it is applied per-lesson by authors, not centrally enforced.

## 3. Learning Psychology

**Why this exists.** Content is the easy part; *retention and transfer* are the hard part. Most curricula fail not because the facts are wrong but because the design fights how human memory works. This section makes the cognitive-science commitments enforceable.

**The mechanisms we design around (and the standard each one creates):**

- **Cognitive Load Theory.** Working memory holds ~4 chunks. Therefore: one core idea per lesson (§8), progressive disclosure, and explicit management of *intrinsic* vs *extraneous* vs *germane* load. Extraneous load (clutter, inconsistent terms, ungrounded jargon) is treated as a defect.
- **The testing effect / retrieval practice.** Recalling beats re-reading. Therefore every lesson embeds **retrieval checkpoints** (§8.4) and the assessment system (§12) is formative-first, not just a final exam.
- **Spaced repetition.** Forgetting is exponential; spaced review flattens the curve. Flashcards become scheduled review items keyed to concepts (§12.4), so a learner is re-prompted on "RPO vs RTO" days later, not just in the moment.
- **Worked examples & faded guidance.** Novices learn procedure faster from fully worked examples than from pure problem-solving; as skill grows, guidance fades to independent practice. Lab design (§11, §13) mandates this fade.
- **Elaboration & interleaving.** Connecting new ideas to prior ones and mixing problem types improves transfer. The graph’s `relatedConcepts` and mixed-topic capstones (§14) operationalize this.
- **Dual coding.** Pair words with diagrams (§10).
- **Metacognition.** Learners are poor judges of their own knowledge. Outcome statements (§22) and self-check prompts make the target explicit so learners can calibrate.

**How the best do it.** Carnegie Mellon’s Open Learning Initiative is the gold standard: instrumentation + frequent low-stakes practice produced measurable learning gains ("the OLI effect"). We can’t instrument as deeply on day one, but we adopt its *frequent retrieval* core. Duolingo and Anki productized spaced repetition; we adopt the schedule, not the gimmicks.

**Scale.** These are per-lesson design rules encoded in the Lesson Standard (§8) and checkable by tooling (does this lesson have ≥N retrieval items? does it have a diagram? are its outcomes above *Remember*?). That is how psychology survives contact with 5,000 lessons.

## 4. Knowledge Progression

**Why this exists.** Expertise is not linear accumulation; it is *restructuring*. A learner doesn’t just add facts — they reorganize their mental model. Progression standards prevent two classic failures: teaching advanced material on a missing foundation (collapse), and re-teaching basics to people ready to advance (boredom/attrition).

**The progression model.** We use the **Dreyfus skill model** as the human-facing ladder and **Bloom’s cognitive taxonomy** as the per-lesson rigor scale:

- **Dreyfus (the learner’s journey):** Novice → Advanced Beginner → Competent → Proficient → Expert. This becomes our difficulty levels (§21): Foundation, Practitioner, Professional, Expert, plus a Leadership capstone tier.
- **Bloom (the lesson’s demand):** Remember → Understand → Apply → Analyze → Evaluate → Create. Outcomes use Bloom-aligned verbs (§22) so rigor is explicit and gradable.

**Spiral, not staircase.** As argued in §0.3, core concepts recur at increasing depth. Progression is therefore measured along *two axes*: breadth (how many domains) and depth (how high up Bloom for a given concept). The metadata model captures both (`difficulty` + `bloom` + `concept` tags), so the same concept can legitimately appear at three depths without being "duplicate content."

**University vs enterprise.** Universities encode progression as prerequisites and course numbering (100/200/300/400-level). Enterprise paths encode it as "learning path order" and cert tiers (Fundamentals → Associate → Expert, e.g. Microsoft AZ-900 → SC-200 → SC-100). We unify both via the prerequisite system (§23) and the dependency graph (§24): course numbers and path order become *derived* properties of the graph, computed, never hand-maintained.

**Scale.** Hand-maintained prerequisite lists rot. A computed graph (§24) lets us add a lesson and have its correct placement, prerequisites, and "you’re ready for this next" recommendations fall out automatically.

---

# PART II — CURRICULUM ARCHITECTURE

## 5. Curriculum Architecture

**Why this exists.** This is the skeleton everything hangs on. Get it wrong and every later standard inherits the flaw.

**The structure (reconciling the brief with Part 0).** Five nested levels for humans, one graph underneath:

```
University (the Academy)
└─ Domain        e.g. "Identity & Access", "Governance/Risk/Compliance", "Cloud Security"
   └─ Volume     a coherent body of knowledge within a domain (the "book")
      └─ Chapter a major theme within a volume
         └─ Lesson the atomic unit of learning (one core idea)
            └─ Components: concept exposition, diagram(s), worked example,
                           lab(s), retrieval checks, assessment, glossary links
```

Beneath this, the **competence graph** (§24) connects lessons by prerequisite and concept regardless of which volume they live in. **Tracks** (role-based reading paths — "SOX IT Auditor," "Cloud Security Engineer," "Incident Responder") are curated, ordered traversals of the graph that cut *across* domains and volumes. A lesson lives in exactly one volume (its home) but can appear in many tracks.

**§5.1 Scope Charter (domains the architecture must accommodate).** The architecture must, without modification, hold: Enterprise IT, Enterprise Architecture, Windows, Linux, Networking, Active Directory, Microsoft Entra, IAM, Governance, Risk & Compliance, SOX, ITGC, Internal/External Audit, DR, BCP, Vendor Risk, Vulnerability Management, Security Engineering, Cloud Security, DevSecOps, Threat Hunting, Incident Response, Digital Forensics, and Enterprise Leadership. None of these is privileged in the schema; each is a Domain node. (The existing `/academy/pca-risk` content becomes the **SOX/ITGC/Audit** slice of the GRC domain — the architecture must absorb it without rework, which §29 ensures.)

**How the best structure it.** Cisco: Course → Module → Topic. Microsoft Learn: Learning Path → Module → Unit. SANS: Course → Day → Section. O’Reilly/CS textbooks: Part → Chapter → Section. All are 3–5 levels — more than five and navigation collapses; fewer and large domains can’t be organized. We chose five with a graph because the domain breadth (24 domains) demands the extra level while the graph prevents rigidity.

**Why superior.** Pure hierarchies force a topic into one place; real knowledge is cross-cutting (identity touches cloud, audit, and IR). The hierarchy-plus-graph gives a clean home *and* honest cross-links. Tradeoff: two structures to keep consistent — resolved by making the hierarchy a *property* of each graph node (a node knows its volume/chapter), so there is one source of truth, not two.

**Scale.** Domains are added as peers; the graph absorbs cross-links automatically; tracks are authored as needed without moving any content.

## 6. Volume Standards

**Why this exists.** A "volume" is the unit a learner commits to ("I’m going to learn Active Directory"). It must be a *complete, coherent* body — not a random bin of chapters.

**Standard.** Every volume must (1) state a **graduate profile** for the volume ("after this volume you can…"), (2) declare its **entry prerequisites** (other volumes/competencies), (3) be decomposable into 6–15 chapters (fewer suggests it should be a chapter; more suggests it should split), (4) contain at least one **integrative capstone** (§14) that forces synthesis across its chapters, and (5) carry domain, difficulty band, estimated effort, and maintenance ownership in metadata. A volume is not "done" until a learner could reach its graduate profile *using only the volume and its declared prerequisites* — no hidden dependencies.

**University/enterprise practice.** A university course has a syllabus with outcomes, prereqs, and a culminating project; a Microsoft Learn *Learning Path* has a stated role outcome and a knowledge check per module. We fuse: volume = syllabus + culminating capstone, with machine-readable prereqs.

**Why superior / scale.** The "self-contained given prerequisites" rule is what lets thousands of volumes coexist: each is independently authorable and testable, and the graph guarantees the prerequisites actually exist.

## 7. Chapter Standards

**Why this exists.** Chapters manage **cognitive load at the mid scale** — they group lessons into a theme small enough to hold in mind and large enough to be meaningful.

**Standard.** A chapter (1) opens with a **chapter-level WHY** and a map of its lessons (advance organizer — Ausubel), (2) contains 3–10 lessons, (3) follows a deliberate internal progression (concept → application → integration), (4) ends with a **chapter retrieval set** and a short integrative exercise, and (5) explicitly names the concepts it introduces vs reinforces (spiral bookkeeping). The advance organizer matters: telling learners the structure *before* the detail measurably improves comprehension and is standard in Cisco Press and good textbooks.

**Scale.** The 3–10 lesson bound keeps chapters navigable and keeps the volume’s chapter count sane; tooling can flag chapters that drift outside the band.

## 8. Lesson Standards

**Why this exists.** The lesson is the **atom**. Quality at the atom level determines quality everywhere. This is the most important production standard in the document.

**The canonical lesson anatomy (every lesson, every domain):**

1. **Metadata header** (§26) — id, title, domain/volume/chapter, difficulty, Bloom level, prerequisites, concepts, est. minutes, volatility, reviewBy.
2. **Hook / WHY** — the threat model or business reason. One paragraph. Non-negotiable (§0.4).
3. **Learning outcomes** — 1–4 outcomes, Bloom-verbed (§22), measurable.
4. **Core exposition** — *one* core idea, chunked, dual-coded with at least one diagram where the idea is structural/relational (§10).
5. **Worked example** — the idea applied concretely (the worked-example effect).
6. **Retrieval checkpoint(s)** — ≥2 low-stakes recall prompts mid/після exposition (testing effect). These are not the graded assessment; they are practice.
7. **Practice / lab pointer** — link to the hands-on artifact (§11/§13) that proves the outcome.
8. **Summary + connections** — compress the idea; link `relatedConcepts` and "what this unlocks next."
9. **Glossary links** — every domain term resolves to the glossary (§9).

**The "one core idea" rule.** If a lesson needs two diagrams to explain two unrelated things, it is two lessons. This is the single most effective anti-cognitive-overload rule and the hardest for authors to obey.

**How the best do it.** Microsoft Learn *Units* are deliberately small and end in a knowledge check; CMU OLI pages interleave exposition and practice every few paragraphs. We are closer to OLI than to a traditional textbook chapter because retrieval-dense beats prose-dense for retention.

**Why superior / scale.** A rigid, rich anatomy is what makes *consistent* mass authoring possible — a new author (or an AI assistant) fills a known skeleton, and tooling validates that every required block is present and that outcomes clear the Bloom floor for the difficulty level.

## 9. Vocabulary Standards

**Why this exists.** Security is a jargon minefield, and ambiguous terms are a top source of extraneous cognitive load and real-world error (the brief’s own content already had to clarify "SOC = System and Organization Controls, *not* Security Operations Center" — a perfect example of why this section exists).

**Standard.** (1) Every domain term has **exactly one canonical glossary entry** (the existing typed `GlossaryTerm` is the substrate). (2) First use of a term in a lesson links to its glossary entry. (3) Each entry carries a `category`, a one-line gist, a full definition, and an explicit **disambiguation** field for confusable terms ("not to be confused with…"). (4) Acronyms are expanded on first use per lesson. (5) Terms are **versioned with the field** — when Azure AD became Entra ID, the entry records both, marks the deprecated form, and dates the change. (6) No term may be used at a difficulty level below where it is defined.

**How the best do it.** Cisco and ISC² maintain controlled vocabularies and official glossaries (NIST’s glossary is the canonical model for security terminology). We align definitions to authoritative sources (NIST, ISO, PCAOB, vendor docs) and cite them (§17).

**Scale.** A single canonical glossary with machine links means a term can be re-defined once and corrected everywhere; tooling can detect undefined or below-grade term usage across thousands of lessons.

## 10. Diagram Standards

**Why this exists.** Security is full of *relationships and flows* (trust boundaries, data flows, attack paths, control mappings) that prose explains badly and pictures explain instantly (dual coding). A diagram-light curriculum in this field is a defective curriculum.

**Standard.** (1) Any lesson whose core idea is structural, relational, sequential, or architectural **must** include at least one diagram. (2) Diagrams are **conceptual-first and durable** — prefer architecture/flow/trust-boundary diagrams (which age slowly) over annotated product screenshots (which rot on the next UI redesign); screenshots, when necessary, are isolated and marked high-volatility. (3) Diagrams are authored as **text-defined, version-controllable sources** (e.g. Mermaid/diagram-as-code) wherever possible so they diff in git and render in the app, not as opaque binaries. (4) Every diagram has a caption, alt text (accessibility, §28), and a stable id. (5) A house visual grammar (consistent shapes for actor/system/data-store/trust-boundary/threat) is defined once and reused, so a learner reads the 500th diagram with zero relearning.

**How the best do it.** Cisco’s entire pedagogy is diagram-driven; AWS/Azure architecture content is reference-architecture-driven; threat modeling (STRIDE/data-flow diagrams) is inherently visual. We standardize the *grammar* the way Cisco standardizes its network-icon set.

**Why superior / scale.** Diagram-as-code with a fixed visual grammar means thousands of diagrams stay consistent, reviewable in PRs, and cheap to fix — the opposite of a folder of inconsistent PNGs.

## 11. Laboratory Standards

**Why this exists.** You cannot learn to defend an enterprise by reading. Labs are where competence is built and where safe failure happens.

**Standard.** (1) Every lab states **objective, prerequisites, environment, steps, expected result, and a verification/"how you know you succeeded" check**. (2) Labs follow the **faded-guidance** arc within and across a chapter: first labs are fully worked, later labs remove scaffolding toward independent problem-solving (§13). (3) Labs declare a **safety/blast-radius class** — *conceptual* (paper/spreadsheet, like the existing PCA labs), *sandboxed* (isolated VM/cloud-sandbox), or *live-but-consented* (only against systems the learner controls, mirroring WebHound’s own consent-based ethic). The Academy **never** instructs unauthorized action against third-party systems; offensive technique is taught in sandboxes with an explicit legal/ethics preface. (4) Labs prefer **reproducible, declarative environments** (scripts/infra-as-code) over "click here" so they survive and self-verify. (5) Each lab maps to the outcome(s) it proves.

**How the best do it.** SANS ranges, Cisco Packet Tracer, Microsoft Learn sandboxes, hospital simulation labs, flight simulators — all share *safe, repeatable, verifiable* practice. The Academy’s consent-and-sandbox stance is also an *ethics* position appropriate to a security school.

**Scale.** Declarative, self-verifying labs are the only kind that scale — a human can’t hand-grade thousands of lab attempts, but a verification check can.

## 12. Assessment Standards

**Why this exists.** Mastery-based progression (§0.2) is only as good as its assessments. Assessment is *also* a learning tool (testing effect), not just a gate.

**Standard.**

- **§12.1 Formative-first.** Most assessment is low-stakes, in-lesson retrieval (the checkpoints of §8). Its job is learning, not judgment.
- **§12.2 Summative gates.** End-of-chapter and end-of-volume assessments gate progression and must be **outcome-aligned** — every question traces to a declared learning outcome (§22). No outcome, no question; no question, no claim of mastery.
- **§12.3 Bloom-matched items.** A *Remember* outcome may use recall items; an *Analyze/Evaluate* outcome demands scenario/case items (like the existing interview "scenario" questions). We forbid testing high-Bloom outcomes with low-Bloom multiple choice — the dominant assessment lie in the industry.
- **§12.4 Spaced retrieval.** Flashcards become scheduled review items keyed to concepts; the system re-surfaces them on a spacing schedule, not just once.
- **§12.5 Authenticity.** Where possible, assess by *doing* (lab verification, §11) or by *judgment under scenario*, because security competence is performance, not trivia.
- **§12.6 Honest scoring.** Item rationales explain *why* each answer is right/wrong (feedback drives learning); question banks are versioned and reviewed for accuracy like any content (§17).

**How the best do it.** GIAC’s practical exams and "CTF"-style assessment, CMU OLI’s embedded assessment, medical OSCEs (observed performance) — all push toward *authentic, outcome-aligned* assessment over trivia. We adopt that bias.

**Scale.** Outcome-tagged item banks let tooling guarantee coverage (every outcome has ≥N items) and detect orphan questions across the whole corpus.

## 13. Practical Exercise Standards

**Why this exists.** Between passive reading and full labs sit **exercises** — structured practice that builds the procedural fluency understanding alone won’t. This is where the worked-example→faded-guidance→independent-practice arc lives.

**Standard.** Exercises (1) come in a deliberate sequence — **worked example** (author does it, learner watches the reasoning), **completion problem** (author does most, learner finishes the hard step), **independent problem** (learner does it, then compares to a model solution); (2) each has a **deliverable** and a **self-check/model answer** (the existing `Lab` records already do this — "deliverable" + "tip"); (3) target *germane* load — effortful but achievable (desirable difficulty, §0.5); (4) are explicitly tagged to the outcome and Bloom level they build.

**Why superior.** Pure problem-solving overwhelms novices (cognitive load); pure worked examples create illusory competence. The faded sequence is the evidence-based middle and is rarely done deliberately — doing it deliberately is an edge.

**Scale.** The three exercise types are a fixed template authors instantiate; tooling can check that a chapter contains the full fade, not just three independent problems thrown at a novice.

## 14. Capstone Standards

**Why this exists.** Knowledge tested in isolation creates people who know everything and can do nothing together. Capstones force **synthesis** — the integration that converts knowledge into competence.

**Standard.** (1) Every volume ends in an **integrative capstone** that requires combining most of its chapters (e.g. for a GRC volume: scope a control, pull a population, test a sample, evaluate exceptions, and write the memo — end to end). (2) Each **track** (role path) ends in a **role capstone** simulating a realistic slice of the job ("respond to this incident," "deliver this audit," "design this access model"). (3) Capstones are **scenario-driven, open-ended, and rubric-graded** against outcomes — there is rarely one right answer, mirroring real work. (4) Capstones are explicitly cross-domain where the role is (an IR capstone touches identity, logging, forensics, and executive communication).

**How the best do it.** Capstone projects (every serious engineering program), SANS NetWars, medical residencies, military field exercises — all are integrative simulations. The Academy treats the capstone as the truest measure of the graduate profile (§1/§22).

**Scale.** Rubrics (not answer keys) let capstones grade open-ended work consistently across many learners and graders, and let the same capstone evolve as the field does without a rewrite.

---

# PART III — AUTHORING & QUALITY

## 15. Writing Standards

**Why this exists.** Voice and clarity are not cosmetic — inconsistent, bloated, or hedge-filled writing *is* extraneous cognitive load and erodes trust. A thousand lessons must read as one authored work.

**Standard.** (1) **Plain, precise, active voice**; short sentences for hard ideas. (2) **Define before use; concrete before abstract; example-rich.** (3) **Address the learner directly** ("you"), at the reading level of a working professional — neither dumbed-down nor academic-obscure. (4) **No bluffing, no filler.** If something is uncertain or contested, say so. (5) **Consistent terminology** (per §9) — the same concept is always called the same thing. (6) **Honest framing of difficulty** — warn when something is genuinely hard rather than pretending it’s trivial. (7) A documented **style guide** (terms, capitalization, number/acronym rules, tone) governs all authors, human or AI-assisted.

**How the best do it.** O’Reilly and Microsoft Press maintain rigorous style guides; the *Microsoft Writing Style Guide* and *Google developer documentation style guide* are public exemplars we align to for tone and mechanics. Cisco Press enforces a consistent instructional voice across hundreds of authors — that consistency is the point.

**Scale.** A style guide + linting (terminology, reading level, banned-filler patterns) is how voice survives across authors and years.

## 16. Editorial Standards

**Why this exists.** No author catches their own errors. Editorial process is the structural guarantee of quality, independent of any individual.

**Standard — a defined pipeline, every artifact:** **Author → Technical Review (accuracy, §17) → Editorial Review (clarity/structure/style, §15) → Accessibility & Metadata check (§26/§28) → Approve/Publish (§20).** (1) Reviews are recorded (who, when, verdict) on the artifact. (2) Technical and editorial review are *separate roles/passes* — different failure modes. (3) Nothing publishes without passing both plus the automated checks (schema valid, links resolve, outcomes meet Bloom floor, diagram/retrieval minimums met). (4) Editorial owns the **macro** (does this belong here? is the progression right?) as well as the micro.

**How the best do it.** Academic peer review, technical-book tech-reviewers + copy editors, and enterprise content pipelines all separate "is it true" from "is it clear." We mirror that separation.

**Scale.** The pipeline is enforced in the same PR workflow as code (§19/§20), so editorial rigor scales with the same tooling that scales the codebase.

## 17. Technical Accuracy Standards

**Why this exists.** In security, wrong is dangerous. An incorrect lesson can cause a breach, a failed audit, or legal exposure. Accuracy is the Academy’s non-negotiable floor and its core trust asset.

**Standard.** (1) **Cite primary/authoritative sources** — NIST, ISO, CIS, PCAOB/AICPA, MITRE ATT&CK, RFCs, vendor documentation — not blogs or other courses. (2) **Distinguish fact from vendor marketing and from opinion**; label each. (3) **Every claim is checkable**; technical reviewers verify against sources and, for procedures, against a real environment. (4) **Volatility management:** each artifact carries a `volatility` rating and a `reviewBy` date; high-volatility content (cloud consoles, product names, threat landscape) is reviewed on a short cycle and is forbidden from "evergreen" phrasing. (5) **No fabrication** — if data/evidence doesn’t exist, the lesson says so rather than inventing it (the same integrity rule the WebHound project applies to itself). (6) **Mapped to frameworks** where relevant (a control lesson cites the NIST CSF/800-53, ISO 27001, or COSO control it implements), so accuracy is anchored to canon.

**How the best do it.** SANS/GIAC and ISC² tie content to defined bodies of knowledge and review cycles; NIST publications are themselves the citation standard. Mapping to ATT&CK/NIST is now table stakes in serious security training.

**Scale.** Citations + `reviewBy` + `volatility` turn maintenance from "re-read everything someday" into a *prioritized queue* — tooling surfaces what’s overdue or high-risk first. This is the single most important defense against the staleness risk named in §0.6.

---

# PART IV — LIFECYCLE

## 18. Version Control

**Why this exists.** A living curriculum changes constantly; without versioning you cannot tell learners *what changed*, cannot roll back a bad edit, and cannot trust that "the access-review lesson" means the same thing today as last quarter.

**Standard.** (1) **All content lives in git** alongside the app (it already does — typed records under `apps/web/src/lib/academy`), so every change is diffable, attributable, reversible, and reviewable in PRs. (2) **Semantic versioning per artifact**: `MAJOR.MINOR.PATCH` — MAJOR = outcomes/structure changed (may invalidate prior mastery), MINOR = content added without breaking, PATCH = fixes/typos. (3) **The corpus has a version** (the constitution is v1.0.0). (4) **Changelogs** are generated from commits + per-artifact `version`/`changelog` fields. (5) Binary/large artifacts (rendered diagrams, datasets) follow the repo’s existing "regenerable, not committed if large" discipline; **text and diagram-as-code are committed**.

**How the best do it.** Docs-as-code (Microsoft Learn’s content is on GitHub; many O’Reilly titles are git-managed) is now the industry norm precisely because it brings software-grade rigor to content. We are already there.

**Scale.** Git + per-artifact semver is the only versioning model proven to scale to tens of thousands of files and many contributors.

## 19. Revision Workflow

**Why this exists.** Content decays; the field moves. A *defined* revision workflow is what keeps a large corpus correct instead of slowly rotting.

**Standard.** (1) **Triggers:** scheduled (`reviewBy` elapsed), event-driven (vendor change, new CVE class, framework update, learner-reported error), or quality-driven (assessment data shows a lesson isn’t landing). (2) **Each revision re-enters the editorial pipeline** (§16) scoped to what changed; a PATCH may need only technical re-check, a MAJOR needs full review and a version bump. (3) **Learner-facing change notes** for MAJOR changes ("this volume was updated for Entra ID; re-take the capstone"). (4) **Amending the constitution itself** is a MAJOR governance change: proposed in a PR, reviewed, and recorded in this document’s changelog — Phase 0 is living but deliberately hard to change.

**How the best do it.** Standards bodies (NIST, ISO) run formal revision cycles with public comment; vendor docs run continuous updates with "last reviewed" stamps. We blend scheduled rigor with continuous responsiveness.

**Scale.** The `reviewBy`/`volatility` queue (from §17) *is* the revision backlog — it scales because work is prioritized by risk and recency, not done all-at-once.

## 20. Publishing Workflow

**Why this exists.** There must be a clear, safe line between "draft" and "live," and a controlled path across it — the same discipline that protects production code protects production curriculum.

**Standard.** (1) **Lifecycle states** on every artifact: `draft → in_review → approved → published → deprecated → archived`. Only `published` renders to learners by default. (2) **Gated promotion:** an artifact reaches `published` only after passing technical + editorial review and all automated checks (§16). (3) **Publishing = merge to main → app build → deploy** (the repo already auto-deploys main via Vercel; published content ships exactly like the existing `/academy` routes). (4) **Deprecation, not deletion:** outdated lessons move to `deprecated` (hidden from default paths, still resolvable by links) then `archived`, preserving history and inbound links. (5) **Preview before publish:** authors review rendered content on a branch/preview deploy.

**How the best do it.** Software release management (staging → prod, feature flags) applied to content; Microsoft Learn ships content through CI/CD. We reuse the project’s existing PR-and-deploy machinery rather than inventing a parallel one.

**Scale.** State + gates + CI/CD is the only publishing model that lets many authors ship safely in parallel without a human bottleneck approving every word at deploy time.

---

# PART V — THE LEARNER MODEL

## 21. Difficulty Levels

**Why this exists.** "Beginner/intermediate/advanced" is too vague to place a lesson or route a learner. We need defined, Dreyfus-aligned bands with concrete admission criteria.

**Standard — five bands:**

| Level | Dreyfus | Bloom ceiling (typical) | The learner can… |
|------|---------|------------------------|------------------|
| **L1 Foundation** | Novice | Understand | follow rules/procedures with context; explain core concepts and *why they matter*. |
| **L2 Practitioner** | Adv. Beginner → Competent | Apply | perform standard tasks in realistic situations; choose among known options. |
| **L3 Professional** | Competent → Proficient | Analyze | diagnose novel situations, weigh tradeoffs, design within constraints. |
| **L4 Expert** | Proficient → Expert | Evaluate / Create | set strategy, handle ambiguity, create new approaches, judge others’ work. |
| **L5 Leadership** | Expert (org scope) | Evaluate / Create | govern programs, manage risk at enterprise scale, communicate to boards. |

(1) Difficulty is a **declared metadata field** (`difficulty: L1..L5`). (2) A lesson’s **outcomes must reach the Bloom floor** for its level — an L3 lesson whose outcomes top out at *Understand* is mis-leveled and tooling rejects it. (3) Terms/prerequisites may not exceed the lesson’s level (§9).

**How the best do it.** Microsoft’s Fundamentals/Associate/Expert, Cisco’s CCNA/CCNP/CCIE, and the Dreyfus model itself. Our five bands map cleanly onto all three and add the explicit Leadership tier the enterprise scope demands.

**Scale.** A typed enum + Bloom floor makes leveling *checkable*, so 5,000 lessons stay correctly stratified.

## 22. Learning Outcomes

**Why this exists.** Outcomes are the contract: they define what "learned" means, drive assessment (§12), and make the vision (§1) falsifiable. Vague outcomes ("understand networking") are unmeasurable and therefore worthless.

**Standard.** (1) Outcomes are **Bloom-verbed, specific, and measurable** — "Evaluate a SOC 1 Type II report and identify reliance gaps," not "know about SOC reports." (2) Each lesson declares 1–4; each chapter/volume/track aggregates them into a **graduate profile**. (3) **Banned verbs:** *know, understand, learn, be familiar with, appreciate* — unmeasurable; replaced with the Bloom verb taxonomy below. (4) Every assessment item and capstone rubric line **traces to an outcome** (no orphan assessment, no untested outcome).

**Bloom verb taxonomy (canonical, used by tooling to infer/validate level):**

- **Remember:** define, list, name, recall, identify, label.
- **Understand:** explain, describe, summarize, classify, contrast, interpret.
- **Apply:** perform, configure, execute, implement, use, solve, demonstrate.
- **Analyze:** diagnose, differentiate, investigate, correlate, deconstruct, troubleshoot.
- **Evaluate:** assess, judge, prioritize, critique, justify, recommend, defend.
- **Create:** design, build, compose, architect, formulate, develop, plan.

**How the best do it.** Outcome-based education (Bloom, 1956; Anderson & Krathwohl revision, 2001) is the backbone of accredited curricula and instructional design (ADDIE/Backward Design — Wiggins & McTighe’s "design from the outcome backward"). We adopt **backward design**: outcomes first, then assessment, then content.

**Scale.** A controlled verb list lets tooling auto-classify a lesson’s Bloom level from its outcomes and flag mismatches with its difficulty band — automated quality at corpus scale.

## 23. Prerequisite System

**Why this exists.** Prerequisites prevent the two progression failures (§4): building on absent foundations, and boring the ready. They also power "what should I learn next."

**Standard.** (1) Prerequisites are declared as **lists of competence/lesson IDs**, not prose ("requires: `iam.authn-vs-authz`, `net.tcp-ip-basics`"). (2) They are **enforced and verified** — a referenced prerequisite must exist (no dangling), and the graph must remain acyclic (§24). (3) Two kinds: **hard** (you literally cannot do this without it) and **soft/recommended** (helpful but not blocking) — distinguished in metadata so paths can be strict or flexible. (4) Prerequisites are **transitive**: the system computes the full ancestry, so authors declare only *direct* prerequisites and the closure is derived.

**How the best do it.** University prerequisite chains and Khan Academy’s knowledge map. Khan’s map is the closest model: declare local edges, compute the reachable set, recommend the frontier.

**Scale.** Declaring only direct edges (and computing closure) is what keeps prerequisite data maintainable across thousands of nodes — the alternative (hand-listing full chains) is unmaintainable.

## 24. Knowledge Dependency Graph

**Why this exists.** This is the substrate argued for in Part 0 — the structure that makes the whole system more than a bookshelf. It is the source of truth for ordering, recommendation, readiness, and gap analysis.

**Standard.** (1) The corpus is a **directed acyclic graph (DAG)**: nodes are competencies/lessons; edges are typed relationships — `requires` (hard prereq), `recommends` (soft), `reinforces` (spiral re-teach of a concept), `relatedTo` (lateral link). (2) **No cycles** (enforced by tooling; a cycle is a content-design bug). (3) **No orphans** at publish time (every published lesson is reachable from some track or volume). (4) Hierarchy (volume/chapter) is a **node property**, not a separate structure — one source of truth. (5) The graph powers: computed prerequisite closure (§23), "ready to learn next" (frontier), gap detection (a competence with no lesson), and impact analysis (if I change X, what depends on it). (6) The graph is **representable in the typed data** and exportable for visualization (the project already has graph tooling and an Obsidian/graph habit; the academy graph reuses that muscle).

**Concrete representation (illustrative):**

```ts
// A node is just a lesson/competency record carrying edges (see Appendix A).
interface DependencyEdge {
  to: string                 // target node id, e.g. "iam.access-reviews"
  type: 'requires' | 'recommends' | 'reinforces' | 'relatedTo'
}
// Tooling builds the DAG from every record's `id` + `edges`,
// then asserts: all `to` resolve · no `requires` cycle · no published orphan.
```

**How the best do it.** Knowledge graphs underpin Khan Academy, intelligent tutoring systems (CMU), and modern adaptive platforms. Prerequisite *graphs* (not lists) are what enable personalization and gap analysis.

**Scale.** The graph is the *only* known structure that lets a curriculum grow to thousands of nodes while keeping ordering correct automatically. Hand-maintained order does not survive that scale; a computed graph does.

## (Bridge) The Learner Model in one sentence

A learner is a **position in the graph** (what they’ve mastered) plus a **goal** (a track’s graduate profile); the system’s job is to route them along the shortest mastery-respecting path from position to goal, drilling weak prerequisites and skipping proven ones. Difficulty (§21), outcomes (§22), prerequisites (§23), and the graph (§24) are the four coordinates of that model.

---

# PART VI — THE MACHINE LAYER (concrete, implementable in this repo)

> These sections turn the philosophy into a schema future lessons plug into. They are written to be enforceable by tooling and to extend — not replace — the existing typed records under `apps/web/src/lib/academy/` (`GlossaryTerm`, `StudyModule`, `QA`, `Flashcard`, `Lab`). The existing `/academy/pca-risk` content is treated as **conformant legacy** that the new schema is backward-compatible with (§29).

## 25. Taxonomy

**Why this exists.** A shared classification vocabulary is what makes search, navigation, recommendation, and reporting possible. Without a controlled taxonomy, tags devolve into synonyms and the corpus becomes unsearchable.

**Standard — controlled, multi-axis taxonomy** (every artifact is classified on each axis; values come from fixed enums, not free text):

- **Domain** (24 values, the Scope Charter §5.1): `enterprise-it`, `enterprise-architecture`, `windows`, `linux`, `networking`, `active-directory`, `entra`, `iam`, `grc`, `sox`, `itgc`, `audit`, `dr-bcp`, `vendor-risk`, `vuln-mgmt`, `security-engineering`, `cloud-security`, `devsecops`, `threat-hunting`, `incident-response`, `forensics`, `leadership`, … (extensible — adding a value is a governed change, §19).
- **Difficulty** (§21): `L1`–`L5`.
- **Bloom** (§22): `remember`…`create`.
- **Content type:** `lesson`, `lab`, `exercise`, `assessment-item`, `flashcard`, `glossary`, `capstone`, `diagram`.
- **Framework mapping** (optional, repeatable): `nist-csf`, `nist-800-53`, `iso-27001`, `cis`, `mitre-attack`, `coso`, `pcaob`, … with the specific control/technique id.
- **Volatility** (§17): `evergreen`, `stable`, `volatile`.
- **Concept tags:** references to glossary `id`s (the spiral bookkeeping of §0.3/§4).

**How the best do it.** Library science (faceted classification — Ranganathan), NIST/MITRE controlled vocabularies, and Microsoft Learn’s role/product/level facets. Faceted (multi-axis) beats a single tree because real content is multi-dimensional.

**Scale.** Fixed enums + governed extension is what keeps tags consistent across thousands of artifacts and many authors; free-text tags do not scale.

## 26. Metadata Standards

**Why this exists.** Metadata is what makes content machine-usable — searchable, routable, gradable, and maintainable. It is the difference between a pile of prose and a queryable knowledge base.

**Standard.** Every artifact carries a **typed metadata header** with required and optional fields, validated at commit time. ID convention: `<domain>.<volume>.<chapter>.<slug>` (dot-namespaced, lowercase-kebab, globally unique, stable forever — IDs are never reused or repurposed; a retired ID stays retired).

**Canonical lesson metadata (illustrative TypeScript, extends the existing record style):**

```ts
export interface LessonMeta {
  id: string                    // "iam.entra-foundations.identity-basics.authn-vs-authz"
  title: string
  domain: Domain                // enum (§25)
  volume: string                // human title; volume id derivable from `id`
  chapter: string
  difficulty: 'L1'|'L2'|'L3'|'L4'|'L5'
  bloom: BloomLevel             // highest Bloom level of its outcomes
  outcomes: LearningOutcome[]   // { verb: BloomVerb; statement: string }
  estMinutes: number
  prerequisites: { to: string; hard: boolean }[]   // §23 (direct edges only)
  edges: DependencyEdge[]                            // §24 (recommends/reinforces/relatedTo)
  concepts: string[]            // glossary ids (§9)
  frameworks?: { framework: string; control: string }[]  // §25 mapping
  volatility: 'evergreen'|'stable'|'volatile'       // §17
  status: 'draft'|'in_review'|'approved'|'published'|'deprecated'|'archived' // §20
  version: string               // semver (§18)
  authors: string[]
  reviewedBy?: { tech?: string; editorial?: string; date?: string }
  reviewBy: string              // ISO date — when this must be re-checked (§17/§19)
  createdAt: string
  updatedAt: string
}
```

Glossary, flashcards, labs, and assessment items carry the **same shared subset** (`id`, `domain`, `difficulty`, `concepts`, `volatility`, `status`, `version`, `reviewBy`) so the whole corpus is queryable uniformly. The existing `GlossaryTerm`/`Lab`/`Flashcard`/`QA` interfaces are extended with these fields (additive; §29 keeps legacy records valid by treating missing fields as sensible defaults during a migration window).

**How the best do it.** Markdown frontmatter (Jekyll/Hugo/Docusaurus), schema.org/learning-resource metadata, IEEE LOM (Learning Object Metadata), and SCORM/xAPI in enterprise LMSs. We deliberately choose **typed records over loose frontmatter** because this repo already renders from typed data and TypeScript gives compile-time validation that frontmatter cannot.

**Scale.** Typed, validated metadata is the foundation everything else (search, graph, dashboards, review queues) computes from — it is the single highest-leverage standard for operating at scale.

## 27. Search Standards

**Why this exists.** At a few hundred lessons, browse works; at thousands, **search is the primary interface**. A corpus you can’t find your way into is, functionally, not there.

**Standard.** (1) **Faceted search** over the taxonomy (§25) — filter by domain, difficulty, content type, framework, concept — exactly the pattern the existing `GlossarySearch` component already implements client-side, generalized to all content. (2) **Full-text** over title, body, outcomes, and glossary definitions. (3) **Concept-aware** — searching a glossary term surfaces every lesson that teaches/reinforces it (via `concepts`), not just literal matches. (4) **Difficulty- and prerequisite-aware ranking** — results consider the learner’s position in the graph (don’t lead a novice to an L4 lesson). (5) **Local-first, no mandatory cloud dependency** — consistent with the project’s offline-capable retrieval ethic; search must work from the committed typed data. (6) Honest **empty states** and synonym handling (the SOC disambiguation problem, §9).

**How the best do it.** Microsoft Learn and AWS Skill Builder lead with faceted filters + search; documentation sites (Algolia DocSearch) lead with instant full-text. The Academy already has both the typed data and a working faceted-search component to build on.

**Scale.** Search is what *replaces* manual curation as the corpus grows — the metadata (§26) and taxonomy (§25) are precisely what make good search possible at thousands of items.

## 28. Navigation Standards

**Why this exists.** Even with search, learners need **orientation** — where am I, what’s the path, what’s next, how does this connect. Disorientation is a top cause of drop-off.

**Standard.** (1) **Persistent structural nav** (the volume/chapter tree) — the existing `AcademyShell` (desktop sidebar / mobile drawer) is the pattern. (2) **Breadcrumbs** (University › Domain › Volume › Chapter › Lesson) so position is always visible. (3) **"You are here / what’s next"** driven by the graph (§24) — next lesson, prerequisites you’re missing, what this unlocks. (4) **Multiple entry modes:** by track (role path), by domain (browse), by search (§27), by graph (visual map). (5) **Mobile-first and accessible** — keyboard navigable, screen-reader friendly, alt text on diagrams (§10); readable on a phone (the existing academy is already built mobile-first). (6) **Progress indication** — what’s done, what’s in progress (the existing `ProgressChecklist` localStorage pattern; server-backed when accounts are available).

**How the best do it.** Cisco NetAcad and Microsoft Learn provide path progress + breadcrumbs + next-unit affordances; good docs sites provide left-nav + breadcrumbs + on-page TOC. Multi-modal entry (path vs browse vs search) is the modern standard.

**Scale.** Navigation generated *from* the graph and taxonomy (not hand-built menus) is what keeps wayfinding correct as content grows — menus are computed, never manually maintained.

## 29. File Organization

**Why this exists.** Where files live determines how easy the corpus is to author, review, navigate in git, and reason about. A flat dump or an inconsistent tree makes a large corpus unmaintainable.

**Standard — mirror the taxonomy in the filesystem, reuse the existing location.** Content lives under the established `apps/web/src/lib/academy/` root (rendered by routes under `apps/web/src/app/academy/`). The directory tree mirrors **domain → volume → chapter**, with shared cross-cutting stores (glossary, assessment bank) at the domain or academy root:

```
apps/web/src/lib/academy/
  _schema/                      # shared TS types + enums (Appendix A/B) — single source
  glossary/                     # canonical glossary, partitioned by domain
  <domain>/                     # e.g. iam/, grc/, cloud-security/
    <volume>/                   # e.g. entra-foundations/
      <chapter>/                # e.g. identity-basics/
        <lesson>.ts             # one typed lesson record per file (§8/§26)
        labs/  exercises/  assessments/
      volume.ts                 # volume metadata + capstone (§6/§14)
  tracks/                       # role paths = ordered graph traversals (§5)
  pca-risk/                     # EXISTING content — conformant legacy, unmoved (§29 below)
```

(1) **One lesson per file**, named by slug, id-stable (§26). (2) **Co-locate** a lesson’s labs/exercises/assessments near it. (3) **Shared schema in one place** (`_schema/`) so all records import the same types. (4) **The existing `pca-risk/` tree is not disturbed** — it is declared conformant legacy and migrated *incrementally* (add metadata fields over time) rather than relocated, so nothing breaks and PR #36’s shipped content keeps working. (5) Large/rendered artifacts follow the repo’s "regenerable, gitignored" rule; **source (typed records, diagram-as-code) is committed.**

**How the best do it.** Docs-as-code repos (Docusaurus/Hugo content trees), monorepo module layout, and "folder = navigation" conventions. Mirroring the taxonomy in the tree means the filesystem *is* a navigable index.

**Scale.** A taxonomy-mirrored tree with one-record-per-file is what keeps thousands of files reviewable (small diffs), parallel-authorable (few merge conflicts), and reasoned-about (path tells you everything).

---

# PART VII — THE FUTURE

## 30. Future Expansion Strategy

**Why this exists.** The single most important property of a foundational document is that it **doesn’t need to be rewritten** to grow. Phase 0’s final job is to guarantee its own extensibility and to be honest about how the Academy expands without breaking.

**Standard / strategy.**

1. **Depth-first, thin vertical slices.** Ship a *complete path to one competence* (e.g. the SOX-IT-auditor track, which the existing pca-risk content already seeds) before broadening. A working narrow Academy beats a sprawling unfinished one (§0.6). Each slice proves the standards end-to-end.
2. **Domains are added as peers, never as forks.** A new domain (say OT/ICS, or AI security) is a new value in the `Domain` enum (§25) and a new subtree (§29); it inherits every standard unchanged. The architecture was designed in §5 to make this a non-event.
3. **The graph absorbs cross-links automatically.** New content connects to existing competencies via edges (§24) without reorganizing anything.
4. **Volatility-driven maintenance keeps the corpus trustworthy as it grows** (§17/§19) — growth and decay are managed by the same `reviewBy`/`volatility` queue, so comprehensiveness never outruns correctness.
5. **Personalization and adaptivity are future layers, pre-enabled now.** Because we capture outcomes, difficulty, prerequisites, the graph, and (eventually) learner mastery state, adaptive pathing, recommendation, and analytics can be added later *without re-authoring content* — the data model anticipated them.
6. **AI-assisted authoring at scale, human-governed.** The schema + standards are explicitly designed so drafting can be accelerated (AI generates a conformant skeleton; humans do technical/editorial review §16/§17). This is how the corpus reaches thousands of lessons without thousands of author-years — *and* the review gates are what keep AI-drafted content honest.
7. **Internationalization & accessibility are structural, not bolted-on.** Typed records separate content from presentation, so translation and a11y (§28) are additive.
8. **Governed evolution of Phase 0 itself.** When reality demands a new standard, it is added here via the §19 amendment process and versioned (§18) — the constitution grows deliberately, never by drift.

**How the best do it.** Microsoft Learn, AWS, and Cisco continuously expand role paths and products onto a stable platform; they almost never rebuild the platform. The platform stability is the asset. Phase 0 *is* that platform for the Academy.

**Scale (the whole point).** Everything above — graph substrate, typed metadata, controlled taxonomy, computed navigation, volatility-driven maintenance, gated publishing, AI-draftable/human-reviewed pipeline — exists so the Academy can reach thousands of lessons across 24+ domains while staying **correct, navigable, and trustworthy**. That, not raw page count, is what "the most comprehensive enterprise cybersecurity university" actually requires.

---

# APPENDICES (implementable reference)

## Appendix A — Canonical enums (proposed `_schema/`)

```ts
export type Difficulty = 'L1' | 'L2' | 'L3' | 'L4' | 'L5'
export type BloomLevel = 'remember'|'understand'|'apply'|'analyze'|'evaluate'|'create'
export type Volatility = 'evergreen' | 'stable' | 'volatile'
export type ContentStatus =
  'draft'|'in_review'|'approved'|'published'|'deprecated'|'archived'
export type EdgeType = 'requires' | 'recommends' | 'reinforces' | 'relatedTo'
export type Domain =
  | 'enterprise-it' | 'enterprise-architecture' | 'windows' | 'linux'
  | 'networking' | 'active-directory' | 'entra' | 'iam' | 'grc' | 'sox'
  | 'itgc' | 'audit' | 'dr-bcp' | 'vendor-risk' | 'vuln-mgmt'
  | 'security-engineering' | 'cloud-security' | 'devsecops' | 'threat-hunting'
  | 'incident-response' | 'forensics' | 'leadership'
```

## Appendix B — Lesson record skeleton (what an author fills in)

```ts
export const lesson: LessonMeta & { sections: LessonSection[] } = {
  id: 'iam.entra-foundations.identity-basics.authn-vs-authz',
  title: 'Authentication vs Authorization',
  domain: 'iam', volume: 'Entra Foundations', chapter: 'Identity Basics',
  difficulty: 'L1', bloom: 'understand',
  outcomes: [
    { verb: 'explain', statement: 'Explain the difference between authentication and authorization and why authN precedes authZ.' },
    { verb: 'classify', statement: 'Classify a given control as authN or authZ.' },
  ],
  estMinutes: 12,
  prerequisites: [{ to: 'iam.entra-foundations.identity-basics.what-is-an-account', hard: true }],
  edges: [{ to: 'iam.entra-foundations.access.rbac', type: 'reinforces' }],
  concepts: ['authentication', 'authorization', 'mfa'],
  frameworks: [{ framework: 'nist-800-53', control: 'AC-3' }],
  volatility: 'evergreen', status: 'draft', version: '0.1.0',
  authors: ['<author>'], reviewBy: '2027-06-26',
  createdAt: '2026-06-26', updatedAt: '2026-06-26',
  sections: [/* hook/WHY, exposition, diagram, worked example, retrieval, summary (§8) */],
}
```

## Appendix C — Authoring quick-checklist (lifted from the standards)

Before a lesson can leave `draft`: WHY/threat-model present (§2) · 1–4 Bloom-verbed outcomes meeting the difficulty Bloom-floor (§21/§22) · one core idea (§8) · ≥1 diagram if structural (§10) · worked example (§13) · ≥2 retrieval checkpoints (§3/§12) · lab/exercise pointer with verification (§11/§13) · all terms glossary-linked (§9) · metadata complete + schema-valid (§26) · prerequisites resolve & no cycle (§23/§24) · citations for factual claims + `reviewBy`/`volatility` set (§17) · passes technical + editorial review (§16).

---

*End of Phase 0. This document governs; lessons obey. Amend deliberately (§19), version honestly (§18), and never let comprehensiveness outrun correctness (§0.6, §17).*
