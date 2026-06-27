# Academy Content Engine — `_content/`

Phase 2A reusable schema for authoring lessons. Standalone (not imported by routes).
Full standard: `docs/academy/PHASE_2A_CONTENT_ENGINE.md`.

- `lesson-schema.ts` — typed `Lesson` model: metadata (links to a `_graph` node via
  `graphNodeId`), 46 section keys, the **tiered section registry** (`SECTION_RULES`:
  core vs conditional vs recommended), `LessonProfile` + `PROFILE_DEFAULT_SECTIONS`,
  and sub-models (DiagramRef, QuizItem, FlashcardItem, InterviewItem). Reuses
  `_graph/types.ts` enums (Difficulty, BloomLevel, Volatility, Score1to5).
- `lesson-template.json` — blank skeleton (CORE sections) to copy.
- `lesson-example.template.json` — a filled MINIMAL example (clearly marked
  TEMPLATE-EXAMPLE, NOT real content) showing the shape for an L1 concept.

Authoring rule (anti-bloat, Phase 0 §0.6): **CORE sections on every lesson; add
conditional sections per the lesson's `profile` + each section's `rule`.** Do NOT
write all 46 sections on an L1 atom.
