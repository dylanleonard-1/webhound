// Phase 2A — the permanent lesson schema every future Academy lesson conforms to.
// Governed by Phase 0 (constitution) + Phase 1 (graph). Reuses _graph/types.ts
// enums and links to graph node ids via `graphNodeId`. STANDALONE: not imported by
// any route/app runtime — schema + tooling only.

import type { Difficulty, BloomLevel, Volatility, Score1to5 } from '../_graph/types'

// ── Learning objectives (Bloom-verbed, Phase 0 §22) ──────────────────────────
export interface LearningObjective {
  verb: string // a Bloom verb (define/explain/apply/analyze/evaluate/create family)
  statement: string // measurable; NEVER "understand X"
}

// ── The 46 sections (metadata + 45 content sections) ─────────────────────────
// `metadata` is section 1 (the header); the rest are content blocks.
export type SectionKey =
  | 'metadata'
  | 'learningObjectives' | 'executiveSummary' | 'whyThisExists' | 'historicalBackground'
  | 'definitions' | 'vocabulary' | 'coreConcept' | 'howItWorks'
  | 'enterpriseArchitecture' | 'enterpriseWorkflow'
  | 'exampleMicrosoft' | 'exampleLinuxOSS' | 'exampleCloud' | 'exampleManufacturing'
  | 'exampleFinancial' | 'exampleHealthcare' | 'exampleGovernment'
  | 'perspectiveSecurity' | 'perspectiveGovernance' | 'perspectiveRisk'
  | 'perspectiveAudit' | 'perspectiveOperations' | 'perspectiveLeadership'
  | 'commonMisunderstandings' | 'commonMistakes' | 'bestPractices'
  | 'realWorldCaseStudy' | 'enterpriseChecklist' | 'auditChecklist'
  | 'implementationWalkthrough' | 'monitoring' | 'validation' | 'evidence'
  | 'handsOnLab' | 'reflectionQuestions' | 'knowledgeCheck' | 'practicalExercise'
  | 'scenarioExercise' | 'whiteboardExercise' | 'interviewQuestions'
  | 'chapterSummary' | 'flashcards' | 'relatedLessons' | 'references' | 'revisionHistory'

/** How a section is governed across the corpus (the anti-bloat tiering). */
export type SectionTier =
  | 'core' // REQUIRED on every published lesson, every difficulty band
  | 'conditional' // included only when its rule is met (band/domain/concept-type)
  | 'recommended' // include unless there is a reason not to

export interface SectionRule {
  key: SectionKey
  tier: SectionTier
  /** Human-readable inclusion rule (also enforceable by the lint script). */
  rule: string
}

// Concept "profile" drives which conditional sections apply (anti-bloat, Phase 0 §0.6).
export type LessonProfile =
  | 'concept-foundation' // L1 atomic idea — lean
  | 'concept-standard' // L2 practitioner concept
  | 'concept-deep' // L3-L4 analysis/architecture concept
  | 'procedure' // a how-to / implementation lesson
  | 'control-audit' // a control/evidence/audit lesson (ITGC, SOX, etc.)
  | 'leadership' // L5 program/strategy lesson

// ── The canonical section registry (core vs conditional + the rule) ──────────
export const SECTION_RULES: SectionRule[] = [
  { key: 'metadata', tier: 'core', rule: 'Always. The typed header below.' },
  { key: 'learningObjectives', tier: 'core', rule: 'Always. 1–4 Bloom-verbed, meeting the difficulty Bloom-floor.' },
  { key: 'whyThisExists', tier: 'core', rule: 'Always. Threat-model / business reason (Phase 0 WHY-before-HOW doctrine).' },
  { key: 'coreConcept', tier: 'core', rule: 'Always. The one core idea (Phase 0 §8 one-idea rule).' },
  { key: 'definitions', tier: 'core', rule: 'Always. Define every new term before use.' },
  { key: 'vocabulary', tier: 'core', rule: 'Always. Glossary-linked terms (Phase 0 §9).' },
  { key: 'knowledgeCheck', tier: 'core', rule: 'Always. >=2 retrieval items (testing effect, Phase 0 §3/§12).' },
  { key: 'commonMisunderstandings', tier: 'core', rule: 'Always. At least one (security is jargon-dangerous).' },
  { key: 'chapterSummary', tier: 'core', rule: 'Always. Compress the idea + connections.' },
  { key: 'relatedLessons', tier: 'core', rule: 'Always. Derived from graph edges (related/reinforces).' },
  { key: 'references', tier: 'core', rule: 'Always when factual claims exist. Authoritative sources (Phase 0 §17).' },
  { key: 'revisionHistory', tier: 'core', rule: 'Always. Semver + reviewBy (Phase 0 §18/§19).' },
  { key: 'flashcards', tier: 'recommended', rule: 'Recommended for all — spaced repetition (Phase 0 §12.4).' },
  { key: 'executiveSummary', tier: 'recommended', rule: 'Recommended L2+; optional for tiny L1 atoms.' },

  { key: 'howItWorks', tier: 'conditional', rule: 'When the concept has mechanism/flow (most L2+). Skip for pure definitions.' },
  { key: 'enterpriseArchitecture', tier: 'conditional', rule: 'When structural/architectural (profile concept-deep/procedure).' },
  { key: 'enterpriseWorkflow', tier: 'conditional', rule: 'When there is a process/lifecycle (procedure, control-audit).' },
  { key: 'historicalBackground', tier: 'conditional', rule: 'When history aids understanding (e.g. SOX, Kerberos origins). Optional for L1.' },
  { key: 'exampleMicrosoft', tier: 'conditional', rule: 'Pick the 1–3 RELEVANT industry/platform examples — NOT all seven.' },
  { key: 'exampleLinuxOSS', tier: 'conditional', rule: 'Include when the concept has a Linux/OSS manifestation.' },
  { key: 'exampleCloud', tier: 'conditional', rule: 'Include when cloud-relevant.' },
  { key: 'exampleManufacturing', tier: 'conditional', rule: 'Include for OT/plant-relevant concepts (PCA context).' },
  { key: 'exampleFinancial', tier: 'conditional', rule: 'Include for finance/SOX-relevant concepts.' },
  { key: 'exampleHealthcare', tier: 'conditional', rule: 'Include only when healthcare context adds signal (HIPAA, etc.).' },
  { key: 'exampleGovernment', tier: 'conditional', rule: 'Include only when gov/FedRAMP/CMMC context is relevant.' },
  { key: 'perspectiveSecurity', tier: 'conditional', rule: 'Include the RELEVANT perspectives for the concept — not all six by rote.' },
  { key: 'perspectiveGovernance', tier: 'conditional', rule: 'Include for governance/policy-relevant concepts.' },
  { key: 'perspectiveRisk', tier: 'conditional', rule: 'Include for risk-bearing concepts.' },
  { key: 'perspectiveAudit', tier: 'conditional', rule: 'Required for control-audit profile; else when audit-relevant.' },
  { key: 'perspectiveOperations', tier: 'conditional', rule: 'Include for operational concepts.' },
  { key: 'perspectiveLeadership', tier: 'conditional', rule: 'Required for leadership profile; optional otherwise.' },
  { key: 'commonMistakes', tier: 'conditional', rule: 'When there are real operational pitfalls (most L2+).' },
  { key: 'bestPractices', tier: 'conditional', rule: 'When actionable practices exist (most L2+).' },
  { key: 'realWorldCaseStudy', tier: 'conditional', rule: 'Required L3+; may reuse a shared case study (see _content/case-studies).' },
  { key: 'enterpriseChecklist', tier: 'conditional', rule: 'When the concept yields a checklist (procedure/control-audit).' },
  { key: 'auditChecklist', tier: 'conditional', rule: 'Required for control-audit profile.' },
  { key: 'implementationWalkthrough', tier: 'conditional', rule: 'Required for procedure profile.' },
  { key: 'monitoring', tier: 'conditional', rule: 'When the control/system is monitored (security/ops concepts).' },
  { key: 'validation', tier: 'conditional', rule: 'When success is verifiable (procedure/control-audit).' },
  { key: 'evidence', tier: 'conditional', rule: 'Required for control-audit profile (what an auditor collects).' },
  { key: 'handsOnLab', tier: 'conditional', rule: 'Required when the graph node has lab=true (Phase 1 metadata).' },
  { key: 'reflectionQuestions', tier: 'conditional', rule: 'Recommended L2+; metacognition prompts.' },
  { key: 'practicalExercise', tier: 'conditional', rule: 'Required when node has lab=true OR profile=procedure/control-audit.' },
  { key: 'scenarioExercise', tier: 'conditional', rule: 'Required L3+ (Analyze/Evaluate practice).' },
  { key: 'whiteboardExercise', tier: 'conditional', rule: 'Required L3+ for architecture/design concepts; else optional.' },
  { key: 'interviewQuestions', tier: 'conditional', rule: 'Required when node interviewProb >= 3 OR difficulty >= L3.' },
]

/** Which conditional sections each profile turns ON by default (authoring guide;
 *  the per-lesson author still applies the per-section `rule`). */
export const PROFILE_DEFAULT_SECTIONS: Record<LessonProfile, SectionKey[]> = {
  'concept-foundation': ['executiveSummary'],
  'concept-standard': ['executiveSummary', 'howItWorks', 'commonMistakes', 'bestPractices', 'reflectionQuestions', 'flashcards'],
  'concept-deep': ['executiveSummary', 'howItWorks', 'enterpriseArchitecture', 'commonMistakes', 'bestPractices', 'realWorldCaseStudy', 'scenarioExercise', 'whiteboardExercise', 'reflectionQuestions', 'flashcards', 'interviewQuestions'],
  'procedure': ['howItWorks', 'enterpriseWorkflow', 'implementationWalkthrough', 'enterpriseChecklist', 'validation', 'monitoring', 'handsOnLab', 'practicalExercise', 'bestPractices', 'commonMistakes'],
  'control-audit': ['enterpriseWorkflow', 'perspectiveAudit', 'auditChecklist', 'evidence', 'validation', 'realWorldCaseStudy', 'scenarioExercise', 'interviewQuestions', 'commonMistakes', 'bestPractices'],
  'leadership': ['executiveSummary', 'perspectiveLeadership', 'perspectiveGovernance', 'perspectiveRisk', 'realWorldCaseStudy', 'scenarioExercise', 'reflectionQuestions'],
}

// ── A rendered content block (markdown body + optional structured payload) ────
export interface SectionContent {
  key: SectionKey
  body?: string // markdown prose
  items?: string[] // bullet/checklist/step content where applicable
  data?: unknown // structured payload (e.g. quiz items, flashcards, diagram refs)
}

// ── Sub-models referenced by sections ────────────────────────────────────────
export type DiagramKind =
  | 'architecture' | 'process-flow' | 'network' | 'identity-flow' | 'timeline'
  | 'risk-matrix' | 'control-matrix' | 'decision-tree' | 'audit-workflow'
  | 'enterprise-data-flow' | 'swimlane'
export interface DiagramRef {
  kind: DiagramKind
  title: string
  altText: string // accessibility (Phase 0 §28)
  src: string // diagram-as-code path (e.g. mermaid) — versionable
}
export type QuizItemType = 'recall' | 'multiple-choice' | 'multi-select' | 'scenario' | 'short-answer'
export interface QuizItem {
  type: QuizItemType
  bloom: BloomLevel
  prompt: string
  options?: string[]
  answer: string | string[]
  rationale: string // why right/wrong (feedback drives learning, Phase 0 §12.6)
  outcomeRef: string // traces to a LearningObjective (no orphan items)
}
export interface FlashcardItem {
  front: string
  back: string
  difficulty: Difficulty
  tags: string[]
  memoryAid?: string
  commonConfusion?: string
  related: string[] // graph node ids / glossary ids
}
export interface InterviewItem {
  category: 'hr' | 'technical' | 'scenario' | 'whiteboard' | 'behavioral'
  question: string
  strongAnswer: string
  weakAnswerExample?: string
  followUps?: string[]
}

// ── The Lesson (metadata header + sections) ──────────────────────────────────
export interface LessonMetadata {
  id: string // <domain>.<volume>.<chapter>.<slug> (Phase 0 §26)
  graphNodeId: string // MUST match an existing _graph node id (Phase 1 link)
  title: string
  domain: string // must exist in _graph/domains.json
  module: string
  chapter: string
  difficulty: Difficulty
  bloom: BloomLevel
  profile: LessonProfile
  estMinutes: number
  prerequisites: string[] // graph node ids
  relatedLessons: string[] // graph node ids
  volatility: Volatility
  status: 'draft' | 'in_review' | 'approved' | 'published' | 'deprecated' | 'archived'
  version: string // semver
  authors: string[]
  reviewBy: string // ISO date
  importance?: { ent: Score1to5; bus: Score1to5; sec: Score1to5; aud: Score1to5; int: Score1to5 }
  /** OPTIONAL, additive (backward-compatible): a Golden-Lesson certification stamp,
   *  e.g. "WebHound Enterprise Security Academy — Golden Lesson Reference v1.0".
   *  Absent on uncertified lessons; does not change any existing lesson's validity. */
  certification?: string
}
export interface Lesson {
  metadata: LessonMetadata
  objectives: LearningObjective[]
  sections: SectionContent[] // each key must satisfy SECTION_RULES (core present)
  diagrams?: DiagramRef[]
  quiz?: QuizItem[]
  flashcards?: FlashcardItem[]
  interview?: InterviewItem[]
}

// Convenience: the set of always-required section keys (for a validator/lint).
export const CORE_SECTIONS: SectionKey[] =
  SECTION_RULES.filter((s) => s.tier === 'core').map((s) => s.key)
