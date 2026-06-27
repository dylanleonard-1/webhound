// Phase 2B — the Lesson Design Brief ("Author Brain" output).
// UPSTREAM of the Phase 2A lesson-schema: the brief answers "what must this lesson
// accomplish?"; lesson-schema.ts is the downstream "shape of the lesson". Every
// future lesson MUST have a passing brief before content is written.
// Governed by Phase 0/1/2A. Reuses existing enums — introduces NO new vocabularies.
// STANDALONE: not imported by any route/app runtime.

import type { Difficulty, BloomLevel, Volatility, Score1to5 } from '../_graph/types'
import type { LessonProfile, DiagramKind } from './lesson-schema'

// 1 — Lesson Identity
export interface BriefIdentity {
  lessonId: string // <domain>.<volume>.<chapter>.<slug> (Phase 0 §26)
  graphNodeId: string // MUST reference a _graph node (Phase 1 link)
  volume: string
  module: string
  chapter: string
  lesson: string // human title
  version: string // semver
}

// 2 — Purpose
export interface BriefPurpose {
  whyExists: string
  whyLearnerNeeds: string
  futureDependents: string[] // graph node ids of lessons that depend on this one
  businessProblem: string
}

// 3 — Target Audience
export interface BriefAudience {
  primaryRoles: string[] // e.g. help-desk, sysadmin, iam-analyst, it-auditor, CISO
  level: Difficulty // the band this lesson serves
}

// 4 — Prerequisite Knowledge (pulled from graph edges)
export interface BriefPrerequisites {
  required: string[] // graph node ids (hard)
  recommended: string[] // graph node ids (soft)
  optional: string[] // graph node ids (nice-to-have)
}

// 5 — Learning Outcomes (Bloom-aligned, measurable)
export interface BriefOutcome {
  verb: string // Bloom verb (no "understand")
  statement: string // measurable
  bloom: BloomLevel
}

// 6 — Business Context
export interface BriefBusinessContext {
  departments: string[] // Finance/HR/Manufacturing/IT/Security/Executive/Audit/Compliance
  note: string
}

// 7 — Enterprise Context
export interface BriefEnterpriseContext {
  whereItLives: string // where in the enterprise stack this concept lives
  owner: string // who owns it
  maintainer: string // who maintains it
  auditor: string // who audits/assures it
}

// 8 — Interview Intelligence
export interface BriefInterviewIntel {
  probability: Score1to5 // ★1–5 likelihood in interviews
  likelyQuestions: string[]
  traps: string[]
  strongAnswerTraits: string[]
  weakAnswerTraits: string[]
  followUps: string[]
}

// 9 — Vocabulary Intelligence
export interface BriefVocabIntel {
  core: string[]
  supporting: string[]
  business: string[]
  audit: string[]
  risk: string[]
  acronyms: string[]
  commonConfusion: string[]
}

// 10 — Misconception Intelligence
export interface BriefMisconception {
  misconception: string
  correction: string
}

// 11 — Diagram Intelligence
export interface BriefDiagramNeed {
  kind: DiagramKind
  why: string
}

// 12 — Lab Intelligence
// Phase 2C widened LabIntent additively (added 'thought-exercise', 'case-study');
// pre-existing values are unchanged, so older briefs remain valid.
export type LabIntent =
  | 'none' | 'thought-exercise' | 'guided' | 'enterprise' | 'scenario' | 'case-study' | 'capstone'
export interface BriefLabIntel {
  type: LabIntent
  why: string
}

// 13 — Cross-Link Intelligence
export interface BriefCrossLinks {
  previous: string[] // prior lesson/node ids
  future: string[] // downstream lesson/node ids
  related: string[] // lateral lesson/node ids
  domains: string[] // domain ids touched
  vocab: string[] // glossary ids
  interviewTopics: string[]
}

// 14 — Difficulty Intelligence
export interface BriefDifficultyIntel {
  bloom: BloomLevel
  difficulty: Difficulty
  studyMinutes: number
  readingMinutes: number
  labMinutes: number
  reviewMinutes: number
}

// 15 — Writing Guidance
export interface BriefWritingGuidance {
  profile: LessonProfile // drives Phase 2A conditional sections
  instructions: string[] // e.g. "teach business before tech", "WHY before HOW"
}

// ── Phase 2C — Golden-brief enrichment (OPTIONAL, additive authoring layer) ───
// This is NOT an architecture change: `enrichment` is an optional field, so every
// brief written against the original 15-section schema (e.g. lesson-brief.example.json)
// still validates unchanged. It captures the deeper authoring intelligence the
// "golden" reference briefs carry — expressed alongside, not instead of, the core
// sections. The validator only checks enrichment when it is present.
export type Industry = 'Manufacturing' | 'Finance' | 'Healthcare' | 'Government' | 'Technology'

export interface BriefIndustryScenario {
  industry: Industry
  scenario: string // a realistic, concrete situation in that industry
}

// The four stakeholder views on the concept.
export interface BriefAuditContext {
  internalAudit: string
  externalAudit: string
  compliance: string
  executive: string
}

// What's IN, what's OUT, what FUTURE lessons teach instead — anti-scope-creep.
export interface BriefEducationalBoundaries {
  inScope: string[]
  outOfScope: string[]
  deferredToFuture: string[] // ideally references future lesson/node ids
}

export interface BriefTeachingStrategy {
  order: string[] // the teaching beats, in sequence
  whyThisSequence: string // the pedagogical reason for that order
  analogyPoints: string[] // where an analogy belongs
  mandatoryDiagramsAt: string[] // beats where a diagram becomes non-optional
}

export interface BriefDiagramDetail {
  kind: DiagramKind
  complexity: 'low' | 'medium' | 'high'
  learningObjective: string // the single thing this diagram must make clear
}

export interface BriefInterviewAnswers {
  averageAnswer: string // what a passable candidate says
  exceptionalAnswer: string // what a standout candidate says
}

// The one idea the learner should still hold in five years.
export interface BriefEnrichment {
  mentalModel: string
  educationalBoundaries: BriefEducationalBoundaries
  teachingStrategy: BriefTeachingStrategy
  industryContext: BriefIndustryScenario[]
  auditContext: BriefAuditContext
  vocabAdvanced: string[] // the "advanced" tier beyond core/supporting
  interviewAnswers: BriefInterviewAnswers
  diagramDetail: BriefDiagramDetail[]
}

// ── The Lesson Design Brief (all 15 sections) ────────────────────────────────
export interface LessonDesignBrief {
  schema: 'webhound.academy.lessonBrief.v1'
  status: 'draft' | 'approved' // 'approved' = passed the quality gates (Del. 4)
  volatility: Volatility
  reviewBy: string // ISO date
  identity: BriefIdentity // 1
  purpose: BriefPurpose // 2
  audience: BriefAudience // 3
  prerequisites: BriefPrerequisites // 4
  outcomes: BriefOutcome[] // 5
  businessContext: BriefBusinessContext // 6
  enterpriseContext: BriefEnterpriseContext // 7
  interviewIntel: BriefInterviewIntel // 8
  vocabIntel: BriefVocabIntel // 9
  misconceptions: BriefMisconception[] // 10
  diagramNeeds: BriefDiagramNeed[] // 11
  labIntel: BriefLabIntel // 12
  crossLinks: BriefCrossLinks // 13
  difficultyIntel: BriefDifficultyIntel // 14
  writingGuidance: BriefWritingGuidance // 15
  enrichment?: BriefEnrichment // Phase 2C — optional, golden-brief authoring layer
}

// Quality gates (Del. 4) — the brief must pass ALL to unblock lesson generation.
export const BRIEF_GATES: string[] = [
  'identity.graphNodeId present',
  'purpose.whyExists + businessProblem present',
  'purpose.futureDependents identified (may be empty only for terminal leaves)',
  'prerequisites object present (required/recommended/optional arrays)',
  'outcomes >=1, each Bloom-verbed + measurable (no "understand")',
  'businessContext.departments non-empty',
  'enterpriseContext owner/maintainer/auditor present',
  'interviewIntel.probability assigned (1–5)',
  'vocabIntel.core non-empty',
  'diagramNeeds selected (>=1) OR explicitly justified empty',
  'labIntel.type selected',
  'difficultyIntel difficulty+bloom+times present',
  'writingGuidance.profile + >=1 instruction',
]
