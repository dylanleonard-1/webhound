// Private study academy — typed content model. Pure data + types, no runtime deps.
// Pages render from these so content is easy to expand.

export type ModuleSlug =
  | 'sox-icfr'
  | 'gitc'
  | 'audit'
  | 'iam'
  | 'change-management'
  | 'dr-backup'
  | 'vendor-risk'
  | 'tools'

export interface GlossaryTerm {
  term: string
  short: string // one-line gist for cards
  definition: string // full definition
  category: string // e.g. "SOX", "GITC", "Audit", "IAM", "SOC"
  also?: string // common confusion / "not to be confused with"
}

export interface QA {
  q: string
  a: string
}

export interface ModuleSection {
  heading: string
  body: string[] // paragraphs
  bullets?: string[]
}

export interface StudyModule {
  slug: ModuleSlug
  title: string
  tagline: string
  phase: number // maps to roadmap phase
  minutes: number // est. study time
  sections: ModuleSection[]
  keyTerms: string[] // glossary term names
  interview: QA[]
}

export interface RoadmapPhase {
  n: number
  title: string
  goal: string
  topics: string[]
  moduleSlug?: ModuleSlug
}

export interface InterviewCategory {
  id: string
  title: string
  blurb: string
  questions: QA[]
}

export interface Flashcard {
  front: string
  back: string
}

export interface FlashcardGroup {
  module: string
  cards: Flashcard[]
}

export interface Lab {
  id: string
  title: string
  scenario: string
  goal: string
  steps: string[]
  deliverable: string
  tip?: string
}
