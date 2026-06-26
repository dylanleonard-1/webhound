// Barrel + navigation config for the private PCA Risk study academy.
export * from './types'
export { GLOSSARY } from './glossary'
export { MODULES, MODULE_SLUGS, getModule } from './modules'
export { ROADMAP } from './roadmap'
export { INTERVIEW } from './interview'
export { FLASHCARDS } from './flashcards'
export { LABS } from './labs'

import { MODULES } from './modules'

export const ACADEMY_BASE = '/academy/pca-risk'

export interface NavItem {
  label: string
  href: string
  children?: { label: string; href: string }[]
}

export const ACADEMY_NAV: NavItem[] = [
  { label: 'Dashboard', href: ACADEMY_BASE },
  { label: 'Roadmap', href: `${ACADEMY_BASE}/roadmap` },
  {
    label: 'Modules',
    href: `${ACADEMY_BASE}/modules/${MODULES[0].slug}`,
    children: MODULES.map((m) => ({ label: m.title, href: `${ACADEMY_BASE}/modules/${m.slug}` })),
  },
  { label: 'Glossary', href: `${ACADEMY_BASE}/glossary` },
  { label: 'Interview Prep', href: `${ACADEMY_BASE}/interview` },
  { label: 'Flashcards', href: `${ACADEMY_BASE}/flashcards` },
  { label: 'Labs', href: `${ACADEMY_BASE}/labs` },
]

// High-yield terms surfaced on the dashboard.
export const HIGH_YIELD_TERMS = [
  'SOX 404', 'ICFR', 'GITC', 'Test of Operating Effectiveness', 'access review',
  'deprovisioning', 'SOC 1', 'Type II', 'CUEC', 'RTO', 'RPO', 'material weakness',
]

// "Today's study checklist" seed items (progress stored in localStorage, no DB).
export const STUDY_CHECKLIST = [
  'Read the SOX & ICFR module end to end',
  'Memorize the COSO five components',
  'Drill the Identity & Access flashcards',
  'Explain ToD vs ToE out loud without notes',
  'Do the terminated-user sample lab',
  'Review SOC 1 vs SOC 2 vs SOC 3 + Type I/II',
  'Rehearse "tell me about yourself" in your own voice',
]
