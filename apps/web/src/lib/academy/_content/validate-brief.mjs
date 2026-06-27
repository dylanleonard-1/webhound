#!/usr/bin/env node
// Phase 2B — Lesson Design Brief quality-gate validator.
// BLOCKS lesson generation if the brief is incomplete. Pure Node, no deps, no
// network, no app imports — same pattern as _graph/validate.mjs (Phase 1.5).
//
// Usage:  node src/lib/academy/_content/validate-brief.mjs [path-to-brief.json]
//   Default target: ./lesson-brief.example.json (next to this file).
// Exit code: 0 = all gates pass; 1 = one or more gates failed (BLOCKED).

import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const GRAPH = resolve(HERE, '..', '_graph')

const BLOOM = ['remember', 'understand', 'apply', 'analyze', 'evaluate', 'create']
const DIFF = ['L1', 'L2', 'L3', 'L4', 'L5']
const VOLAT = ['evergreen', 'stable', 'volatile']
const LABS = ['none', 'thought-exercise', 'guided', 'enterprise', 'scenario', 'case-study', 'capstone']
const INDUSTRIES = ['Manufacturing', 'Finance', 'Healthcare', 'Government', 'Technology']
const COMPLEXITY = ['low', 'medium', 'high']
const PROFILES = [
  'concept-foundation', 'concept-standard', 'concept-deep',
  'procedure', 'control-audit', 'leadership',
]

const errors = []
const warnings = []
const err = (g, m) => errors.push(`[GATE: ${g}] ${m}`)
const warn = (m) => warnings.push(m)
const str = (v) => typeof v === 'string' && v.trim().length > 0
const arr = (v) => Array.isArray(v)
const nonEmpty = (v) => arr(v) && v.length > 0

function loadGraphNodeIds() {
  try {
    const raw = JSON.parse(readFileSync(resolve(GRAPH, 'nodes.json'), 'utf8'))
    const list = Array.isArray(raw) ? raw : raw.nodes || []
    return new Set(list.map((n) => n.id))
  } catch {
    return null // graph not loadable from here — skip the soft cross-check
  }
}
function loadGraphDomainIds() {
  try {
    const raw = JSON.parse(readFileSync(resolve(GRAPH, 'domains.json'), 'utf8'))
    const list = Array.isArray(raw) ? raw : raw.domains || []
    return new Set(list.map((d) => d.id))
  } catch {
    return null
  }
}

function validate(b) {
  if (b == null || typeof b !== 'object') {
    err('schema', 'brief is not a JSON object')
    return
  }
  if (b.schema !== 'webhound.academy.lessonBrief.v1') {
    err('schema', `schema must be "webhound.academy.lessonBrief.v1" (got ${JSON.stringify(b.schema)})`)
  }
  if (!['draft', 'approved'].includes(b.status)) err('status', 'status must be "draft" or "approved"')
  if (!VOLAT.includes(b.volatility)) err('volatility', `volatility must be one of ${VOLAT.join('/')}`)
  if (!/^\d{4}-\d{2}-\d{2}$/.test(b.reviewBy || '')) warn('reviewBy missing or not YYYY-MM-DD — freshness loop is unscheduled')

  // 1 — identity / graphNodeId present (HARD)
  const id = b.identity || {}
  for (const k of ['lessonId', 'volume', 'module', 'chapter', 'lesson', 'version']) {
    if (!str(id[k])) err('identity', `identity.${k} is required`)
  }
  if (!str(id.graphNodeId)) {
    err('identity.graphNodeId present', 'identity.graphNodeId is required (Phase 1 link)')
  } else {
    const nodes = loadGraphNodeIds()
    const domains = loadGraphDomainIds()
    if (nodes && !nodes.has(id.graphNodeId)) {
      const domainPrefix = id.graphNodeId.split('.')[0]
      if (domains && domains.has(domainPrefix)) {
        warn(`graphNodeId "${id.graphNodeId}" not yet enumerated as a leaf node, but domain "${domainPrefix}" exists (scaffolded) — acceptable`)
      } else {
        err('identity.graphNodeId present', `graphNodeId "${id.graphNodeId}" resolves to no known graph node or domain`)
      }
    }
  }

  // 2 — purpose
  const p = b.purpose || {}
  if (!str(p.whyExists)) err('purpose.whyExists + businessProblem present', 'purpose.whyExists is required')
  if (!str(p.businessProblem)) err('purpose.whyExists + businessProblem present', 'purpose.businessProblem is required')
  if (!str(p.whyLearnerNeeds)) warn('purpose.whyLearnerNeeds is empty')
  if (!arr(p.futureDependents)) {
    err('purpose.futureDependents identified', 'purpose.futureDependents must be an array (empty only for terminal leaves)')
  } else if (p.futureDependents.length === 0) {
    warn('purpose.futureDependents is empty — confirm this is a terminal leaf with no downstream lessons')
  }

  // 3 — audience
  const a = b.audience || {}
  if (!nonEmpty(a.primaryRoles)) err('audience', 'audience.primaryRoles must be non-empty')
  if (!DIFF.includes(a.level)) err('audience', `audience.level must be one of ${DIFF.join('/')}`)

  // 4 — prerequisites object present (arrays)
  const pre = b.prerequisites || {}
  for (const k of ['required', 'recommended', 'optional']) {
    if (!arr(pre[k])) err('prerequisites object present', `prerequisites.${k} must be an array (may be empty)`)
  }

  // 5 — outcomes >=1, Bloom-verbed + measurable
  if (!nonEmpty(b.outcomes)) {
    err('outcomes >=1', 'at least one learning outcome is required')
  } else {
    b.outcomes.forEach((o, i) => {
      if (!str(o.verb)) err('outcomes measurable', `outcome[${i}].verb is required`)
      if (str(o.verb) && /^understand$/i.test(o.verb.trim())) {
        err('outcomes measurable', `outcome[${i}].verb "understand" is not measurable — use a Bloom action verb`)
      }
      if (!str(o.statement)) err('outcomes measurable', `outcome[${i}].statement is required`)
      if (!BLOOM.includes(o.bloom)) err('outcomes measurable', `outcome[${i}].bloom must be one of ${BLOOM.join('/')}`)
    })
  }

  // 6 — businessContext.departments non-empty
  const bc = b.businessContext || {}
  if (!nonEmpty(bc.departments)) err('businessContext.departments non-empty', 'businessContext.departments must be non-empty')

  // 7 — enterpriseContext owner/maintainer/auditor
  const ec = b.enterpriseContext || {}
  for (const k of ['whereItLives', 'owner', 'maintainer', 'auditor']) {
    if (!str(ec[k])) err('enterpriseContext owner/maintainer/auditor present', `enterpriseContext.${k} is required`)
  }

  // 8 — interviewIntel.probability assigned (1–5)
  const ii = b.interviewIntel || {}
  if (!(Number.isInteger(ii.probability) && ii.probability >= 1 && ii.probability <= 5)) {
    err('interviewIntel.probability assigned', 'interviewIntel.probability must be an integer 1–5')
  }
  for (const k of ['likelyQuestions', 'traps', 'strongAnswerTraits', 'weakAnswerTraits', 'followUps']) {
    if (!arr(ii[k])) err('interviewIntel.probability assigned', `interviewIntel.${k} must be an array`)
  }

  // 9 — vocabIntel.core non-empty
  const vi = b.vocabIntel || {}
  if (!nonEmpty(vi.core)) err('vocabIntel.core non-empty', 'vocabIntel.core must be non-empty')
  for (const k of ['supporting', 'business', 'audit', 'risk', 'acronyms', 'commonConfusion']) {
    if (!arr(vi[k])) err('vocabIntel.core non-empty', `vocabIntel.${k} must be an array`)
  }

  // 10 — misconceptions (array; warn if empty)
  if (!arr(b.misconceptions)) err('misconceptions', 'misconceptions must be an array')
  else if (b.misconceptions.length === 0) warn('misconceptions is empty — most lessons have at least one')

  // 11 — diagramNeeds >=1 OR justified empty
  if (!arr(b.diagramNeeds)) {
    err('diagramNeeds selected', 'diagramNeeds must be an array')
  } else if (b.diagramNeeds.length === 0) {
    warn('diagramNeeds is empty — confirm this lesson genuinely needs no diagram')
  } else {
    b.diagramNeeds.forEach((d, i) => {
      if (!str(d.kind)) err('diagramNeeds selected', `diagramNeeds[${i}].kind is required`)
    })
  }

  // 12 — labIntel.type selected
  const li = b.labIntel || {}
  if (!LABS.includes(li.type)) err('labIntel.type selected', `labIntel.type must be one of ${LABS.join('/')}`)

  // 13 — crossLinks arrays
  const cl = b.crossLinks || {}
  for (const k of ['previous', 'future', 'related', 'domains', 'vocab', 'interviewTopics']) {
    if (!arr(cl[k])) err('crossLinks', `crossLinks.${k} must be an array`)
  }

  // 14 — difficultyIntel difficulty+bloom+times
  const di = b.difficultyIntel || {}
  if (!BLOOM.includes(di.bloom)) err('difficultyIntel difficulty+bloom+times', 'difficultyIntel.bloom invalid')
  if (!DIFF.includes(di.difficulty)) err('difficultyIntel difficulty+bloom+times', 'difficultyIntel.difficulty invalid')
  for (const k of ['studyMinutes', 'readingMinutes', 'labMinutes', 'reviewMinutes']) {
    if (!Number.isFinite(di[k]) || di[k] < 0) err('difficultyIntel difficulty+bloom+times', `difficultyIntel.${k} must be a number >= 0`)
  }
  if (Number.isFinite(di.studyMinutes) && di.studyMinutes < 1) err('difficultyIntel difficulty+bloom+times', 'difficultyIntel.studyMinutes must be >= 1')

  // 15 — writingGuidance.profile + >=1 instruction
  const wg = b.writingGuidance || {}
  if (!PROFILES.includes(wg.profile)) err('writingGuidance.profile', `writingGuidance.profile must be one of ${PROFILES.join('/')}`)
  if (!nonEmpty(wg.instructions)) err('writingGuidance.profile', 'writingGuidance.instructions must have >= 1 instruction')

  // Phase 2C — enrichment is OPTIONAL. Absent ⇒ legacy brief, no enrichment gates.
  // Present ⇒ it must be complete (golden-brief standard).
  if (b.enrichment === undefined) {
    warn('enrichment absent — this is a legacy/minimal brief, not a golden reference brief')
  } else {
    const en = b.enrichment || {}
    if (!str(en.mentalModel)) err('enrichment.mentalModel', 'enrichment.mentalModel is required when enrichment is present')

    const eb = en.educationalBoundaries || {}
    if (!nonEmpty(eb.inScope)) err('enrichment.educationalBoundaries', 'educationalBoundaries.inScope must be non-empty')
    for (const k of ['outOfScope', 'deferredToFuture']) {
      if (!arr(eb[k])) err('enrichment.educationalBoundaries', `educationalBoundaries.${k} must be an array`)
    }

    const ts = en.teachingStrategy || {}
    if (!nonEmpty(ts.order)) err('enrichment.teachingStrategy', 'teachingStrategy.order must be non-empty')
    if (!str(ts.whyThisSequence)) err('enrichment.teachingStrategy', 'teachingStrategy.whyThisSequence is required')
    for (const k of ['analogyPoints', 'mandatoryDiagramsAt']) {
      if (!arr(ts[k])) err('enrichment.teachingStrategy', `teachingStrategy.${k} must be an array`)
    }

    if (!nonEmpty(en.industryContext)) {
      err('enrichment.industryContext', 'industryContext must have >= 1 industry scenario')
    } else {
      en.industryContext.forEach((c, i) => {
        if (!INDUSTRIES.includes(c.industry)) err('enrichment.industryContext', `industryContext[${i}].industry must be one of ${INDUSTRIES.join('/')}`)
        if (!str(c.scenario)) err('enrichment.industryContext', `industryContext[${i}].scenario is required`)
      })
    }

    const ac = en.auditContext || {}
    for (const k of ['internalAudit', 'externalAudit', 'compliance', 'executive']) {
      if (!str(ac[k])) err('enrichment.auditContext', `auditContext.${k} is required`)
    }

    if (!arr(en.vocabAdvanced)) err('enrichment.vocabAdvanced', 'vocabAdvanced must be an array')

    const ia = en.interviewAnswers || {}
    if (!str(ia.averageAnswer)) err('enrichment.interviewAnswers', 'interviewAnswers.averageAnswer is required')
    if (!str(ia.exceptionalAnswer)) err('enrichment.interviewAnswers', 'interviewAnswers.exceptionalAnswer is required')

    if (!arr(en.diagramDetail)) {
      err('enrichment.diagramDetail', 'diagramDetail must be an array')
    } else {
      en.diagramDetail.forEach((d, i) => {
        if (!str(d.kind)) err('enrichment.diagramDetail', `diagramDetail[${i}].kind is required`)
        if (!COMPLEXITY.includes(d.complexity)) err('enrichment.diagramDetail', `diagramDetail[${i}].complexity must be one of ${COMPLEXITY.join('/')}`)
        if (!str(d.learningObjective)) err('enrichment.diagramDetail', `diagramDetail[${i}].learningObjective is required`)
      })
    }
  }
}

// Validate one brief file; returns true on PASS. Resets the shared error/warning
// accumulators first so the same module can validate many files in one run.
function validateFile(path) {
  errors.length = 0
  warnings.length = 0
  let brief
  try {
    brief = JSON.parse(readFileSync(path, 'utf8'))
  } catch (e) {
    console.error(`✗ ${path} is not valid JSON: ${e.message}`)
    return false
  }
  validate(brief)
  const label = brief?.identity?.lessonId || path
  console.log(`Lesson Design Brief gate check — ${label}`)
  if (warnings.length) {
    console.log(`⚠  ${warnings.length} warning(s):`)
    for (const w of warnings) console.log(`   - ${w}`)
  }
  if (errors.length) {
    console.log(`✗ BLOCKED — ${errors.length} gate failure(s):`)
    for (const e of errors) console.log(`   - ${e}`)
    return false
  }
  console.log(`✓ PASS — all quality gates satisfied. Lesson generation unblocked.`)
  return true
}

// ── run ──────────────────────────────────────────────────────────────────────
// Accepts a file OR a directory (validates every *.json in it). Default: the example.
const target = process.argv[2] ? resolve(process.cwd(), process.argv[2]) : resolve(HERE, 'lesson-brief.example.json')

if (!existsSync(target)) {
  console.error(`✗ path not found: ${target}`)
  process.exit(1)
}

let files
if (statSync(target).isDirectory()) {
  files = readdirSync(target).filter((f) => f.endsWith('.json')).sort().map((f) => resolve(target, f))
  if (files.length === 0) {
    console.error(`✗ no .json briefs found in ${target}`)
    process.exit(1)
  }
} else {
  files = [target]
}

let passed = 0
const failedFiles = []
for (const f of files) {
  if (validateFile(f)) passed++
  else failedFiles.push(f)
  if (files.length > 1) console.log('')
}

if (files.length > 1) {
  console.log(`=== SUMMARY: ${passed}/${files.length} brief(s) PASS ===`)
  if (failedFiles.length) for (const f of failedFiles) console.log(`   ✗ ${f}`)
}
process.exit(failedFiles.length ? 1 : 0)
