#!/usr/bin/env node
// Phase 1.5 — academy knowledge-graph validator.
// Reads _graph/*.json and enforces the Phase 0/Phase 1 invariants.
// HARD ERRORS -> exit 1. WARNINGS -> printed, exit 0 (unless errors present).
//
// Run:  node apps/web/src/lib/academy/_graph/validate.mjs
//   or: (cd apps/web && npm run academy:validate-graph)
//
// No deps, no network, no app imports — pure Node + the committed JSON.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const DIR = dirname(fileURLToPath(import.meta.url))
const DIFFICULTIES = ['L1', 'L2', 'L3', 'L4', 'L5']
const BLOOM = ['remember', 'understand', 'apply', 'analyze', 'evaluate', 'create']
const EDGE_TYPES = ['requires', 'recommends', 'reinforces', 'relatedTo']
const VOLATILITIES = ['evergreen', 'stable', 'volatile']
const STATUSES = ['enumerated', 'enumerated-partial', 'scaffolded']
const SCORE = (v) => Number.isInteger(v) && v >= 1 && v <= 5

const errors = []
const warnings = []
const err = (check, detail) => errors.push({ check, detail })
const warn = (check, detail) => warnings.push({ check, detail })

// ── 1. Parse ─────────────────────────────────────────────────────────────────
function load(name) {
  try {
    return JSON.parse(readFileSync(join(DIR, name), 'utf8'))
  } catch (e) {
    err('json-parse', `${name}: ${e.message}`)
    return null
  }
}
const domainsFile = load('domains.json')
const nodesFile = load('nodes.json')
const edgesFile = load('edges.json')
if (errors.length) finish() // can't continue without parseable JSON

const domains = domainsFile.domains ?? []
const nodes = nodesFile.nodes ?? []
const edges = edgesFile.edges ?? []

// ── 2. Unique IDs (domains, nodes, edges) ────────────────────────────────────
function dupes(ids) {
  const seen = new Set(), dup = new Set()
  for (const id of ids) { if (seen.has(id)) dup.add(id); seen.add(id) }
  return [...dup]
}
for (const d of dupes(domains.map((d) => d.id))) err('unique-domain-id', `duplicate domain id: ${d}`)
for (const d of dupes(nodes.map((n) => n.id))) err('unique-node-id', `duplicate node id: ${d}`)
const edgeKey = (e) => `${e.from}→${e.to}#${e.type}`
for (const d of dupes(edges.map(edgeKey))) err('unique-edge-id', `duplicate edge: ${d}`)

// Known id universe = all node ids + all domain ids (nodes may reference domains).
const domainIds = new Set(domains.map((d) => d.id))
const nodeIds = new Set(nodes.map((n) => n.id))
const known = new Set([...domainIds, ...nodeIds])

// ── 3. Valid domain references (every node's domain prefix exists) ────────────
for (const n of nodes) {
  if (n.type === 'domain') continue
  const dom = String(n.id).split('.')[0]
  if (!domainIds.has(dom)) err('valid-domain-ref', `node ${n.id} references unknown domain "${dom}"`)
}

// ── 4. Required metadata per node type + enum validity ───────────────────────
for (const n of nodes) {
  if (!n.id) { err('required-meta', 'node with no id'); continue }
  if (!STATUSES.includes(n.status)) err('enum-status', `node ${n.id}: bad status "${n.status}"`)
  if (n.type === 'concept') {
    const req = ['title', 'difficulty', 'bloom', 'estMinutes', 'prereq', 'importance',
      'careers', 'departments', 'interviewProb', 'lab', 'diagram', 'vocabCount',
      'related', 'capstone', 'status', 'volatility']
    for (const f of req) if (!(f in n)) err('required-meta', `concept ${n.id}: missing field "${f}"`)
    if (n.difficulty && !DIFFICULTIES.includes(n.difficulty)) err('enum-difficulty', `${n.id}: bad difficulty "${n.difficulty}"`)
    if (n.bloom && !BLOOM.includes(n.bloom)) err('enum-bloom', `${n.id}: bad bloom "${n.bloom}"`)
    if (n.volatility && !VOLATILITIES.includes(n.volatility)) err('enum-volatility', `${n.id}: bad volatility "${n.volatility}"`)
    if (n.interviewProb !== undefined && !SCORE(n.interviewProb)) err('enum-interviewProb', `${n.id}: interviewProb must be 1–5, got ${n.interviewProb}`)
    if (n.importance) {
      for (const k of ['ent', 'bus', 'sec', 'aud', 'int'])
        if (!SCORE(n.importance[k])) err('enum-importance', `${n.id}: importance.${k} must be 1–5, got ${n.importance?.[k]}`)
    }
    if (n.careers) for (const [role, v] of Object.entries(n.careers))
      if (!SCORE(v)) err('enum-career-score', `${n.id}: careers.${role} must be 1–5, got ${v}`)
  } else if (['domain', 'module', 'chapter'].includes(n.type)) {
    for (const f of ['title', 'status']) if (!(f in n)) err('required-meta', `${n.type} ${n.id}: missing "${f}"`)
  } else {
    err('node-type', `node ${n.id}: unknown type "${n.type}"`)
  }
}

// ── 5. Edge validity: type + dangling endpoints ──────────────────────────────
for (const e of edges) {
  if (!EDGE_TYPES.includes(e.type)) err('enum-edge-type', `edge ${edgeKey(e)}: bad type "${e.type}"`)
  if (!known.has(e.from)) err('dangling-edge', `edge ${edgeKey(e)}: 'from' "${e.from}" does not exist`)
  if (!known.has(e.to)) err('dangling-edge', `edge ${edgeKey(e)}: 'to' "${e.to}" does not exist`)
}

// ── 6. prereq fields resolve (concept nodes) ─────────────────────────────────
for (const n of nodes) {
  if (Array.isArray(n.prereq)) for (const p of n.prereq)
    if (!known.has(p)) err('dangling-prereq', `node ${n.id}: prereq "${p}" does not exist`)
}

// ── 7. No cycles in `requires` edges (Kahn topological sort) ─────────────────
{
  const req = edges.filter((e) => e.type === 'requires' && known.has(e.from) && known.has(e.to))
  const adj = new Map(), indeg = new Map(), V = new Set()
  for (const e of req) {
    V.add(e.from); V.add(e.to)
    if (!adj.has(e.to)) adj.set(e.to, [])
    adj.get(e.to).push(e.from)
    indeg.set(e.from, (indeg.get(e.from) ?? 0) + 1)
    if (!indeg.has(e.to)) indeg.set(e.to, indeg.get(e.to) ?? 0)
  }
  const q = [...V].filter((v) => (indeg.get(v) ?? 0) === 0)
  let seen = 0
  while (q.length) {
    const x = q.pop(); seen++
    for (const y of adj.get(x) ?? []) {
      indeg.set(y, indeg.get(y) - 1)
      if (indeg.get(y) === 0) q.push(y)
    }
  }
  if (seen !== V.size) {
    const inCycle = [...V].filter((v) => (indeg.get(v) ?? 0) > 0)
    err('requires-cycle', `cycle in 'requires' graph (${V.size - seen} nodes), e.g.: ${inCycle.slice(0, 6).join(', ')}`)
  }
}

// ── 8. broken relatedConcept (`related`) references — WARNING ─────────────────
for (const n of nodes) {
  if (Array.isArray(n.related)) for (const r of n.related)
    if (!known.has(r)) warn('related-ref', `node ${n.id}: related "${r}" does not resolve`)
}

// ── 9. orphan nodes (no incoming AND no outgoing edges) — WARNING ────────────
{
  const touched = new Set()
  for (const e of edges) { touched.add(e.from); touched.add(e.to) }
  for (const n of nodes) {
    if (n.type === 'concept' && !touched.has(n.id)) warn('orphan-node', `concept ${n.id} has no edges (orphan)`)
  }
}

// ── 10. duplicate vocabulary — WARNING (placeholder: vocabCount sanity) ───────
// Full vocab terms live in lesson content (Phase 2); here we sanity-check counts
// and flag any concept missing a positive vocabCount as a soft warning.
for (const n of nodes) {
  if (n.type === 'concept' && (!Number.isInteger(n.vocabCount) || n.vocabCount <= 0))
    warn('vocab-count', `concept ${n.id}: vocabCount should be a positive integer (got ${n.vocabCount})`)
}

finish()

function finish() {
  const counts = {
    domains: domainsFile?.domains?.length ?? 0,
    nodes: nodesFile?.nodes?.length ?? 0,
    conceptNodes: (nodesFile?.nodes ?? []).filter((n) => n.type === 'concept').length,
    edges: edgesFile?.edges?.length ?? 0,
    requiresEdges: (edgesFile?.edges ?? []).filter((e) => e.type === 'requires').length,
  }
  console.log('── Academy Graph Validation ──')
  for (const [k, v] of Object.entries(counts)) console.log(`  ${k}: ${v}`)
  console.log('')
  if (warnings.length) {
    console.log(`WARNINGS (${warnings.length}):`)
    for (const w of warnings) console.log(`  ⚠ [${w.check}] ${w.detail}`)
    console.log('')
  }
  if (errors.length) {
    console.log(`ERRORS (${errors.length}):`)
    for (const e of errors) console.log(`  ✗ [${e.check}] ${e.detail}`)
    console.log(`\nRESULT: FAIL (${errors.length} error(s), ${warnings.length} warning(s))`)
    process.exit(1)
  }
  console.log(`RESULT: PASS (0 errors, ${warnings.length} warning(s))`)
  process.exit(0)
}
