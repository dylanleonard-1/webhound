// Phase 1.5 — typed schema for the academy knowledge graph.
// Matches the existing _graph/*.json (domains/nodes/edges) and the Phase 0
// constitution enums (docs/academy/PHASE_0_ACADEMY_CONSTITUTION.md, Appendix A).
// STANDALONE: not imported by any route/app runtime — types + the validator only.

// ── Controlled enums (must match Phase 0 + the Phase 1 JSON) ──────────────────
export type Difficulty = 'L1' | 'L2' | 'L3' | 'L4' | 'L5'
export type BloomLevel =
  | 'remember' | 'understand' | 'apply' | 'analyze' | 'evaluate' | 'create'
export type Volatility = 'evergreen' | 'stable' | 'volatile'
export type EdgeType = 'requires' | 'recommends' | 'reinforces' | 'relatedTo'
export type NodeType = 'domain' | 'module' | 'chapter' | 'concept'
/** Node enumeration completeness (Phase 1 honesty marker). */
export type NodeStatus = 'enumerated' | 'enumerated-partial' | 'scaffolded'
/** Importance + interview-probability are 1–5 integer scales. */
export type Score1to5 = 1 | 2 | 3 | 4 | 5

export type DomainGroup =
  | 'foundations' | 'infrastructure' | 'identity-access' | 'grc-audit'
  | 'security-operations' | 'security-engineering'
  | 'resilience-thirdparty' | 'leadership-business'

// ── domains.json ─────────────────────────────────────────────────────────────
export interface DomainRecord {
  id: string
  title: string
  group: DomainGroup
  oneLiner: string
  addedByPhase1: boolean
}
export interface DomainsFile {
  schema: string
  governedBy: string
  note?: string
  groups: DomainGroup[]
  domains: DomainRecord[]
}

// ── nodes.json ───────────────────────────────────────────────────────────────
export interface Importance {
  ent: Score1to5
  bus: Score1to5
  sec: Score1to5
  aud: Score1to5
  int: Score1to5
}

/** Full metadata required on `concept` (leaf) nodes that are `enumerated`. */
export interface ConceptNode {
  id: string
  type: 'concept'
  title: string
  difficulty: Difficulty
  bloom: BloomLevel
  estMinutes: number
  prereq: string[]
  importance: Importance
  careers: Record<string, Score1to5>
  departments: string[]
  interviewProb: Score1to5
  lab: boolean
  diagram: boolean
  vocabCount: number
  related: string[]
  capstone: string[]
  status: NodeStatus
  volatility: Volatility
}

/** Domain/module/chapter scaffold nodes carry the lighter shape. */
export interface ScaffoldNode {
  id: string
  type: 'domain' | 'module' | 'chapter'
  title: string
  status: NodeStatus
}

export type GraphNode = ConceptNode | ScaffoldNode

export interface NodesFile {
  schema: string
  governedBy: string
  fieldSemantics?: Record<string, string>
  enumeratedVerticals?: string[]
  nodes: GraphNode[]
}

// ── edges.json ───────────────────────────────────────────────────────────────
export interface GraphEdge {
  from: string
  to: string
  type: EdgeType
}
export interface EdgesFile {
  schema: string
  governedBy: string
  edgeTypes?: Record<string, string>
  cycleCheckApplies?: EdgeType[]
  edges: GraphEdge[]
}

// ── Validation result (used by validate.mjs, typed here for reference) ─────────
export interface ValidationIssue {
  level: 'error' | 'warning'
  check: string
  detail: string
}
export interface ValidationReport {
  ok: boolean
  errors: number
  warnings: number
  counts: Record<string, number>
  issues: ValidationIssue[]
}

// Canonical allowed-value sets (the validator imports the same values via .mjs).
export const DIFFICULTIES: Difficulty[] = ['L1', 'L2', 'L3', 'L4', 'L5']
export const BLOOM_LEVELS: BloomLevel[] =
  ['remember', 'understand', 'apply', 'analyze', 'evaluate', 'create']
export const EDGE_TYPES: EdgeType[] = ['requires', 'recommends', 'reinforces', 'relatedTo']
export const VOLATILITIES: Volatility[] = ['evergreen', 'stable', 'volatile']
export const NODE_STATUSES: NodeStatus[] = ['enumerated', 'enumerated-partial', 'scaffolded']
