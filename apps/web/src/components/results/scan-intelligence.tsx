'use client'

// WebHound — components/results/scan-intelligence.tsx
// Surfaces scanner intelligence the backend already computes + stores in
// ScanResult.scanner_metadata but that the results page never rendered —
// the direct fix for "deep scans look identical": detected frameworks
// (Phase 9), the WADE Security Advisor (Phase 13), and the Security Graph
// summary (Phase 18). Each block renders nothing when its slot is absent,
// so older scans and minimal scans degrade cleanly.

import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Layers, Lightbulb, Network, HelpCircle, ArrowRight,
} from 'lucide-react'

interface Props {
  scannerMetadata: Record<string, unknown> | null
}

interface FrameworkDetection {
  framework: string
  category?: string
  confidence?: number
  confidence_label?: string
}
interface FrameworksMeta {
  detected?: FrameworkDetection[]
  primary_framework?: string | null
  primary_confidence_label?: string
  routes_observed?: number
  apis_observed?: number
  forms_observed?: number
}
interface AdvisorMeta {
  qa?: Record<string, string>
  action_plan?: { counts?: Record<string, number> }
  trend?: { headline?: string; detail?: string } | null
  remediation_roadmap?: Array<{ title?: string; recommendation?: string }>
}
interface GraphSummary {
  node_count?: number
  edge_count?: number
  page_count?: number
  script_count?: number
  third_party_domain_count?: number
  unknown_vendor_count?: number
  form_count?: number
  api_endpoint_count?: number
  top_third_parties?: string[]
  unknown_vendors?: string[]
  busiest_pages?: Array<{ page: string; connections: number }>
}

const QA_LABELS: Record<string, string> = {
  what_should_i_fix_first: 'What should I fix first?',
  did_my_website_get_hacked: 'Did my website get hacked?',
  is_my_website_safe: 'Is my website safe?',
  what_changed: 'What changed since last time?',
  whats_most_urgent: 'What’s most urgent?',
}

export function ScanIntelligence({ scannerMetadata }: Props) {
  if (!scannerMetadata) return null
  const md = scannerMetadata
  const frameworks = md.frameworks as FrameworksMeta | undefined
  const advisor = md.advisor as AdvisorMeta | undefined
  const graph = md.security_graph_summary as GraphSummary | undefined
  const wadeCompared = md.wade_compared_to_previous as boolean | undefined

  const hasFrameworks = frameworks?.detected && frameworks.detected.length > 0
  const hasAdvisor = advisor && (advisor.qa || advisor.action_plan)
  const hasGraph = graph && (graph.node_count ?? 0) > 0
  if (!hasFrameworks && !hasAdvisor && !hasGraph) return null

  return (
    <div className="space-y-4">
      {hasFrameworks && <FrameworksPanel f={frameworks!} />}
      {hasAdvisor && <AdvisorPanel a={advisor!} wadeCompared={wadeCompared} />}
      {hasGraph && <GraphPanel g={graph!} />}
    </div>
  )
}

function FrameworksPanel({ f }: { f: FrameworksMeta }) {
  return (
    <Card className="p-4">
      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white">
        <Layers className="h-4 w-4 text-emerald-400" /> Technology Detected
      </div>
      <div className="flex flex-wrap gap-2">
        {(f.detected ?? []).slice(0, 12).map((d, i) => (
          <Badge key={i} variant="outline"
            className="border-emerald-500/30 bg-emerald-500/10 text-emerald-300">
            {d.framework}
            {d.confidence_label && (
              <span className="ml-1 text-emerald-500/70">· {d.confidence_label}</span>
            )}
          </Badge>
        ))}
      </div>
      {f.primary_framework && (
        <p className="mt-3 text-xs text-zinc-400">
          Primary platform: <span className="text-zinc-200">{f.primary_framework}</span>
          {' '}({f.primary_confidence_label}). Observed {f.routes_observed ?? 0} routes,
          {' '}{f.apis_observed ?? 0} APIs, {f.forms_observed ?? 0} forms.
        </p>
      )}
    </Card>
  )
}

function AdvisorPanel({ a, wadeCompared }: { a: AdvisorMeta; wadeCompared?: boolean }) {
  const counts = a.action_plan?.counts ?? {}
  const qa = a.qa ?? {}
  const qaEntries = Object.entries(qa).filter(([, v]) => v)
  return (
    <Card className="p-4">
      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white">
        <Lightbulb className="h-4 w-4 text-amber-400" /> Security Advisor
      </div>

      <div className="mb-3 flex flex-wrap gap-2 text-xs">
        <ActionPill label="Fix now" n={counts.fix_now ?? 0} color="#ef4444" />
        <ActionPill label="Fix soon" n={counts.fix_soon ?? 0} color="#FF8A3E" />
        <ActionPill label="Monitor" n={counts.monitor ?? 0} color="#FFC53E" />
        <ActionPill label="Info" n={counts.informational ?? 0} color="#9ca3af" />
      </div>

      {a.trend?.headline && (
        <p className="mb-3 text-xs text-zinc-300">{a.trend.headline} {a.trend.detail}</p>
      )}

      <div className="space-y-2">
        {qaEntries.slice(0, 4).map(([k, v]) => (
          <div key={k} className="rounded-lg bg-white/5 p-2.5">
            <div className="flex items-center gap-1.5 text-xs font-medium text-zinc-300">
              <HelpCircle className="h-3.5 w-3.5 text-zinc-500" />
              {QA_LABELS[k] ?? k.replace(/_/g, ' ')}
            </div>
            <p className="mt-1 text-xs text-zinc-400">{v}</p>
          </div>
        ))}
      </div>

      {wadeCompared === false && (
        <p className="mt-3 flex items-center gap-1.5 text-xs text-blue-300/80">
          <ArrowRight className="h-3.5 w-3.5" />
          Baseline established — change tracking (WADE) starts on your next scan.
        </p>
      )}
    </Card>
  )
}

function ActionPill({ label, n, color }: { label: string; n: number; color: string }) {
  return (
    <span className="rounded-full px-2 py-0.5 font-medium"
      style={{ color, background: `${color}1a` }}>
      {n} {label}
    </span>
  )
}

function GraphPanel({ g }: { g: GraphSummary }) {
  return (
    <Card className="p-4">
      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white">
        <Network className="h-4 w-4 text-violet-400" /> Security Graph
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
        <Stat label="Pages" v={g.page_count} />
        <Stat label="Scripts" v={g.script_count} />
        <Stat label="Third parties" v={g.third_party_domain_count} />
        <Stat label="Unknown vendors" v={g.unknown_vendor_count} accent={g.unknown_vendor_count ? '#FF8A3E' : undefined} />
        <Stat label="Forms" v={g.form_count} />
        <Stat label="APIs" v={g.api_endpoint_count} />
        <Stat label="Nodes" v={g.node_count} />
        <Stat label="Connections" v={g.edge_count} />
      </div>
      {g.unknown_vendors && g.unknown_vendors.length > 0 && (
        <p className="mt-3 text-xs text-zinc-400">
          Unrecognised vendors:{' '}
          <span className="text-amber-300">{g.unknown_vendors.slice(0, 6).join(', ')}</span>
        </p>
      )}
      {g.busiest_pages && g.busiest_pages.length > 0 && (
        <p className="mt-1 text-xs text-zinc-500">
          Busiest surface: {g.busiest_pages[0].page.replace(/^https?:\/\//, '')}
          {' '}({g.busiest_pages[0].connections} connections)
        </p>
      )}
    </Card>
  )
}

function Stat({ label, v, accent }: { label: string; v?: number; accent?: string }) {
  return (
    <div className="rounded-lg bg-white/5 p-2">
      <div className="text-lg font-semibold" style={{ color: accent ?? '#e4e4e7' }}>
        {v ?? 0}
      </div>
      <div className="text-[10px] uppercase tracking-wide text-zinc-500">{label}</div>
    </div>
  )
}
