'use client'

// WebHound — components/results/scan-insights.tsx
// Phase-5G dashboard consumption panel. Reads the new JSON-v4 fields
// the scanner writes into ScanResult.scanner_metadata and renders:
//   * Correlated threat chains (correlated_chains)
//   * Asset map summary (asset_map.total_surface_count + exposure_signals)
//   * Threat-intel coverage (threat_intel_coverage.coverage_ratio +
//     per-tier histogram)
//   * Evidence quality (evidence_quality.completeness_ratio +
//     per-engine incomplete list)
//   * Browser pass status (browser_pass.host_count + artifact_count
//     + deferred state)
//
// Each section renders nothing when its slot is missing — older scans
// pre-dating v4 simply show no insights panel content, and the surrounding
// page layout stays intact.

import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  AlertTriangle, ShieldCheck, Globe2, Eye, Activity, Network,
} from 'lucide-react'

interface InsightsProps {
  scannerMetadata: Record<string, unknown> | null
}

interface ChainEntry {
  chain_name?: string
  title?: string
  severity?: string
  signal_count?: number
  cluster_finding_id?: string
}

interface AssetMap {
  primary_host?: string
  total_surface_count?: number
  exposure_signals?: string[]
  ct_subdomains?: string[]
  common_subdomains?: string[]
  external_hosts?: string[]
}

interface ThreatIntelCoverage {
  total_hosts?: number
  classified_hosts?: number
  coverage_ratio?: number
  has_coverage_gap?: boolean
  per_tier_count?: Record<string, number>
  unclassified_hosts?: string[]
  enriched_via_external_provider?: number
}

interface EvidenceQuality {
  total_findings?: number
  complete_findings?: number
  completeness_ratio?: number
  has_gaps?: boolean
  per_engine_incomplete_count?: Record<string, number>
}

interface BrowserPass {
  deferred?: boolean
  error?: string | null
  page_count?: number
  artifact_count?: number
  host_count?: number
  duration_ms?: number
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-400 border-red-500/30',
  high:     'bg-orange-500/10 text-orange-400 border-orange-500/30',
  medium:   'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  low:      'bg-blue-500/10 text-blue-400 border-blue-500/30',
  info:     'bg-zinc-500/10 text-zinc-400 border-zinc-500/30',
}

export function ScanInsights({ scannerMetadata }: InsightsProps) {
  if (!scannerMetadata) return null
  const md = scannerMetadata as Record<string, unknown>

  const chains = (md.correlated_chains as ChainEntry[] | undefined) ?? []
  const assetMap = (md.asset_map as AssetMap | undefined) ?? undefined
  const tiCoverage = (md.threat_intel_coverage as ThreatIntelCoverage | undefined) ?? undefined
  const evidence = (md.evidence_quality as EvidenceQuality | undefined) ?? undefined
  const browser = (md.browser_pass as BrowserPass | undefined) ?? undefined

  const hasAnything = (
    chains.length > 0 || assetMap || tiCoverage || evidence || browser
  )
  if (!hasAnything) return null

  return (
    <div className="space-y-4">
      <CorrelatedChainsPanel chains={chains} />
      <AssetMapPanel assetMap={assetMap} />
      <ThreatIntelCoveragePanel coverage={tiCoverage} />
      <EvidenceQualityPanel evidence={evidence} />
      <BrowserPassPanel browser={browser} />
    </div>
  )
}


function CorrelatedChainsPanel({ chains }: { chains: ChainEntry[] }) {
  if (!chains.length) return null
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-3">
        <Network className="w-4 h-4 text-orange-400" />
        <h3 className="text-sm font-semibold uppercase tracking-wider">
          Correlated threat chains
        </h3>
        <Badge className="ml-auto">{chains.length}</Badge>
      </div>
      <p className="text-xs text-zinc-500 mb-3">
        Multiple engines independently flagged related signals. Each
        chain points back to the constituent findings that contributed.
      </p>
      <div className="space-y-2">
        {chains.map((c) => (
          <div
            key={c.cluster_finding_id ?? c.chain_name}
            className="flex items-start gap-3 p-3 rounded border border-zinc-800 hover:border-zinc-700"
          >
            <span
              className={`mt-0.5 inline-flex px-2 py-0.5 rounded text-[10px] font-bold border ${
                SEVERITY_COLORS[c.severity ?? 'medium'] ?? SEVERITY_COLORS.medium
              }`}
            >
              {(c.severity ?? 'medium').toUpperCase()}
            </span>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium">{c.title}</div>
              <div className="text-xs text-zinc-500 mt-1">
                {c.signal_count ?? '?'} corroborating signal
                {(c.signal_count ?? 0) === 1 ? '' : 's'}
                {c.chain_name ? ` · ${c.chain_name}` : ''}
              </div>
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}


function AssetMapPanel({ assetMap }: { assetMap: AssetMap | undefined }) {
  if (!assetMap || (assetMap.total_surface_count ?? 0) === 0) return null
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-3">
        <Globe2 className="w-4 h-4 text-emerald-400" />
        <h3 className="text-sm font-semibold uppercase tracking-wider">
          Attack surface
        </h3>
      </div>
      <div className="grid grid-cols-3 gap-3 mb-3">
        <Stat label="surface" value={assetMap.total_surface_count ?? 0} />
        <Stat label="CT subdomains" value={(assetMap.ct_subdomains ?? []).length} />
        <Stat label="third-party hosts" value={(assetMap.external_hosts ?? []).length} />
      </div>
      {(assetMap.exposure_signals ?? []).length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {(assetMap.exposure_signals ?? []).map((sig) => (
            <Badge key={sig} variant="outline" className="text-xs">
              {sig}
            </Badge>
          ))}
        </div>
      )}
    </Card>
  )
}


function ThreatIntelCoveragePanel({
  coverage,
}: { coverage: ThreatIntelCoverage | undefined }) {
  if (!coverage || (coverage.total_hosts ?? 0) === 0) return null
  const ratio = Math.round((coverage.coverage_ratio ?? 1) * 100)
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-3">
        <ShieldCheck className="w-4 h-4 text-blue-400" />
        <h3 className="text-sm font-semibold uppercase tracking-wider">
          Threat-intel coverage
        </h3>
        {coverage.has_coverage_gap && (
          <Badge variant="critical" className="ml-auto">
            gap
          </Badge>
        )}
      </div>
      <div className="flex items-baseline gap-3 mb-2">
        <span className="text-3xl font-bold">{ratio}%</span>
        <span className="text-xs text-zinc-500">
          {coverage.classified_hosts ?? 0} of {coverage.total_hosts ?? 0} hosts classified
        </span>
      </div>
      {coverage.enriched_via_external_provider ? (
        <div className="text-xs text-zinc-500 mb-2">
          {coverage.enriched_via_external_provider} enriched via external provider
          (VirusTotal etc.)
        </div>
      ) : null}
      {coverage.per_tier_count && (
        <div className="flex flex-wrap gap-1.5 mt-2">
          {Object.entries(coverage.per_tier_count).map(([tier, count]) => (
            <Badge key={tier} variant="outline" className="text-xs">
              {tier}: {count}
            </Badge>
          ))}
        </div>
      )}
    </Card>
  )
}


function EvidenceQualityPanel({
  evidence,
}: { evidence: EvidenceQuality | undefined }) {
  if (!evidence || (evidence.total_findings ?? 0) === 0) return null
  const ratio = Math.round((evidence.completeness_ratio ?? 1) * 100)
  const perEngine = Object.entries(
    evidence.per_engine_incomplete_count ?? {},
  )
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-3">
        <Eye className="w-4 h-4 text-purple-400" />
        <h3 className="text-sm font-semibold uppercase tracking-wider">
          Evidence quality
        </h3>
        {evidence.has_gaps && (
          <Badge variant="critical" className="ml-auto">
            gaps
          </Badge>
        )}
      </div>
      <div className="flex items-baseline gap-3 mb-2">
        <span className="text-3xl font-bold">{ratio}%</span>
        <span className="text-xs text-zinc-500">
          {evidence.complete_findings ?? 0} of {evidence.total_findings ?? 0}
          {' '}findings fully justified
        </span>
      </div>
      {perEngine.length > 0 && (
        <div className="mt-2">
          <div className="text-xs text-zinc-500 mb-1">
            Engines missing rationales:
          </div>
          <div className="flex flex-wrap gap-1.5">
            {perEngine.map(([engine, count]) => (
              <Badge key={engine} variant="outline" className="text-xs">
                {engine}: {count}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </Card>
  )
}


function BrowserPassPanel({ browser }: { browser: BrowserPass | undefined }) {
  if (!browser) return null
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-3">
        <Activity className="w-4 h-4 text-cyan-400" />
        <h3 className="text-sm font-semibold uppercase tracking-wider">
          Browser pass
        </h3>
        {browser.deferred ? (
          <Badge variant="outline" className="ml-auto text-xs">
            deferred
          </Badge>
        ) : null}
      </div>
      {browser.deferred ? (
        <p className="text-xs text-zinc-500">
          {browser.error ?? 'Browser execution was not enabled for this scan profile.'}
        </p>
      ) : (
        <div className="grid grid-cols-3 gap-3">
          <Stat label="pages" value={browser.page_count ?? 0} />
          <Stat label="artifacts" value={browser.artifact_count ?? 0} />
          <Stat label="hosts" value={browser.host_count ?? 0} />
        </div>
      )}
    </Card>
  )
}


function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="flex flex-col">
      <span className="text-lg font-bold">{value}</span>
      <span className="text-[10px] text-zinc-500 uppercase tracking-wider">{label}</span>
    </div>
  )
}
