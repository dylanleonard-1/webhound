'use client'

import { useEffect, useState } from 'react'
import { ShieldAlert, ShieldX, Globe2, Link2, AlertTriangle, ChevronDown, ChevronUp } from 'lucide-react'
import { api, type GroupedFindingDetailResponse, type GroupedFindingResponse, type EvidenceItem } from '@/lib/api'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

interface ThreatIntelDomainsSectionProps {
  scanResultId: string
}

interface ProviderVerdict {
  provider: string
  is_malicious?: boolean | null
  is_suspicious?: boolean | null
  reputation_score?: number | null
  categories?: string[]
  error?: string | null
}

interface DomainRow {
  finding: GroupedFindingResponse
  host: string
  tier: 'malicious' | 'risky' | 'suspicious' | 'shortener' | 'punycode' | 'other'
  kinds: string[]
  signals: string[]
  score: number | null
  providers: ProviderVerdict[]
  mergedClass: string | null
}

const TIER_STYLE: Record<DomainRow['tier'], { label: string; cls: string; icon: typeof ShieldX }> = {
  malicious: {
    label: 'Likely malicious',
    cls: 'bg-red-500/10 text-red-300 border-red-500/30',
    icon: ShieldX,
  },
  risky: {
    label: 'High-risk',
    cls: 'bg-orange-500/10 text-orange-300 border-orange-500/30',
    icon: ShieldAlert,
  },
  suspicious: {
    label: 'Suspicious',
    cls: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30',
    icon: AlertTriangle,
  },
  shortener: {
    label: 'URL shortener',
    cls: 'bg-blue-500/10 text-blue-300 border-blue-500/30',
    icon: Link2,
  },
  punycode: {
    label: 'Punycode / IDN',
    cls: 'bg-purple-500/10 text-purple-300 border-purple-500/30',
    icon: Globe2,
  },
  other: {
    label: 'Flagged',
    cls: 'bg-gray-500/10 text-gray-300 border-gray-500/30',
    icon: AlertTriangle,
  },
}

const TIER_ORDER: DomainRow['tier'][] = [
  'malicious', 'risky', 'suspicious', 'punycode', 'shortener', 'other',
]

function tierFromTitle(title: string): DomainRow['tier'] {
  const t = title.toLowerCase()
  if (t.startsWith('likely malicious')) return 'malicious'
  if (t.startsWith('high-risk')) return 'risky'
  if (t.startsWith('suspicious')) return 'suspicious'
  if (t.includes('url shortener')) return 'shortener'
  if (t.includes('punycode')) return 'punycode'
  return 'other'
}

function hostFromFinding(f: GroupedFindingResponse): string {
  // Title format: "<tier> third-party host: <host>" OR
  //               "URL shortener as third-party host: <host>" OR
  //               "Punycode (IDN) domain referenced: <host>"
  const m = f.title.match(/:\s*(\S[\S]*)$/)
  return m ? m[1] : '(unknown)'
}

function extractEvidence(detail: GroupedFindingDetailResponse): {
  signals: string[]; score: number | null; kinds: string[];
  providers: ProviderVerdict[]; mergedClass: string | null
} {
  const ev = detail.sample_evidence?.[0] as EvidenceItem | undefined
  const extra = (ev as { extra?: Record<string, unknown> } | undefined)?.extra ?? {}
  const signalsRaw = (extra as { signals?: unknown }).signals
  const signals = Array.isArray(signalsRaw)
    ? signalsRaw.filter((s): s is string => typeof s === 'string')
    : []
  const kindsRaw = (extra as { kinds?: unknown }).kinds
  const kinds = Array.isArray(kindsRaw)
    ? kindsRaw.filter((k): k is string => typeof k === 'string')
    : []
  const score = typeof (extra as { score?: unknown }).score === 'number'
    ? (extra as { score: number }).score : null
  const providersRaw = (extra as { external_providers?: unknown }).external_providers
  const providers: ProviderVerdict[] = Array.isArray(providersRaw)
    ? (providersRaw as ProviderVerdict[])
    : []
  const mergedClass = typeof (extra as { merged_classification?: unknown })
    .merged_classification === 'string'
    ? (extra as { merged_classification: string }).merged_classification
    : null
  return { signals, score, kinds, providers, mergedClass }
}

function ProviderBadge({ p }: { p: ProviderVerdict }) {
  if (p.error) {
    return (
      <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded border bg-gray-500/10 text-gray-500 border-gray-500/20">
        {p.provider}: error
      </span>
    )
  }
  const verdict = p.is_malicious ? 'malicious'
    : p.is_suspicious ? 'suspicious' : 'clean'
  const cls = p.is_malicious
    ? 'bg-red-500/15 text-red-300 border-red-500/30'
    : p.is_suspicious
      ? 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30'
      : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
  const rep = p.reputation_score !== null && p.reputation_score !== undefined
    ? ` ${p.reputation_score.toFixed(1)}/10`
    : ''
  return (
    <span className={cn(
      'inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded border',
      cls,
    )}>
      {p.provider}: {verdict}{rep}
    </span>
  )
}

function DomainCard({ row, defaultOpen }: { row: DomainRow; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  const tierCfg = TIER_STYLE[row.tier]
  const Icon = tierCfg.icon
  return (
    <div className="bg-app-card rounded-lg border border-app-border overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-3 py-2.5 hover:bg-white/[0.02] transition-colors text-left"
      >
        <Icon className="w-3.5 h-3.5 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-[12px] font-mono text-white truncate">{row.host}</p>
          <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
            <Badge className={cn('text-[9px] font-semibold', tierCfg.cls)}>
              {tierCfg.label}
            </Badge>
            {row.score !== null && (
              <span className="text-[9px] font-mono text-gray-500">
                score {row.score.toFixed(1)}/10
              </span>
            )}
            {row.kinds.length > 0 && (
              <span className="text-[9px] text-gray-500">
                {row.kinds.join(', ')}
              </span>
            )}
          </div>
        </div>
        {open
          ? <ChevronUp className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />
          : <ChevronDown className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />}
      </button>
      {open && (
        <div className="px-3 pb-3 pt-1 space-y-2 border-t border-app-border">
          {row.providers.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">
                External providers
              </p>
              <div className="flex flex-wrap gap-1">
                {row.providers.map((p, i) => <ProviderBadge key={i} p={p} />)}
              </div>
              {row.mergedClass && (
                <p className="text-[10px] text-gray-500 mt-1">
                  Merged verdict: <span className="text-gray-300 font-mono">{row.mergedClass}</span>
                </p>
              )}
            </div>
          )}
          {row.signals.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">
                Signals matched
              </p>
              <ul className="space-y-0.5">
                {row.signals.map((s, i) => (
                  <li key={i} className="text-[11px] text-gray-400 leading-snug">• {s}</li>
                ))}
              </ul>
            </div>
          )}
          {row.finding.description && (
            <p className="text-[11px] text-gray-400 leading-relaxed">
              {row.finding.description}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

export function ThreatIntelDomainsSection({ scanResultId }: ThreatIntelDomainsSectionProps) {
  const [rows, setRows] = useState<DomainRow[] | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const list = await api.scanResults.groupedFindings(scanResultId, {
          scanner_engine: 'threat_intel',
          limit: 200,
        })
        // Drop the INFO-tier inventory finding from this widget — that finding
        // doesn't represent a single domain.
        const candidates = list.items.filter(f =>
          !f.title.toLowerCase().startsWith('third-party domain inventory')
        )
        // Pull detail for each candidate to access evidence.extra
        const details = await Promise.allSettled(
          candidates.map(f =>
            api.scanResults.groupedFindingDetail(scanResultId, f.id),
          ),
        )
        const built: DomainRow[] = []
        for (let i = 0; i < candidates.length; i++) {
          const f = candidates[i]
          const d = details[i]
          if (d.status !== 'fulfilled') continue
          const ev = extractEvidence(d.value)
          built.push({
            finding: f,
            host: hostFromFinding(f),
            tier: tierFromTitle(f.title),
            kinds: ev.kinds,
            signals: ev.signals,
            score: ev.score,
            providers: ev.providers,
            mergedClass: ev.mergedClass,
          })
        }
        if (!cancelled) {
          built.sort((a, b) =>
            TIER_ORDER.indexOf(a.tier) - TIER_ORDER.indexOf(b.tier)
              || (b.score ?? 0) - (a.score ?? 0)
              || a.host.localeCompare(b.host),
          )
          setRows(built)
        }
      } catch {
        if (!cancelled) setRows([])
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [scanResultId])

  if (loading) {
    return (
      <Card>
        <div className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <ShieldAlert className="w-4 h-4 text-gray-400" />
            <h2 className="font-medium text-white">Threat Intelligence — External Domains</h2>
          </div>
          <div className="h-16 bg-gray-800/40 rounded animate-pulse" />
        </div>
      </Card>
    )
  }

  if (!rows || rows.length === 0) return null

  const byTier = rows.reduce<Record<DomainRow['tier'], DomainRow[]>>((acc, r) => {
    (acc[r.tier] ??= []).push(r)
    return acc
  }, {} as Record<DomainRow['tier'], DomainRow[]>)

  const malCount = byTier.malicious?.length ?? 0
  const riskCount = byTier.risky?.length ?? 0
  const susCount = byTier.suspicious?.length ?? 0

  return (
    <Card>
      <div className="flex items-center justify-between gap-2 p-4 border-b border-app-border">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-orange-400" />
          <h2 className="font-medium text-white">Threat Intelligence — External Domains</h2>
        </div>
        <div className="flex items-center gap-1.5">
          {malCount > 0 && (
            <Badge className="bg-red-500/15 text-red-300 border-red-500/30 text-[10px]">
              {malCount} malicious
            </Badge>
          )}
          {riskCount > 0 && (
            <Badge className="bg-orange-500/15 text-orange-300 border-orange-500/30 text-[10px]">
              {riskCount} risky
            </Badge>
          )}
          {susCount > 0 && (
            <Badge className="bg-yellow-500/15 text-yellow-300 border-yellow-500/30 text-[10px]">
              {susCount} suspicious
            </Badge>
          )}
        </div>
      </div>

      <div className="p-4 space-y-4">
        {TIER_ORDER.map(tier => {
          const items = byTier[tier]
          if (!items || items.length === 0) return null
          const tierCfg = TIER_STYLE[tier]
          return (
            <div key={tier}>
              <div className="flex items-center gap-2 mb-2">
                <tierCfg.icon className="w-3.5 h-3.5" />
                <span className="text-xs font-medium text-gray-300">
                  {tierCfg.label}
                </span>
                <span className="text-xs text-gray-500">
                  ({items.length})
                </span>
              </div>
              <div className="space-y-1.5">
                {items.map(row => (
                  <DomainCard
                    key={row.finding.id}
                    row={row}
                    defaultOpen={tier === 'malicious' || tier === 'risky'}
                  />
                ))}
              </div>
            </div>
          )
        })}
      </div>
    </Card>
  )
}
