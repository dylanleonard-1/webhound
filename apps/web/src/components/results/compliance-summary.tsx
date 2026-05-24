'use client'

import { useEffect, useState } from 'react'
import { Scale, AlertTriangle, ShieldCheck } from 'lucide-react'
import { api, type GroupedFindingResponse } from '@/lib/api'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

interface ComplianceSummaryProps {
  scanResultId: string
}

interface FrameworkBucket {
  key: string
  label: string
  description: string
  total: number
  actionable: number          // critical + high + medium
  uniqueRefs: Set<string>
}

const FRAMEWORKS: { key: string; label: string; description: string }[] = [
  { key: 'pci_dss',     label: 'PCI DSS 4.0',  description: 'Payment-card data handling' },
  { key: 'iso_27001',   label: 'ISO 27001',    description: 'Information-security mgmt' },
  { key: 'soc2',        label: 'SOC 2',        description: 'Trust Service Criteria' },
  { key: 'hipaa',       label: 'HIPAA',        description: 'Health-info security rule' },
  { key: 'owasp_top10', label: 'OWASP Top 10', description: 'Web-app risk categories' },
  { key: 'nist_controls', label: 'NIST 800-53', description: 'US Federal security controls' },
  { key: 'cwe_ids',     label: 'CWE',          description: 'Common weaknesses' },
]

const ACTIONABLE_SEVERITIES = new Set(['critical', 'high', 'medium'])

export function ComplianceSummary({ scanResultId }: ComplianceSummaryProps) {
  const [buckets, setBuckets] = useState<FrameworkBucket[] | null>(null)
  const [exploitCounts, setExploitCounts] = useState<Record<string, number>>({})

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const all: GroupedFindingResponse[] = []
        let offset = 0
        const pageSize = 200
        for (;;) {
          const page = await api.scanResults.groupedFindings(scanResultId, {
            limit: pageSize, offset,
          })
          all.push(...page.items)
          if (page.items.length < pageSize) break
          offset += pageSize
          if (offset > 2000) break  // safety cap
        }
        if (cancelled) return

        // Build per-framework counts and unique-ref sets.
        const map: Record<string, FrameworkBucket> = {}
        for (const fw of FRAMEWORKS) {
          map[fw.key] = {
            key: fw.key, label: fw.label, description: fw.description,
            total: 0, actionable: 0, uniqueRefs: new Set<string>(),
          }
        }
        const exp: Record<string, number> = {}
        for (const f of all) {
          const fwk = f.framework ?? {}
          const isActionable = ACTIONABLE_SEVERITIES.has(f.severity)
          for (const fw of FRAMEWORKS) {
            const values = (fwk as Record<string, unknown>)[fw.key]
            if (Array.isArray(values) && values.length > 0) {
              map[fw.key].total += 1
              if (isActionable) map[fw.key].actionable += 1
              for (const v of values) {
                if (typeof v === 'string') map[fw.key].uniqueRefs.add(v)
              }
            }
          }
          const e = (fwk as { exploitability?: unknown }).exploitability
          if (typeof e === 'string') exp[e] = (exp[e] ?? 0) + 1
        }

        setBuckets(FRAMEWORKS.map(fw => map[fw.key]))
        setExploitCounts(exp)
      } catch {
        if (!cancelled) setBuckets([])
      }
    }
    load()
    return () => { cancelled = true }
  }, [scanResultId])

  if (buckets === null) {
    return (
      <Card>
        <div className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <Scale className="w-4 h-4 text-gray-400" />
            <h2 className="font-medium text-white">Compliance &amp; Standards Coverage</h2>
          </div>
          <div className="h-20 bg-gray-800/40 rounded animate-pulse" />
        </div>
      </Card>
    )
  }

  const visible = buckets.filter(b => b.total > 0)
  if (visible.length === 0) return null

  const knownExploited = exploitCounts.known_exploited ?? 0
  const practical = exploitCounts.practical ?? 0

  return (
    <Card>
      <div className="flex items-center justify-between gap-2 p-4 border-b border-app-border">
        <div className="flex items-center gap-2">
          <Scale className="w-4 h-4 text-gray-400" />
          <h2 className="font-medium text-white">Compliance &amp; Standards Coverage</h2>
        </div>
        <div className="flex items-center gap-1.5">
          {knownExploited > 0 && (
            <Badge className="bg-red-500/15 text-red-300 border-red-500/30 text-[10px] flex items-center gap-1">
              <AlertTriangle className="w-2.5 h-2.5" />
              {knownExploited} known-exploited
            </Badge>
          )}
          {practical > 0 && (
            <Badge className="bg-orange-500/15 text-orange-300 border-orange-500/30 text-[10px]">
              {practical} practical
            </Badge>
          )}
        </div>
      </div>

      <div className="p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
        {visible.map(b => {
          const refsList = Array.from(b.uniqueRefs).slice(0, 6)
          return (
            <div
              key={b.key}
              className="bg-app-card rounded-lg p-3 flex flex-col gap-1.5 border border-app-border"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-[12px] font-semibold text-white truncate">{b.label}</p>
                  <p className="text-[10px] text-gray-500 leading-snug">{b.description}</p>
                </div>
                <div className="text-right flex-shrink-0">
                  <p className={`text-[18px] font-mono font-bold leading-none ${
                    b.actionable > 0 ? 'text-orange-400' : 'text-gray-400'
                  }`}>
                    {b.total}
                  </p>
                  <p className="text-[9px] text-gray-500 uppercase tracking-wide">findings</p>
                </div>
              </div>
              <div className="flex items-center gap-1.5 text-[10px]">
                {b.actionable > 0 ? (
                  <span className="text-orange-300">
                    {b.actionable} need attention
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-emerald-300">
                    <ShieldCheck className="w-2.5 h-2.5" /> all advisory
                  </span>
                )}
                <span className="text-gray-600">·</span>
                <span className="text-gray-500">{b.uniqueRefs.size} refs</span>
              </div>
              {refsList.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-0.5">
                  {refsList.map((r, i) => (
                    <span
                      key={i}
                      className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-gray-500/10 text-gray-400 border border-gray-500/15"
                    >
                      {r}
                    </span>
                  ))}
                  {b.uniqueRefs.size > refsList.length && (
                    <span className="text-[9px] text-gray-600">
                      +{b.uniqueRefs.size - refsList.length}
                    </span>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </Card>
  )
}
