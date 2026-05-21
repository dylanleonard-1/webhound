'use client'

import { useCallback, useEffect, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowRight, Braces, ChevronRight,
  Code2, Cookie, Cpu, FileText, Filter, Flame, Globe,
  HelpCircle, Info, Lock, Network, Search, Shield,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { api, type GroupedFindingResponse } from '@/lib/api'
import { Badge } from '@/components/ui/badge'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { FindingDetailDrawer } from './finding-detail-drawer'
import { LoadingState } from '@/components/loading-state'
import { EmptyState } from '@/components/empty-state'
import { ErrorState } from '@/components/error-state'
import { cn } from '@/lib/utils'

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info:     'bg-gray-500/15 text-gray-400 border-gray-500/30',
}

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-400',
  high:     'bg-orange-400',
  medium:   'bg-yellow-400',
  low:      'bg-blue-400',
  info:     'bg-gray-500',
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

const CATEGORY_LABEL: Record<string, string> = {
  security_header:    'Security Headers',
  headers:            'Headers',
  javascript:         'JavaScript',
  cookies:            'Cookies',
  tls_dns:            'TLS / DNS',
  forms:              'Forms',
  recon:              'Reconnaissance',
  compromise:         'Compromise',
  technology:         'Technology',
  anomaly_detection:  'Anomaly',
}

const CATEGORY_ICON: Record<string, LucideIcon> = {
  security_header: Shield,
  headers:         Shield,
  javascript:      Code2,
  cookies:         Cookie,
  tls_dns:         Lock,
  tls:             Lock,
  dns:             Network,
  forms:           FileText,
  recon:           Search,
  compromise:      AlertTriangle,
  technology:      Cpu,
  cors:            Globe,
  api:             Braces,
  anomaly_detection: Activity,
  informational:   Info,
}

function CategoryIcon({ category, className }: { category: string; className?: string }) {
  const Icon = CATEGORY_ICON[category] ?? HelpCircle
  return <Icon className={cn('w-3 h-3 flex-shrink-0', className)} />
}

// Confidence bar: 0–100 filled portion with color by confidence level
function ConfidenceBar({ value }: { value: number | null }) {
  if (value === null) return null
  const pct = Math.round(value * 100)
  const color = pct >= 80 ? 'bg-accent-green' : pct >= 50 ? 'bg-yellow-500' : 'bg-gray-500'
  return (
    <div className="flex items-center gap-1.5 mt-0.5">
      <div className="h-1 w-14 rounded-full bg-white/[0.06] overflow-hidden">
        <div className={cn('h-full rounded-full transition-all', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] text-gray-600">{pct}% confidence</span>
    </div>
  )
}

// Plain-English impact hint per category shown in Fix First
const CATEGORY_IMPACT: Record<string, string> = {
  security_header:    'Missing headers let attackers hijack sessions or run malicious scripts.',
  headers:            'Missing security headers leave browsers unprotected.',
  javascript:         'Unsafe scripts can steal credentials or redirect visitors.',
  cookies:            'Insecure cookies can be stolen and used to impersonate your users.',
  tls_dns:            'Weak TLS or DNS issues expose data in transit.',
  forms:              'Forms without protection can leak user data or be abused.',
  recon:              'Exposed paths help attackers map your site.',
  compromise:         'Indicators of an active or past compromise detected.',
  technology:         'Outdated or revealed technology helps attackers choose exploits.',
}

function categoryLabel(raw: string): string {
  return CATEGORY_LABEL[raw] ?? raw.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

interface GroupedFindingsTableProps {
  scanResultId: string
}

export function GroupedFindingsTable({ scanResultId }: GroupedFindingsTableProps) {
  const [findings, setFindings] = useState<GroupedFindingResponse[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState(false)
  const [hasMore, setHasMore] = useState(false)
  const [selected, setSelected] = useState<GroupedFindingResponse | null>(null)

  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterCategory, setFilterCategory] = useState('')
  const [filterEngine, setFilterEngine] = useState('')

  const LIMIT = 50

  const load = useCallback(async () => {
    setLoading(true)
    setError(false)
    try {
      const res = await api.scanResults.groupedFindings(scanResultId, {
        limit: LIMIT,
        offset: 0,
        severity: filterSeverity || undefined,
        category: filterCategory || undefined,
        scanner_engine: filterEngine || undefined,
      })
      setFindings(res.items)
      setTotal(res.total)
      setHasMore(res.has_more)
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }, [scanResultId, filterSeverity, filterCategory, filterEngine])

  useEffect(() => { load() }, [load])

  async function loadMore() {
    setLoadingMore(true)
    try {
      const res = await api.scanResults.groupedFindings(scanResultId, {
        limit: LIMIT,
        offset: findings.length,
        severity: filterSeverity || undefined,
        category: filterCategory || undefined,
        scanner_engine: filterEngine || undefined,
      })
      setFindings(prev => [...prev, ...res.items])
      setTotal(res.total)
      setHasMore(res.has_more)
    } catch { /* ignore load-more failures silently */ }
    finally { setLoadingMore(false) }
  }

  const engines = [...new Set(findings.map(f => f.scanner_engine))].sort()
  const categories = [...new Set(findings.map(f => f.category))].sort()

  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  )

  const priorityFindings = sorted
    .filter(f => f.severity === 'critical' || f.severity === 'high')
    .slice(0, 5)

  const noFiltersActive = !filterSeverity && !filterCategory && !filterEngine

  return (
    <>
      {/* Fix First — only when unfiltered and critical/high findings exist */}
      {!loading && !error && priorityFindings.length > 0 && noFiltersActive && (
        <Card>
          <div className="flex items-center gap-2 p-4 border-b border-app-border">
            <Flame className="w-4 h-4 text-orange-400" />
            <h2 className="font-medium text-white">Fix First</h2>
            <span className="text-xs text-gray-500 hidden sm:block">
              Start here — these have the highest business impact
            </span>
          </div>
          <div className="divide-y divide-app-border">
            {priorityFindings.map((f, idx) => {
              const impact = CATEGORY_IMPACT[f.category] ?? null
              return (
                <button
                  key={f.id}
                  onClick={() => setSelected(f)}
                  className="w-full text-left px-4 py-3.5 hover:bg-white/[0.02] transition-colors group"
                >
                  <div className="flex items-start gap-3">
                    <div className="flex items-center justify-center w-5 h-5 rounded-full bg-white/5 text-[10px] font-bold text-gray-500 flex-shrink-0 mt-0.5">
                      {idx + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="text-sm font-medium text-gray-100 group-hover:text-white transition-colors">
                          {f.title}
                        </span>
                        <Badge className={cn('text-[10px]', SEVERITY_STYLE[f.severity] ?? SEVERITY_STYLE.info)}>
                          {f.severity}
                        </Badge>
                        <Badge className="bg-gray-500/10 text-gray-500 border-gray-500/20 text-[10px] inline-flex items-center gap-1">
                          <CategoryIcon category={f.category} />
                          {categoryLabel(f.category)}
                        </Badge>
                      </div>
                      {impact ? (
                        <p className="text-xs text-gray-400 line-clamp-1">{impact}</p>
                      ) : f.remediation ? (
                        <p className="text-xs text-gray-400 line-clamp-1">{f.remediation}</p>
                      ) : (
                        <p className="text-xs text-gray-600">
                          {f.affected_url_count} page{f.affected_url_count !== 1 ? 's' : ''} affected
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0 mt-0.5">
                      <span className="text-[11px] text-gray-600 hidden sm:block">
                        {f.affected_url_count} {f.affected_url_count === 1 ? 'page' : 'pages'}
                      </span>
                      <ArrowRight className="w-3.5 h-3.5 text-gray-600 group-hover:text-gray-400 transition-colors" />
                    </div>
                  </div>
                </button>
              )
            })}
          </div>
        </Card>
      )}

      <Card>
        {/* Header + filters */}
        <div className="p-4 border-b border-app-border">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-gray-400" />
              <h2 className="font-medium text-white">All Findings</h2>
              <Badge className="bg-gray-500/10 text-gray-400 border-gray-500/20">
                {total}
              </Badge>
            </div>
          </div>

          <div className="flex gap-2 flex-wrap">
            <select
              value={filterSeverity}
              onChange={e => setFilterSeverity(e.target.value)}
              className="bg-app-bg border border-app-border rounded-lg px-2.5 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-accent-green"
            >
              <option value="">All Severities</option>
              {SEVERITY_ORDER.map(s => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>

            {categories.length > 1 && (
              <select
                value={filterCategory}
                onChange={e => setFilterCategory(e.target.value)}
                className="bg-app-bg border border-app-border rounded-lg px-2.5 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-accent-green"
              >
                <option value="">All Categories</option>
                {categories.map(c => (
                  <option key={c} value={c}>{categoryLabel(c)}</option>
                ))}
              </select>
            )}

            {engines.length > 1 && (
              <select
                value={filterEngine}
                onChange={e => setFilterEngine(e.target.value)}
                className="bg-app-bg border border-app-border rounded-lg px-2.5 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-accent-green"
              >
                <option value="">All Engines</option>
                {engines.map(e => (
                  <option key={e} value={e}>{e}</option>
                ))}
              </select>
            )}

            {!noFiltersActive && (
              <button
                onClick={() => { setFilterSeverity(''); setFilterCategory(''); setFilterEngine('') }}
                className="text-xs text-gray-500 hover:text-gray-300 px-2 transition-colors"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Table body */}
        {loading ? (
          <div className="p-6"><LoadingState /></div>
        ) : error ? (
          <div className="p-6"><ErrorState message="Failed to load findings." onRetry={load} /></div>
        ) : sorted.length === 0 ? (
          <div className="p-6">
            <EmptyState
              title="No findings"
              description={noFiltersActive
                ? 'This scan found no security issues. Good work!'
                : 'No findings match the current filters.'
              }
            />
          </div>
        ) : (
          <>
            <div className="grid grid-cols-[auto_1fr_auto_auto_auto] gap-3 px-4 py-2 border-b border-app-border text-[10px] text-gray-500 uppercase tracking-wider">
              <span className="w-2" />
              <span>Finding</span>
              <span className="w-24 text-center hidden sm:block">Category</span>
              <span className="w-16 text-center">Pages</span>
              <span className="w-8" />
            </div>

            <div className="divide-y divide-app-border">
              {sorted.map(finding => (
                <button
                  key={finding.id}
                  onClick={() => setSelected(finding)}
                  className="w-full grid grid-cols-[auto_1fr_auto_auto_auto] gap-3 items-center px-4 py-3 hover:bg-white/[0.02] transition-colors text-left group"
                >
                  <div className={cn('w-2 h-2 rounded-full flex-shrink-0', SEVERITY_DOT[finding.severity] ?? SEVERITY_DOT.info)} />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                      <span className="text-sm text-gray-200 group-hover:text-white transition-colors">
                        {finding.title}
                      </span>
                      <Badge className={cn('text-[10px]', SEVERITY_STYLE[finding.severity] ?? SEVERITY_STYLE.info)}>
                        {finding.severity}
                      </Badge>
                    </div>
                    {finding.description && (
                      <p className="text-[11px] text-gray-500 truncate mt-0.5 max-w-[420px] leading-snug">
                        {finding.description}
                      </p>
                    )}
                    <ConfidenceBar value={finding.confidence} />
                  </div>
                  <div className="w-24 hidden sm:flex items-center justify-center gap-1">
                    <CategoryIcon category={finding.category} className="text-gray-600" />
                    <span className="text-[11px] text-gray-500 truncate">
                      {categoryLabel(finding.category)}
                    </span>
                  </div>
                  <div className="w-16 flex items-center justify-end gap-1">
                    <span className="text-sm font-mono text-gray-300">{finding.affected_url_count}</span>
                    <span className="text-[10px] text-gray-600 hidden sm:inline">
                      {finding.affected_url_count === 1 ? 'pg' : 'pgs'}
                    </span>
                  </div>
                  <ChevronRight className="w-3.5 h-3.5 text-gray-600 group-hover:text-gray-400 transition-colors w-8" />
                </button>
              ))}
            </div>

            {hasMore && (
              <div className="p-4 border-t border-app-border">
                <Button
                  variant="ghost"
                  size="sm"
                  className="w-full"
                  onClick={loadMore}
                  disabled={loadingMore}
                >
                  {loadingMore ? 'Loading…' : `Load more (${total - findings.length} remaining)`}
                </Button>
              </div>
            )}
          </>
        )}
      </Card>

      <FindingDetailDrawer
        finding={selected}
        scanResultId={scanResultId}
        onClose={() => setSelected(null)}
      />
    </>
  )
}
