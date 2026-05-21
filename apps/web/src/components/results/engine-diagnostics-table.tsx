'use client'

import { useCallback, useEffect, useState } from 'react'
import { Cpu, CheckCircle, XCircle, MinusCircle, AlertCircle, ChevronDown, ChevronRight } from 'lucide-react'
import { api, type EngineDiagnosticResponse } from '@/lib/api'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { LoadingState } from '@/components/loading-state'
import { EmptyState } from '@/components/empty-state'
import { ErrorState } from '@/components/error-state'
import { cn } from '@/lib/utils'

interface EngineDiagnosticsTableProps {
  scanResultId: string
}

const ENGINE_LABELS: Record<string, string> = {
  security_headers:     'Security Headers',
  cors:                 'CORS Policy',
  cookie_scanner:       'Cookie Security',
  csp:                  'Content Security Policy',
  tls_checker:          'TLS / HTTPS',
  dns_checker:          'DNS Security',
  js_collector:         'Script Inventory',
  js_analyzer:          'JavaScript Analysis',
  obfuscation_detector: 'Code Obfuscation',
  third_party_domains:  'Third-Party Scripts',
  technology:           'Technology Detection',
  sensitive_paths:      'Sensitive Paths',
  robots_sitemap:       'Robots & Sitemap',
  form_risk:            'Form Security',
  input_analysis:       'Input Validation',
  injected_js:          'Script Injection',
  hidden_iframes:       'Hidden Iframes',
  seo_spam:             'SEO Spam Detection',
  suspicious_redirects: 'Redirect Analysis',
  wade:                 'Behavioral Anomalies',
  secret_scanner:       'Secret Detection',
}

const CATEGORY_LABELS: Record<string, string> = {
  headers:            'Headers',
  cookies:            'Cookies',
  tls_dns:            'TLS / DNS',
  javascript:         'JavaScript',
  technology:         'Technology',
  recon:              'Reconnaissance',
  forms:              'Forms',
  compromise:         'Compromise',
  anomaly_detection:  'Anomaly Detection',
  unknown:            'Other',
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info:     'bg-gray-500/15 text-gray-400 border-gray-500/30',
}

function formatDuration(ms: number | null) {
  if (ms === null) return '—'
  if (ms < 1000) return `${ms.toFixed(0)}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

function topSeverity(counts: Record<string, number> | null): string | null {
  if (!counts) return null
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    if ((counts[sev] ?? 0) > 0) return sev
  }
  return null
}

function EngineRow({ d }: { d: EngineDiagnosticResponse }) {
  const label = ENGINE_LABELS[d.engine_name] ?? d.engine_name.replace(/_/g, ' ')
  const catLabel = CATEGORY_LABELS[d.category ?? ''] ?? d.category ?? ''
  const top = topSeverity(d.severity_counts)

  return (
    <div className="grid grid-cols-[1fr_auto_auto_auto] gap-3 items-center px-4 py-2.5 text-sm">
      <div className="min-w-0">
        <span className="text-gray-200 text-sm truncate block">{label}</span>
        {catLabel && <span className="text-[10px] text-gray-600">{catLabel}</span>}
      </div>
      <div className="flex items-center gap-1.5">
        {top && (
          <Badge className={cn('text-[10px]', SEVERITY_BADGE[top])}>
            {top}
          </Badge>
        )}
        <span className="font-mono text-gray-300 text-sm w-6 text-right">{d.findings_count}</span>
      </div>
      <span className="text-xs font-mono text-gray-500 w-16 text-right hidden sm:block">
        {formatDuration(d.duration_ms)}
      </span>
      <div className="w-24 hidden lg:block">
        {d.error_message && (
          <span className="text-[10px] text-red-400 truncate block" title={d.error_message}>
            {d.error_message}
          </span>
        )}
        {d.skipped_reason && (
          <span className="text-[10px] text-gray-500 truncate block" title={d.skipped_reason}>
            {d.skipped_reason}
          </span>
        )}
      </div>
    </div>
  )
}

function CollapsibleGroup({
  label,
  icon: Icon,
  iconClass,
  items,
  defaultOpen = false,
  headerBadge,
}: {
  label: string
  icon: React.FC<{ className?: string }>
  iconClass: string
  items: EngineDiagnosticResponse[]
  defaultOpen?: boolean
  headerBadge?: string
}) {
  const [open, setOpen] = useState(defaultOpen)
  if (items.length === 0) return null

  return (
    <div className="border-t border-app-border first:border-0">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-4 py-2.5 hover:bg-white/[0.02] transition-colors"
      >
        <Icon className={cn('w-3.5 h-3.5 flex-shrink-0', iconClass)} />
        <span className="text-xs font-medium text-gray-300">{label}</span>
        <Badge className={cn('text-[10px] ml-1', headerBadge ?? 'bg-gray-500/10 text-gray-400 border-gray-500/20')}>
          {items.length}
        </Badge>
        <span className="ml-auto">
          {open
            ? <ChevronDown className="w-3 h-3 text-gray-600" />
            : <ChevronRight className="w-3 h-3 text-gray-600" />
          }
        </span>
      </button>

      {open && (
        <div className="divide-y divide-app-border/50">
          {items.map(d => <EngineRow key={d.id} d={d} />)}
        </div>
      )}
    </div>
  )
}

export function EngineDiagnosticsTable({ scanResultId }: EngineDiagnosticsTableProps) {
  const [diagnostics, setDiagnostics] = useState<EngineDiagnosticResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError(false)
    try {
      const data = await api.scanResults.engineDiagnostics(scanResultId)
      setDiagnostics(data)
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }, [scanResultId])

  useEffect(() => { load() }, [load])

  const failed   = diagnostics.filter(d => d.status === 'failed')
  const findings = diagnostics.filter(d => d.status === 'findings')
  const passed   = diagnostics.filter(d => d.status === 'passed')
  const skipped  = diagnostics.filter(d => d.status === 'skipped')

  return (
    <Card>
      <div className="flex items-center gap-2 p-4 border-b border-app-border">
        <Cpu className="w-4 h-4 text-gray-400" />
        <h2 className="font-medium text-white">Scanner Engines</h2>
        {!loading && !error && (
          <div className="flex items-center gap-1.5 ml-1">
            {failed.length > 0 && (
              <Badge className="bg-red-500/10 text-red-400 border-red-500/20 text-[10px]">
                {failed.length} failed
              </Badge>
            )}
            {findings.length > 0 && (
              <Badge className="bg-orange-500/10 text-orange-400 border-orange-500/20 text-[10px]">
                {findings.length} with findings
              </Badge>
            )}
            <Badge className="bg-gray-500/10 text-gray-400 border-gray-500/20 text-[10px]">
              {passed.length} passed
            </Badge>
          </div>
        )}
      </div>

      {loading ? (
        <div className="p-6"><LoadingState /></div>
      ) : error ? (
        <div className="p-6"><ErrorState message="Failed to load engine diagnostics." onRetry={load} /></div>
      ) : diagnostics.length === 0 ? (
        <div className="p-6">
          <EmptyState title="No diagnostics" description="No engine diagnostic data available." />
        </div>
      ) : (
        <div>
          {/* Failed engines — always visible, prominent */}
          {failed.length > 0 && (
            <div className="border-t border-app-border first:border-0">
              <div className="flex items-center gap-2 px-4 py-2.5 bg-red-500/5">
                <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                <span className="text-xs font-medium text-red-400">Engines with errors — these checks were not completed</span>
              </div>
              <div className="divide-y divide-app-border/50">
                {failed.map(d => <EngineRow key={d.id} d={d} />)}
              </div>
            </div>
          )}

          {/* Engines with findings — expanded by default */}
          <CollapsibleGroup
            label="Engines with findings"
            icon={AlertCircle}
            iconClass="text-orange-400"
            items={findings}
            defaultOpen={true}
            headerBadge="bg-orange-500/10 text-orange-400 border-orange-500/20"
          />

          {/* Passed — collapsed by default */}
          <CollapsibleGroup
            label="Engines that passed"
            icon={CheckCircle}
            iconClass="text-accent-green"
            items={passed}
            defaultOpen={false}
            headerBadge="bg-accent-green/10 text-accent-green border-accent-green/20"
          />

          {/* Skipped — collapsed by default */}
          <CollapsibleGroup
            label="Skipped checks"
            icon={MinusCircle}
            iconClass="text-gray-500"
            items={skipped}
            defaultOpen={false}
          />
        </div>
      )}
    </Card>
  )
}
