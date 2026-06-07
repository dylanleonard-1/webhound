'use client'

// Phase-16 Agency/MSP portfolio command center — overview of every site
// one account monitors: portfolio scores, cross-site alerts, the site
// table with client-group filtering, and the top-risk / most-changed
// panels. Activates only when the user opens it; single-site users keep
// their normal dashboard.

import { useEffect, useState, useCallback, useMemo } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { Layers, ShieldAlert, AlertTriangle, Activity, TrendingUp, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import {
  api,
  type PortfolioSummary,
  type PortfolioSitesResponse,
  type PortfolioAlertsResponse,
  type PortfolioGroup,
} from '@/lib/api'
import { LoadingState } from '@/components/loading-state'
import { ErrorState } from '@/components/error-state'

const RISK_COLOR: Record<string, string> = {
  safe: '#8BFF3E', low: '#4F9CF9', medium: '#FFC53E',
  high: '#FF8A3E', critical: '#ef4444',
}
const SEV_COLOR: Record<string, string> = {
  info: '#9ca3af', low: '#4F9CF9', medium: '#FFC53E',
  high: '#FF8A3E', critical: '#ef4444',
}

function ScoreCard({ label, value, suffix = '/100', accent }: {
  label: string; value: number; suffix?: string; accent: string
}) {
  return (
    <div className="rounded-xl border p-4"
      style={{ borderColor: 'rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.02)' }}>
      <div className="text-xs uppercase tracking-wide text-gray-400">{label}</div>
      <div className="mt-1 text-2xl font-semibold" style={{ color: accent }}>
        {value}<span className="text-sm text-gray-500">{suffix}</span>
      </div>
    </div>
  )
}

export default function PortfolioPage() {
  const [summary, setSummary] = useState<PortfolioSummary | null>(null)
  const [sites, setSites] = useState<PortfolioSitesResponse | null>(null)
  const [alerts, setAlerts] = useState<PortfolioAlertsResponse | null>(null)
  const [groups, setGroups] = useState<PortfolioGroup[]>([])
  const [groupFilter, setGroupFilter] = useState<string>('all')
  const [riskFilter, setRiskFilter] = useState<string>('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const [s, si, al, gr] = await Promise.all([
        api.portfolio.summary(),
        api.portfolio.sites(),
        api.portfolio.alerts(),
        api.portfolio.listGroups(),
      ])
      setSummary(s); setSites(si); setAlerts(al); setGroups(gr.groups)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load portfolio')
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { void load() }, [load])

  const filteredSites = useMemo(() => {
    const rows = sites?.sites ?? []
    return rows.filter(r =>
      (groupFilter === 'all' || r.group_id === groupFilter) &&
      (riskFilter === 'all' || r.risk_level === riskFilter))
  }, [sites, groupFilter, riskFilter])

  if (loading) return <LoadingState message="Loading portfolio…" />
  if (error) return <ErrorState message={error} onRetry={() => void load()} />
  if (!summary) return null

  const sc = summary.summary
  const d = summary.dashboard

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Layers className="h-6 w-6" style={{ color: '#8BFF3E' }} />
          <div>
            <h1 className="text-xl font-semibold text-white">Portfolio</h1>
            <p className="text-sm text-gray-400">
              {sc.sites_monitored} site{sc.sites_monitored === 1 ? '' : 's'} monitored
            </p>
          </div>
        </div>
        <button onClick={() => void load()}
          className="flex items-center gap-2 rounded-lg border px-3 py-2 text-sm text-gray-300"
          style={{ borderColor: 'rgba(255,255,255,0.1)' }}>
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>

      {/* Portfolio scores */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <ScoreCard label="Risk" value={sc.portfolio_risk_score}
          accent={sc.portfolio_risk_score >= 60 ? '#ef4444' : '#8BFF3E'} />
        <ScoreCard label="Health" value={sc.portfolio_health_score}
          accent={sc.portfolio_health_score >= 60 ? '#8BFF3E' : '#FF8A3E'} />
        <ScoreCard label="Monitoring" value={sc.portfolio_monitoring_score} accent="#4F9CF9" />
        <ScoreCard label="Stability" value={sc.portfolio_stability_score} accent="#FFC53E" />
      </div>

      {/* Cross-site alerts */}
      {alerts && alerts.count > 0 && (
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
          className="rounded-xl border p-4"
          style={{ borderColor: 'rgba(239,68,68,0.25)', background: 'rgba(239,68,68,0.05)' }}>
          <div className="mb-3 flex items-center gap-2 text-sm font-medium text-white">
            <AlertTriangle className="h-4 w-4" style={{ color: '#FF8A3E' }} />
            Cross-Site Alerts ({alerts.count})
          </div>
          <div className="space-y-2">
            {alerts.alerts.slice(0, 6).map((a, i) => (
              <div key={i} className="flex items-start gap-3 text-sm">
                <span className="mt-0.5 rounded px-1.5 py-0.5 text-xs font-medium"
                  style={{ color: SEV_COLOR[a.severity], background: `${SEV_COLOR[a.severity]}1a` }}>
                  {a.severity}
                </span>
                <div>
                  <div className="text-gray-200">{a.title}</div>
                  <div className="text-xs text-gray-500">{a.detail}</div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Top panels */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Panel icon={<ShieldAlert className="h-4 w-4" />} title="Highest-Risk Sites"
          rows={d.most_vulnerable_sites.map(s => ({ label: s.url, value: s.risk_level }))} />
        <Panel icon={<TrendingUp className="h-4 w-4" />} title="Most Changed"
          rows={d.most_changed_sites.map(s => ({ label: s.url, value: `${s.change_frequency} changes` }))} />
        <Panel icon={<Activity className="h-4 w-4" />} title="Most Stable"
          rows={d.most_stable_sites.map(s => ({ label: s.url, value: `health ${s.health_score}` }))} />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select value={groupFilter} onChange={e => setGroupFilter(e.target.value)}
          className="rounded-lg border bg-transparent px-3 py-2 text-sm text-gray-300"
          style={{ borderColor: 'rgba(255,255,255,0.1)' }}>
          <option value="all">All clients/groups</option>
          {groups.map(g => <option key={g.group_id} value={g.group_id}>{g.name} ({g.site_count})</option>)}
        </select>
        <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)}
          className="rounded-lg border bg-transparent px-3 py-2 text-sm text-gray-300"
          style={{ borderColor: 'rgba(255,255,255,0.1)' }}>
          <option value="all">All risk levels</option>
          {['critical', 'high', 'medium', 'low', 'safe'].map(l => <option key={l} value={l}>{l}</option>)}
        </select>
      </div>

      {/* Site table */}
      <div className="overflow-hidden rounded-xl border" style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
        <table className="w-full text-left text-sm">
          <thead className="text-xs uppercase text-gray-500" style={{ background: 'rgba(255,255,255,0.03)' }}>
            <tr>
              <th className="px-4 py-3">Domain</th>
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3">Monitoring</th>
              <th className="px-4 py-3">Changes</th>
              <th className="px-4 py-3">Last Scan</th>
            </tr>
          </thead>
          <tbody>
            {filteredSites.map(r => (
              <tr key={r.site_id} className="border-t" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
                <td className="px-4 py-3">
                  <Link href={`/dashboard/websites/${r.site_id}`} className="text-gray-200 hover:underline">
                    {r.domain}
                  </Link>
                </td>
                <td className="px-4 py-3">
                  <span style={{ color: RISK_COLOR[r.risk_level] }}>{r.risk_level}</span>
                  <span className="text-gray-600"> · {r.risk_score}</span>
                </td>
                <td className="px-4 py-3 text-gray-400">{r.monitoring ? 'Active' : 'Not scanned'}</td>
                <td className="px-4 py-3 text-gray-400">{r.wade_changed ? 'Changed' : '—'}</td>
                <td className="px-4 py-3 text-gray-500">
                  {r.last_scan_at ? new Date(r.last_scan_at).toLocaleDateString() : '—'}
                </td>
              </tr>
            ))}
            {filteredSites.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">No sites match these filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Panel({ icon, title, rows }: {
  icon: React.ReactNode; title: string; rows: { label: string; value: string }[]
}) {
  return (
    <div className="rounded-xl border p-4" style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
      <div className="mb-3 flex items-center gap-2 text-sm font-medium text-gray-300">{icon}{title}</div>
      <div className="space-y-2">
        {rows.length === 0 && <div className="text-xs text-gray-600">No sites.</div>}
        {rows.slice(0, 5).map((r, i) => (
          <div key={i} className="flex items-center justify-between text-sm">
            <span className="truncate text-gray-400">{r.label.replace(/^https?:\/\//, '')}</span>
            <span className="ml-2 shrink-0 text-xs text-gray-500">{r.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
