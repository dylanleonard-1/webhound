'use client'

// Global Command Center — live operational metrics for the internal SOC.

import { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  Activity, Users, ScanLine, CircleCheck, Clock, TrendingUp, Siren, ArrowRight, ArrowUp, ArrowDown, Minus,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell, Tooltip,
} from 'recharts'
import { api, type CommandCenter } from '@/lib/api'

const LIME = '#8BFF3E'

const ok = (v: unknown): v is Record<string, number> =>
  !!v && typeof v === 'object' && !('error' in (v as object))

// Maps the new infra.overall code to a friendly label + color for the header.
const OVERALL_LABEL: Record<string, { label: string; color: string }> = {
  operational: { label: 'Operational', color: LIME },
  degraded:    { label: 'Degraded',    color: '#f59e0b' },
  maintenance: { label: 'Maintenance', color: '#a855f7' },
  offline:     { label: 'Offline',     color: '#ef4444' },
}

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6', info: '#8b94a6',
}

function HealthPill({ label, status, severity = false }: {
  label: string; status: string; severity?: boolean
}) {
  // `severity=true` means the status string itself is the operational code
  // (operational/degraded/maintenance/offline). Otherwise legacy ok/down/stale.
  const tone = severity
    ? OVERALL_LABEL[status]?.color ?? 'rgba(255,255,255,0.5)'
    : (status === 'ok' ? LIME
       : status === 'stale' || status === 'unknown' ? '#f59e0b'
       : 'rgba(255,255,255,0.55)')
  const display = severity ? (OVERALL_LABEL[status]?.label ?? status) : status
  return (
    <div className="flex items-center gap-2 rounded-lg px-3 py-2"
         style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
      <span className="w-2 h-2 rounded-full"
            style={{ background: tone, boxShadow: `0 0 8px ${tone}` }} />
      <span className="text-[11px]" style={{ color: 'rgba(255,255,255,0.55)' }}>{label}</span>
      <span className="text-[11px] font-semibold ml-auto" style={{ color: tone }}>{display}</span>
    </div>
  )
}

// Delta pill: shows ↑5.2% / ↓12% / · steady with semantic color. `positive`
// flips the color mapping for "delta of failure rate" (where down = good).
function Delta({ pct, positiveIsGood = true }: { pct: number | null | undefined; positiveIsGood?: boolean }) {
  if (pct == null) {
    return <span className="text-[10px] text-white/30">· new</span>
  }
  const Icon = pct > 0 ? ArrowUp : pct < 0 ? ArrowDown : Minus
  const isGood = pct === 0 ? null : (pct > 0) === positiveIsGood
  const color = isGood === null ? 'rgba(255,255,255,0.45)'
    : isGood ? '#8BFF3E' : '#ef4444'
  const label = pct === 0 ? 'steady'
    : `${pct > 0 ? '+' : ''}${pct.toFixed(1)}%`
  return (
    <span className="inline-flex items-center gap-0.5 text-[10px] font-semibold"
          style={{ color }}>
      <Icon className="w-2.5 h-2.5" /> {label}
    </span>
  )
}

function Stat({ icon: Icon, label, value, sub, trend }: {
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  label: string; value: React.ReactNode; sub?: string
  trend?: React.ReactNode
}) {
  return (
    <div className="rounded-xl p-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)' }}>
      <div className="flex items-center gap-2 mb-2">
        <Icon className="w-4 h-4" style={{ color: 'rgba(255,255,255,0.4)' }} />
        <span className="text-[11px] font-bold tracking-[0.1em] uppercase" style={{ color: 'rgba(255,255,255,0.4)' }}>{label}</span>
        {trend && <span className="ml-auto">{trend}</span>}
      </div>
      <div className="text-[26px] font-bold text-white leading-none">{value}</div>
      {sub && <div className="text-[11px] mt-1.5" style={{ color: 'rgba(255,255,255,0.4)' }}>{sub}</div>}
    </div>
  )
}

function IncidentBanner({ data }: { data: NonNullable<CommandCenter['incidents']> }) {
  const top = data.top
  if (!top) return null
  const c = SEV_COLOR[top.severity] ?? '#f59e0b'
  return (
    <Link href={`/control/incidents`}
          className="block rounded-xl p-3.5 hover:bg-white/[0.02] transition-colors"
          style={{ background: `${c}0d`, border: `1px solid ${c}3a` }}>
      <div className="flex items-center gap-3">
        <Siren className="w-4 h-4 shrink-0" style={{ color: c }} />
        <div className="min-w-0 flex-1">
          <div className="text-[12px] font-semibold flex items-center gap-2">
            <span className="font-mono text-[10px] px-1.5 py-0.5 rounded uppercase tracking-wider"
                  style={{ background: `${c}1a`, color: c, border: `1px solid ${c}33` }}>
              {top.severity}
            </span>
            <span className="text-white truncate">INC-{String(top.number).padStart(4, '0')} · {top.title}</span>
            {top.breached && (
              <span className="text-[10px] font-bold px-1.5 py-0.5 rounded uppercase"
                    style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444',
                             border: '1px solid rgba(239,68,68,0.3)' }}>
                SLA breach
              </span>
            )}
          </div>
          <div className="text-[11px] mt-0.5" style={{ color: 'rgba(255,255,255,0.55)' }}>
            {data.active} active · {data.breached} breached · {top.alert_count} alerts on top incident
          </div>
        </div>
        <ArrowRight className="w-4 h-4 shrink-0" style={{ color: c }} />
      </div>
    </Link>
  )
}

export default function CommandCenterPage() {
  const [data, setData] = useState<CommandCenter | null>(null)
  const [err, setErr] = useState(false)

  useEffect(() => {
    let cancelled = false
    const load = () => api.internal.commandCenter()
      .then(d => { if (!cancelled) { setData(d); setErr(false) } })
      .catch(() => { if (!cancelled) setErr(true) })
    load()
    const id = setInterval(load, 10000)
    return () => { cancelled = true; clearInterval(id) }
  }, [])

  const scans = data && ok(data.scans) ? data.scans : null
  const users = data && ok(data.users) ? data.users : null
  const billing = data && ok(data.billing) ? data.billing : null
  const infra = data?.infra && !('error' in data.infra) ? data.infra : null
  const overall = infra?.overall ?? 'operational'

  const chart = scans ? [
    { name: 'Completed', value: scans.completed_24h, color: LIME },
    { name: 'Failed', value: scans.failed_24h, color: '#ef4444' },
    { name: 'Queued', value: scans.queued, color: '#3b82f6' },
    { name: 'Running', value: scans.running, color: '#f59e0b' },
  ] : []

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-[19px] font-bold text-white">Command Center</h1>
          {infra && (
            <span className="text-[10px] font-bold tracking-[0.18em] uppercase px-2 py-0.5 rounded"
                  style={{ background: `${OVERALL_LABEL[overall]?.color ?? LIME}1a`,
                           color: OVERALL_LABEL[overall]?.color ?? LIME,
                           border: `1px solid ${OVERALL_LABEL[overall]?.color ?? LIME}33` }}>
              {OVERALL_LABEL[overall]?.label ?? overall}
            </span>
          )}
          {data && (
            <span className="text-[11px]" style={{ color: 'rgba(255,255,255,0.4)' }}>
              · updated {new Date(data.generated_at).toLocaleTimeString()}
            </span>
          )}
        </div>
        {err && <span className="text-[12px] text-red-400">metrics unavailable — retrying…</span>}
      </div>

      {data?.incidents && <IncidentBanner data={data.incidents} />}

      {/* Infra health */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2.5">
        <HealthPill label="Posture" status={overall} severity />
        <HealthPill label="Database" status={infra?.database ?? '…'} />
        <HealthPill label="Redis" status={infra?.redis ?? '…'} />
        <HealthPill label="Worker" status={infra?.worker ?? '…'} />
        <HealthPill label="Queue depth" status={infra?.queue_depth != null ? String(infra.queue_depth) : '…'} />
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat icon={ScanLine} label="Active scans" value={scans ? scans.queued + scans.running : '—'}
              sub={scans ? `${scans.queued} queued · ${scans.running} running` : ''} />
        <Stat icon={CircleCheck} label="Completed 24h" value={scans?.completed_24h ?? '—'}
              sub={scans?.avg_duration_s != null ? `avg ${scans.avg_duration_s}s` : ''}
              trend={scans ? <Delta pct={scans.completed_24h_delta_pct} positiveIsGood /> : undefined} />
        <Stat icon={Users} label="Customers" value={users?.paid ?? '—'}
              sub={users ? `${users.total} total · ${users.new_7d} new (7d)` : ''}
              trend={users ? <Delta pct={users.new_7d_delta_pct} positiveIsGood /> : undefined} />
        <Stat icon={TrendingUp} label="MRR" value={billing ? `$${billing.mrr_usd.toLocaleString()}` : '—'}
              sub={billing ? `$${billing.arr_usd.toLocaleString()} ARR · ${billing.active_subscriptions} active` : ''} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {/* Scan funnel chart */}
        <div className="rounded-xl p-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)' }}>
          <div className="flex items-center gap-2 mb-3">
            <Activity className="w-4 h-4" style={{ color: LIME }} />
            <span className="text-[12px] font-semibold text-white">Scan activity (24h)</span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={chart} layout="vertical" margin={{ left: 8, right: 16 }}>
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="name" width={80} tick={{ fill: 'rgba(255,255,255,0.5)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                       contentStyle={{ background: '#0b0f17', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {chart.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Activity feed */}
        <div className="rounded-xl p-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)' }}>
          <div className="flex items-center gap-2 mb-3">
            <Clock className="w-4 h-4" style={{ color: 'rgba(255,255,255,0.5)' }} />
            <span className="text-[12px] font-semibold text-white">Recent admin activity</span>
          </div>
          <div className="space-y-1.5 max-h-[200px] overflow-auto">
            {(data?.activity ?? []).length === 0 ? (
              <p className="text-[12px]" style={{ color: 'rgba(255,255,255,0.35)' }}>No recorded actions yet.</p>
            ) : (
              data!.activity.map(a => (
                <div key={a.id} className="flex items-center gap-2 text-[12px] py-1">
                  <span className="font-mono px-1.5 py-0.5 rounded text-[10px]" style={{ background: 'rgba(139,255,62,0.08)', color: LIME }}>{a.action}</span>
                  <span style={{ color: 'rgba(255,255,255,0.6)' }}>{a.actor ?? 'system'}</span>
                  {a.target && <span style={{ color: 'rgba(255,255,255,0.35)' }}>· {a.target}</span>}
                  <span className="ml-auto text-[10px]" style={{ color: 'rgba(255,255,255,0.3)' }}>{a.at ? new Date(a.at).toLocaleTimeString() : ''}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
