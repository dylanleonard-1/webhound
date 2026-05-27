'use client'

// Global Command Center — live operational metrics for the internal SOC.

import { useEffect, useState } from 'react'
import {
  Activity, Users, ScanLine, CircleCheck, Clock, TrendingUp,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell, Tooltip,
} from 'recharts'
import { api, type CommandCenter } from '@/lib/api'

const LIME = '#8BFF3E'
const ok = (v: unknown): v is Record<string, number> =>
  !!v && typeof v === 'object' && !('error' in (v as object))

function HealthPill({ label, status }: { label: string; status: string }) {
  const good = status === 'ok'
  const warn = status === 'stale' || status === 'unknown'
  const color = good ? LIME : warn ? '#f59e0b' : '#ef4444'
  return (
    <div className="flex items-center gap-2 rounded-lg px-3 py-2"
         style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
      <span className="w-2 h-2 rounded-full" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
      <span className="text-[11px]" style={{ color: 'rgba(255,255,255,0.55)' }}>{label}</span>
      <span className="text-[11px] font-semibold ml-auto" style={{ color }}>{status}</span>
    </div>
  )
}

function Stat({ icon: Icon, label, value, sub }: {
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  label: string; value: React.ReactNode; sub?: string
}) {
  return (
    <div className="rounded-xl p-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)' }}>
      <div className="flex items-center gap-2 mb-2">
        <Icon className="w-4 h-4" style={{ color: 'rgba(255,255,255,0.4)' }} />
        <span className="text-[11px] font-bold tracking-[0.1em] uppercase" style={{ color: 'rgba(255,255,255,0.4)' }}>{label}</span>
      </div>
      <div className="text-[26px] font-bold text-white leading-none">{value}</div>
      {sub && <div className="text-[11px] mt-1.5" style={{ color: 'rgba(255,255,255,0.4)' }}>{sub}</div>}
    </div>
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

  const chart = scans ? [
    { name: 'Completed', value: scans.completed_24h, color: LIME },
    { name: 'Failed', value: scans.failed_24h, color: '#ef4444' },
    { name: 'Queued', value: scans.queued, color: '#3b82f6' },
    { name: 'Running', value: scans.running, color: '#f59e0b' },
  ] : []

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[19px] font-bold text-white">Command Center</h1>
          <p className="text-[12px]" style={{ color: 'rgba(255,255,255,0.4)' }}>
            Live operational metrics{data ? ` · updated ${new Date(data.generated_at).toLocaleTimeString()}` : ''}
          </p>
        </div>
        {err && <span className="text-[12px] text-red-400">metrics unavailable — retrying…</span>}
      </div>

      {/* Infra health */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2.5">
        <HealthPill label="Database" status={infra?.database ?? '…'} />
        <HealthPill label="Redis" status={infra?.redis ?? '…'} />
        <HealthPill label="Worker" status={infra?.worker ?? '…'} />
        <HealthPill label="Stripe" status={infra?.stripe_configured ? 'ok' : 'down'} />
        <HealthPill label="Queue depth" status={infra?.queue_depth != null ? String(infra.queue_depth) : '…'} />
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat icon={ScanLine} label="Active scans" value={scans ? scans.queued + scans.running : '—'} sub={scans ? `${scans.queued} queued · ${scans.running} running` : ''} />
        <Stat icon={CircleCheck} label="Completed 24h" value={scans?.completed_24h ?? '—'} sub={scans?.avg_duration_s != null ? `avg ${scans.avg_duration_s}s` : ''} />
        <Stat icon={Users} label="Customers" value={users?.paid ?? '—'} sub={users ? `${users.total} total · ${users.new_7d} new (7d)` : ''} />
        <Stat icon={TrendingUp} label="MRR" value={billing ? `$${billing.mrr_usd.toLocaleString()}` : '—'} sub={billing ? `$${billing.arr_usd.toLocaleString()} ARR · ${billing.active_subscriptions} active` : ''} />
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

      <p className="text-[10px] pt-2" style={{ color: 'rgba(255,255,255,0.25)' }}>
        Phase 1 · Command Center. Scan ops, SOC alerting, customer mgmt, fraud/abuse,
        support, billing ops, log explorer & more are roadmapped in docs/INTERNAL_PLATFORM.md.
      </p>
    </div>
  )
}
