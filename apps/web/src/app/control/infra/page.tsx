'use client'

// Infrastructure Operations — time-series charts for queue depth, active
// scans, worker heartbeat age, and Redis memory. Backed by
// /internal/infra/history (the worker beat samples once every 5 min).

import { useCallback, useEffect, useState } from 'react'
import { Server, Loader2, Activity, Cpu, MemoryStick, Workflow } from 'lucide-react'
import {
  AreaChart, Area, LineChart, Line, XAxis, YAxis, ResponsiveContainer, Tooltip, CartesianGrid,
} from 'recharts'
import { api, type InfraSample, type CommandCenter } from '@/lib/api'

const LIME = '#8BFF3E'
const RANGES = [
  { hours: 6,   label: '6h' },
  { hours: 24,  label: '24h' },
  { hours: 72,  label: '3d' },
  { hours: 168, label: '7d' },
]

// Narrow the discriminated `infra` union to its "ok" branch (the error branch
// only has `error: string`). The cast is the standard escape hatch for
// discriminated unions whose members don't share a discriminant field.
type InfraOk = Extract<CommandCenter['infra'], { database: string }>
function asInfraOk(v: CommandCenter['infra'] | undefined): InfraOk | null {
  if (!v || 'error' in v) return null
  return v as InfraOk
}

function Stat({ icon: Icon, label, value, sub, color = LIME }: {
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  label: string; value: React.ReactNode; sub?: string; color?: string
}) {
  return (
    <div className="rounded-xl p-4"
         style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)' }}>
      <div className="flex items-center gap-2 mb-2">
        <Icon className="w-4 h-4" style={{ color }} />
        <span className="text-[11px] font-bold tracking-[0.1em] uppercase"
              style={{ color: 'rgba(255,255,255,0.4)' }}>{label}</span>
      </div>
      <div className="text-[22px] font-bold text-white leading-none">{value}</div>
      {sub && <div className="text-[11px] mt-1.5" style={{ color: 'rgba(255,255,255,0.4)' }}>{sub}</div>}
    </div>
  )
}

interface ChartPoint {
  t: number
  taken_at: string | null
  queue_depth: number | null
  active_scans: number | null
  worker_heartbeat_age_s: number | null
  redis_used_memory_mb: number | null
  worker_alive: number  // 0 | 1 for the worker uptime band
}

function ChartCard({ title, icon: Icon, children, color = LIME }: {
  title: string
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  children: React.ReactNode
  color?: string
}) {
  return (
    <div className="rounded-xl p-4"
         style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)' }}>
      <div className="flex items-center gap-2 mb-2">
        <Icon className="w-4 h-4" style={{ color }} />
        <span className="text-[12px] font-semibold text-white">{title}</span>
      </div>
      <ResponsiveContainer width="100%" height={180}>
        {children as React.ReactElement}
      </ResponsiveContainer>
    </div>
  )
}

const TIME_AXIS = {
  type: 'number' as const,
  domain: ['dataMin', 'dataMax'] as [string, string],
  tickFormatter: (v: number) => new Date(v).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  tick: { fill: 'rgba(255,255,255,0.4)', fontSize: 10 },
  axisLine: false,
  tickLine: false,
}
const Y_AXIS = {
  tick: { fill: 'rgba(255,255,255,0.4)', fontSize: 10 },
  axisLine: false,
  tickLine: false,
  width: 40,
}
const TOOLTIP_STYLE = {
  contentStyle: { background: '#0b0f17', border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: 8, fontSize: 12 } as React.CSSProperties,
  // Recharts types the label as ReactNode — at runtime it's our numeric `t`.
  labelFormatter: (v: React.ReactNode) =>
    typeof v === 'number' ? new Date(v).toLocaleString() : String(v ?? ''),
}

export default function InfraOpsPage() {
  const [hours, setHours] = useState(24)
  const [samples, setSamples] = useState<InfraSample[]>([])
  const [center, setCenter] = useState<CommandCenter | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    Promise.all([
      api.internal.infraHistory(hours).then(r => setSamples(r.items)).catch(() => setSamples([])),
      api.internal.commandCenter().then(setCenter).catch(() => {}),
    ]).finally(() => setLoading(false))
  }, [hours])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    const id = setInterval(load, 30000)
    return () => clearInterval(id)
  }, [load])

  const data: ChartPoint[] = samples
    .map(s => ({
      t: s.taken_at ? new Date(s.taken_at).getTime() : 0,
      taken_at: s.taken_at,
      queue_depth: s.queue_depth,
      active_scans: s.active_scans,
      worker_heartbeat_age_s: s.worker_heartbeat_age_s,
      redis_used_memory_mb: s.redis_used_memory_mb,
      worker_alive: s.worker_alive ? 1 : 0,
    }))
    .filter(p => p.t > 0)

  const infra = asInfraOk(center?.infra)
  const alivePct = data.length > 0
    ? Math.round(100 * data.filter(p => p.worker_alive).length / data.length)
    : null

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <Server className="w-5 h-5" style={{ color: LIME }} />
        <h1 className="text-[19px] font-bold text-white">Infrastructure Operations</h1>
        <span className="text-[12px] text-white/40">· {samples.length} samples</span>
        <div className="ml-auto flex items-center gap-1">
          {RANGES.map(r => (
            <button key={r.hours} onClick={() => setHours(r.hours)}
                    className="px-2.5 py-1 rounded text-[11px] font-semibold transition-colors"
                    style={hours === r.hours
                      ? { background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.25)' }
                      : { background: 'rgba(255,255,255,0.02)', color: 'rgba(255,255,255,0.55)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {r.label}
            </button>
          ))}
        </div>
      </div>

      {/* Current snapshot — matches Command Center semantics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat icon={Workflow} label="Queue depth"
              value={infra?.queue_depth != null ? String(infra.queue_depth) : '—'}
              sub={infra?.worker === 'ok' ? 'workers draining' : infra?.worker === 'stale' ? 'worker stale!' : ''} />
        <Stat icon={Activity} label="Active scans"
              value={data.length > 0 ? (data[data.length - 1].active_scans ?? '—') : '—'}
              sub="queued + running" />
        <Stat icon={Cpu} label="Worker uptime"
              value={alivePct != null ? `${alivePct}%` : '—'}
              sub={`over the last ${RANGES.find(r => r.hours === hours)?.label}`}
              color={alivePct != null && alivePct < 90 ? '#f59e0b' : LIME} />
        <Stat icon={MemoryStick} label="Redis memory"
              value={data.length > 0 && data[data.length - 1].redis_used_memory_mb != null
                ? `${data[data.length - 1].redis_used_memory_mb!.toFixed(1)} MB`
                : '—'}
              sub="server reported" />
      </div>

      {data.length === 0 ? (
        <div className="py-14 text-center text-[13px] text-white/35"
             style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12 }}>
          {loading ? <Loader2 className="w-4 h-4 animate-spin inline text-white/40" /> :
            'No infra samples yet — the worker beat writes one every 5 min.'}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <ChartCard title="Queue depth" icon={Workflow}>
            <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="qFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={LIME} stopOpacity={0.4} />
                  <stop offset="95%" stopColor={LIME} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="t" {...TIME_AXIS} />
              <YAxis {...Y_AXIS} />
              <Tooltip {...TOOLTIP_STYLE} />
              <Area type="monotone" dataKey="queue_depth" stroke={LIME} strokeWidth={1.5}
                    fill="url(#qFill)" isAnimationActive={false} />
            </AreaChart>
          </ChartCard>

          <ChartCard title="Active scans" icon={Activity} color="#3b82f6">
            <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="aFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="t" {...TIME_AXIS} />
              <YAxis {...Y_AXIS} />
              <Tooltip {...TOOLTIP_STYLE} />
              <Area type="monotone" dataKey="active_scans" stroke="#3b82f6" strokeWidth={1.5}
                    fill="url(#aFill)" isAnimationActive={false} />
            </AreaChart>
          </ChartCard>

          <ChartCard title="Redis memory (MB)" icon={MemoryStick} color="#a855f7">
            <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="t" {...TIME_AXIS} />
              <YAxis {...Y_AXIS} />
              <Tooltip {...TOOLTIP_STYLE} />
              <Line type="monotone" dataKey="redis_used_memory_mb" stroke="#a855f7"
                    strokeWidth={1.5} dot={false} isAnimationActive={false} />
            </LineChart>
          </ChartCard>

          <ChartCard title="Worker heartbeat age (s)" icon={Cpu} color="#f59e0b">
            <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="t" {...TIME_AXIS} />
              <YAxis {...Y_AXIS} />
              <Tooltip {...TOOLTIP_STYLE} />
              <Line type="monotone" dataKey="worker_heartbeat_age_s" stroke="#f59e0b"
                    strokeWidth={1.5} dot={false} isAnimationActive={false} />
            </LineChart>
          </ChartCard>
        </div>
      )}
    </div>
  )
}
