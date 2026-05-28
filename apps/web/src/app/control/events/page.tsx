'use client'

// Live SOC Event Stream — real-time feed of typed `Event` envelopes pushed
// through the layout's shared SSE subscription. Severity filter, kind
// filter, pause/replay. Ring buffer of the most recent N events.

import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Radio, Pause, Play, Trash2, Filter,
} from 'lucide-react'
import { useControlEvents } from '../layout'

const BUFFER_SIZE = 500
const LIME = '#8BFF3E'

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#f59e0b',
  low: '#3b82f6', info: '#8b94a6',
}
const SEV_RANK: Record<string, number> = {
  info: 0, low: 10, medium: 20, high: 30, critical: 40,
}
const SEVERITIES = ['', 'info', 'low', 'medium', 'high', 'critical']

// Friendly kind labels — keeps the table readable. Anything not listed shows
// the raw `domain.verb` code (which is already pretty).
const KIND_LABEL: Record<string, string> = {
  'scan.started': 'Scan started',
  'scan.completed': 'Scan completed',
  'scan.failed': 'Scan failed',
  'alert.opened': 'Alert opened',
  'alert.updated': 'Alert updated',
  'alert.ack': 'Alert acked',
  'alert.resolved': 'Alert resolved',
  'incident.opened': 'Incident opened',
  'incident.status': 'Incident status',
  'auth.login': 'Login',
  'auth.suspicious_login': 'Suspicious login',
  'customer.suspended': 'Customer suspended',
  'customer.reactivated': 'Customer reactivated',
  'customer.plan_changed': 'Plan changed',
  'billing.payment_failed': 'Payment failed',
  'billing.sub_changed': 'Subscription changed',
  'infra.worker_down': 'Worker down',
  'infra.worker_recovered': 'Worker recovered',
  'infra.queue_backup': 'Queue backup',
  'engine.degraded': 'Engine degraded',
  'engine.recovered': 'Engine recovered',
  'engine.maintenance': 'Engine maintenance',
  'abuse.flag_opened': 'Abuse flag',
  'abuse.user_banned': 'User banned',
  'ticket.opened': 'Ticket opened',
  'ticket.sla_breach': 'Ticket SLA breach',
  'deploy.recorded': 'Deploy recorded',
  'admin.action': 'Admin action',
}

interface EventRow {
  // Stable client-side id so the list keys stay sane across renders.
  rid: number
  kind: string
  severity: string
  source: string
  message: string
  target_type: string | null
  target_id: string | null
  detail: Record<string, unknown>
  actor_email: string | null
  at: string  // ISO from server; we render local time
}

function SevDot({ s }: { s: string }) {
  const c = SEV_COLOR[s] ?? '#8b94a6'
  return <span className="w-2 h-2 rounded-full shrink-0" style={{ background: c, boxShadow: `0 0 6px ${c}` }} />
}

export default function EventStreamPage() {
  const { live, subscribe } = useControlEvents()
  const [paused, setPaused] = useState(false)
  const [minSeverity, setMinSeverity] = useState('')
  const [kindFilter, setKindFilter] = useState('')
  const [events, setEvents] = useState<EventRow[]>([])
  const [expanded, setExpanded] = useState<number | null>(null)

  // Buffer events through a ref so the pause toggle decides whether they
  // land in the visible state — otherwise pausing would only freeze the
  // *visible* list, and new events would still pile up in state silently.
  const idCounter = useRef(0)
  const pausedRef = useRef(paused)
  pausedRef.current = paused

  useEffect(() => subscribe((raw) => {
    if (pausedRef.current) return
    // Accept the typed envelope shape from apps/api/telemetry.py — anything
    // missing fields gets sensible defaults so legacy alert pings still show.
    const r = raw as Record<string, unknown>
    const ev: EventRow = {
      rid: ++idCounter.current,
      kind: typeof r.kind === 'string' ? r.kind : (typeof r.type === 'string' ? `legacy.${r.type}` : 'unknown'),
      severity: typeof r.severity === 'string' ? r.severity : 'info',
      source: typeof r.source === 'string' ? r.source : 'platform',
      message: typeof r.message === 'string' ? r.message : '',
      target_type: typeof r.target_type === 'string' ? r.target_type : null,
      target_id: typeof r.target_id === 'string' ? r.target_id : null,
      detail: (r.detail && typeof r.detail === 'object') ? r.detail as Record<string, unknown> : {},
      actor_email: typeof r.actor_email === 'string' ? r.actor_email : null,
      at: typeof r.at === 'string' ? r.at : new Date().toISOString(),
    }
    setEvents(prev => {
      const next = [ev, ...prev]
      return next.length > BUFFER_SIZE ? next.slice(0, BUFFER_SIZE) : next
    })
  }), [subscribe])

  const visible = events.filter(e => {
    if (kindFilter && e.kind !== kindFilter) return false
    if (minSeverity && (SEV_RANK[e.severity] ?? 0) < (SEV_RANK[minSeverity] ?? 0)) return false
    return true
  })

  // Unique kinds seen so far — populates the kind filter without us having
  // to enumerate every event kind ahead of time.
  const kindsSeen = Array.from(new Set(events.map(e => e.kind))).sort()

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Radio className="w-5 h-5" style={{ color: live ? LIME : 'rgba(255,255,255,0.4)' }} />
        <h1 className="text-[19px] font-bold text-white">Live Event Stream</h1>
        <span className="flex items-center gap-1.5 text-[10px] font-semibold tracking-[0.14em] uppercase">
          <span className="relative inline-flex w-1.5 h-1.5">
            {live && !paused && <span className="absolute inset-0 rounded-full animate-ping"
                                       style={{ background: LIME, opacity: 0.55 }} />}
            <span className="relative w-1.5 h-1.5 rounded-full"
                  style={{ background: paused ? '#f59e0b' : live ? LIME : '#ef4444',
                           boxShadow: `0 0 6px ${paused ? '#f59e0b' : live ? LIME : '#ef4444'}` }} />
          </span>
          <span style={{ color: paused ? '#f59e0b' : live ? LIME : '#ef4444' }}>
            {paused ? 'Paused' : live ? 'Streaming' : 'Disconnected'}
          </span>
        </span>
        <span className="text-[12px] text-white/40 ml-2">
          · {visible.length}{events.length !== visible.length ? ` / ${events.length}` : ''} events
          {events.length === BUFFER_SIZE && <span className="text-white/30"> · buffer full</span>}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button onClick={() => setPaused(p => !p)}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold"
                style={paused
                  ? { background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.3)' }
                  : { background: 'rgba(245,158,11,0.1)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.3)' }}>
          {paused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
          {paused ? 'Resume' : 'Pause'}
        </button>
        <button onClick={() => { setEvents([]); setExpanded(null) }}
                disabled={events.length === 0}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold disabled:opacity-40"
                style={{ background: 'rgba(255,255,255,0.03)', color: 'rgba(255,255,255,0.7)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <Trash2 className="w-3 h-3" /> Clear
        </button>
        <div className="flex items-center gap-1.5 ml-2">
          <Filter className="w-3 h-3 text-white/40" />
          <select value={minSeverity} onChange={e => setMinSeverity(e.target.value)}
                  className="px-2.5 py-1 rounded text-[11px] text-white/80 outline-none"
                  style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <option value="" className="bg-[#0b0f17]">all severities</option>
            {SEVERITIES.filter(s => s).map(s => <option key={s} value={s} className="bg-[#0b0f17]">≥ {s}</option>)}
          </select>
          <select value={kindFilter} onChange={e => setKindFilter(e.target.value)}
                  className="px-2.5 py-1 rounded text-[11px] text-white/80 outline-none"
                  style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <option value="" className="bg-[#0b0f17]">all kinds</option>
            {kindsSeen.map(k => <option key={k} value={k} className="bg-[#0b0f17]">{k}</option>)}
          </select>
        </div>
      </div>

      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
        {events.length === 0 ? (
          <div className="py-14 text-center text-[13px] text-white/35">
            Waiting for events… {live ? 'stream connected, idle.' : 'stream offline — reconnecting.'}
          </div>
        ) : visible.length === 0 ? (
          <div className="py-14 text-center text-[13px] text-white/35">
            No events match the filters ({events.length} buffered).
          </div>
        ) : (
          <div className="divide-y divide-white/[0.04]">
            {visible.map(e => {
              const open = expanded === e.rid
              const hasDetail = Object.keys(e.detail ?? {}).length > 0
              return (
                <div key={e.rid}
                     className="px-3 py-2 cursor-pointer hover:bg-white/[0.02]"
                     onClick={() => hasDetail && setExpanded(open ? null : e.rid)}>
                  <div className="flex items-center gap-2 text-[12px]">
                    <SevDot s={e.severity} />
                    <span className="text-white/45 font-mono w-[110px] shrink-0">
                      {new Date(e.at).toLocaleTimeString()}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded uppercase tracking-wider"
                          style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.65)' }}>
                      {e.kind}
                    </span>
                    <span className="text-white/80 truncate flex-1">{e.message || KIND_LABEL[e.kind] || e.kind}</span>
                    {e.target_type && (
                      <span className="text-[10px] font-mono text-white/35 truncate max-w-[200px]">
                        {e.target_type}{e.target_id ? `:${e.target_id.slice(0, 10)}` : ''}
                      </span>
                    )}
                    {e.actor_email && (
                      <span className="text-[10px] text-white/45 max-w-[160px] truncate">{e.actor_email}</span>
                    )}
                  </div>
                  {open && hasDetail && (
                    <pre className="ml-6 mt-1 text-[11px] rounded p-2 overflow-auto font-mono"
                         style={{ background: 'rgba(255,255,255,0.02)', color: 'rgba(255,255,255,0.65)' }}>
                      {JSON.stringify(e.detail, null, 2)}
                    </pre>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
