'use client'

// SOC Incidents — correlated grouping of alerts that staff actually work on.
// Statuses: open → acknowledged → investigating → mitigated → resolved.
// Suppressed is the terminal "false positive" state.

import { useCallback, useEffect, useState } from 'react'
import {
  Siren, X, Loader2, AlertTriangle, Clock, MessageSquare, Activity, Timer,
} from 'lucide-react'
import { api, type IncidentRow, type IncidentDetail } from '@/lib/api'
import { useInternalMe, useControlEvents } from '../layout'

const LIME = '#8BFF3E'
const ROLE_RANK: Record<string, number> = {
  none: 0, read_only: 10, billing: 20, support: 20, developer: 20,
  analyst: 30, admin: 90, super_admin: 100,
}

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#f59e0b',
  low: '#3b82f6', info: '#8b94a6',
}
const STATUS_COLOR: Record<string, string> = {
  open: '#ef4444',
  acknowledged: '#f59e0b',
  investigating: '#3b82f6',
  mitigated: '#a3e635',
  resolved: '#8BFF3E',
  suppressed: 'rgba(255,255,255,0.4)',
}

const STATUSES = ['', 'open', 'acknowledged', 'investigating', 'mitigated', 'resolved', 'suppressed']
const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info']
const NEXT_STATUS_OPTIONS = ['open', 'acknowledged', 'investigating', 'mitigated', 'resolved', 'suppressed']

function SevDot({ sev }: { sev: string }) {
  const c = SEV_COLOR[sev] ?? '#8b94a6'
  return <span className="w-2 h-2 rounded-full shrink-0" style={{ background: c, boxShadow: `0 0 6px ${c}` }} />
}

function StatusBadge({ status }: { status: string }) {
  const c = STATUS_COLOR[status] ?? 'rgba(255,255,255,0.5)'
  return (
    <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded capitalize"
          style={{ background: `${c}1a`, color: c, border: `1px solid ${c}33` }}>
      {status.replace('_', ' ')}
    </span>
  )
}

function SLAPill({ incident }: { incident: IncidentRow }) {
  if (!incident.sla_due_at || incident.status === 'resolved' || incident.status === 'suppressed') {
    return null
  }
  const due = new Date(incident.sla_due_at)
  const ms = due.getTime() - Date.now()
  if (incident.breached) {
    const hrs = Math.round(-ms / 3_600_000)
    return (
      <span className="flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded"
            style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)' }}>
        <AlertTriangle className="w-2.5 h-2.5" /> {hrs}h late
      </span>
    )
  }
  const hrs = Math.max(0, Math.round(ms / 3_600_000))
  const warn = hrs <= 1
  return (
    <span className="flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded"
          style={{ background: 'rgba(255,255,255,0.04)',
                   color: warn ? '#f59e0b' : 'rgba(255,255,255,0.5)',
                   border: `1px solid ${warn ? 'rgba(245,158,11,0.3)' : 'rgba(255,255,255,0.08)'}` }}>
      <Clock className="w-2.5 h-2.5" /> {hrs}h SLA
    </span>
  )
}

function formatMttr(seconds: number | null): string | null {
  if (seconds == null) return null
  if (seconds < 60) return `${seconds}s`
  const m = Math.round(seconds / 60)
  if (m < 60) return `${m}m`
  const h = (seconds / 3600).toFixed(1)
  return `${h}h`
}

function Drawer({ id, onClose, canOperate, onChanged }: {
  id: string; onClose: () => void; canOperate: boolean; onChanged: () => void
}) {
  const [d, setD] = useState<IncidentDetail | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [note, setNote] = useState('')

  const load = useCallback(() => {
    api.internal.incidentDetail(id).then(setD).catch(() => {})
  }, [id])
  useEffect(() => { load() }, [load])

  const act = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(label); try { await fn(); load(); onChanged() } finally { setBusy(null) }
  }

  if (!d) {
    return (
      <div className="fixed inset-0 z-50 flex justify-end" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
        <div className="w-full max-w-[640px] h-full p-6 bg-[#070b13] border-l border-white/[0.08] flex items-center gap-2 text-[12px] text-white/50">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading incident…
        </div>
      </div>
    )
  }

  const mttr = formatMttr(d.mttr_seconds)

  return (
    <div className="fixed inset-0 z-50 flex justify-end" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="w-full max-w-[640px] h-full overflow-auto p-6 bg-[#070b13] border-l border-white/[0.08]"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-start gap-2.5">
            <div className="mt-1.5"><SevDot sev={d.severity} /></div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-[11px] px-1.5 py-0.5 rounded"
                      style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.55)' }}>
                  INC-{String(d.number).padStart(4, '0')}
                </span>
                <StatusBadge status={d.status} />
                <SLAPill incident={d} />
              </div>
              <h2 className="text-[15px] font-bold text-white mt-1.5">{d.title}</h2>
              <p className="text-[11px] mt-0.5" style={{ color: 'rgba(255,255,255,0.4)' }}>
                {d.source} · {d.alert_count} alert{d.alert_count !== 1 ? 's' : ''} · opened {d.first_seen_at ? new Date(d.first_seen_at).toLocaleString() : '—'}
                {d.assignee_email && <> · assignee {d.assignee_email}</>}
                {mttr && <> · MTTR {mttr}</>}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-white/5 shrink-0"><X className="w-4 h-4 text-white/60" /></button>
        </div>

        {/* Action bar */}
        {canOperate && (
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <select value={d.status}
                    disabled={busy !== null}
                    onChange={e => act('status', () => api.internal.setIncidentStatus(id, e.target.value))}
                    className="px-2.5 py-1 rounded text-[11px] text-white/85 outline-none"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {NEXT_STATUS_OPTIONS.map(s => (
                <option key={s} value={s} className="bg-[#0b0f17]">status → {s.replace('_', ' ')}</option>
              ))}
            </select>
            {d.resolved_at && (
              <span className="flex items-center gap-1 text-[11px]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                <Timer className="w-3 h-3" /> resolved {new Date(d.resolved_at).toLocaleString()} by {d.resolved_by ?? 'staff'}
              </span>
            )}
            {d.acknowledged_at && !d.resolved_at && (
              <span className="text-[11px]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                ack&apos;d {new Date(d.acknowledged_at).toLocaleString()} by {d.acknowledged_by ?? 'staff'}
              </span>
            )}
          </div>
        )}

        {/* Detail / target context */}
        {(d.target_type || Object.keys(d.detail ?? {}).length > 0) && (
          <div className="rounded-lg p-3 mb-4 space-y-2"
               style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
            {d.target_type && (
              <div className="text-[11px]" style={{ color: 'rgba(255,255,255,0.6)' }}>
                Target: <span className="font-mono text-white/80">{d.target_type}{d.target_id ? `:${d.target_id.slice(0, 12)}` : ''}</span>
              </div>
            )}
            {Object.keys(d.detail ?? {}).length > 0 && (
              <pre className="text-[11px] font-mono overflow-auto"
                   style={{ color: 'rgba(255,255,255,0.6)' }}>
                {JSON.stringify(d.detail, null, 2)}
              </pre>
            )}
          </div>
        )}

        {/* Timeline */}
        <div className="flex items-center gap-2 text-[12px] font-semibold text-white mb-2">
          <Activity className="w-3.5 h-3.5 text-white/50" /> Timeline ({d.events.length})
        </div>
        <div className="space-y-2 mb-4">
          {d.events.length === 0 ? (
            <p className="text-[12px] text-white/35">No timeline entries.</p>
          ) : d.events.map(e => {
            const isStatus = e.kind === 'status_change'
            const isAlert = e.kind.startsWith('alert_')
            const tone = e.kind === 'note' ? LIME
              : isStatus ? '#3b82f6'
              : isAlert ? '#f59e0b'
              : 'rgba(255,255,255,0.2)'
            return (
              <div key={e.id} className="text-[12px] flex gap-2">
                <span className="w-1 rounded-full shrink-0 mt-1 mb-1" style={{ background: tone }} />
                <div className="flex-1 min-w-0">
                  <div className="text-white/85 whitespace-pre-wrap break-words">{e.body}</div>
                  <div className="text-[10px] text-white/35 flex items-center gap-1.5 mt-0.5">
                    <span className="font-mono uppercase">{e.kind}</span>
                    <span>· {e.author ?? 'system'}</span>
                    <span>· {e.at ? new Date(e.at).toLocaleString() : ''}</span>
                  </div>
                </div>
              </div>
            )
          })}
        </div>

        {/* Note composer */}
        {canOperate && d.status !== 'resolved' && d.status !== 'suppressed' && (
          <div className="space-y-2">
            <textarea value={note} onChange={e => setNote(e.target.value)}
                      placeholder="Investigation note…"
                      rows={2}
                      className="w-full px-3 py-2 rounded-lg bg-transparent outline-none text-[12px] text-white/90 placeholder:text-white/30 resize-y"
                      style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
            <div className="flex justify-end">
              <button disabled={!note.trim() || busy !== null}
                      onClick={() => act('note', async () => { await api.internal.incidentNote(id, note.trim()); setNote('') })}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                      style={{ background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.3)' }}>
                <MessageSquare className="w-3 h-3" /> Add note
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function IncidentsPage() {
  const me = useInternalMe()
  const { subscribe } = useControlEvents()
  const canOperate = (ROLE_RANK[me?.role ?? 'none'] ?? 0) >= ROLE_RANK.analyst

  const [rows, setRows] = useState<IncidentRow[]>([])
  const [total, setTotal] = useState(0)
  const [status, setStatus] = useState('open')
  const [severity, setSeverity] = useState('')
  const [breachedOnly, setBreachedOnly] = useState(false)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<string | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    api.internal.incidents({
      status: status || undefined,
      severity: severity || undefined,
      breached_only: breachedOnly,
      limit: 100,
    }).then(r => { setRows(r.items); setTotal(r.total) })
      .finally(() => setLoading(false))
  }, [status, severity, breachedOnly])

  useEffect(() => { load() }, [load])
  useEffect(() => subscribe(() => load()), [subscribe, load])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Siren className="w-5 h-5" style={{ color: '#ef4444' }} />
        <h1 className="text-[19px] font-bold text-white">Incidents</h1>
        <span className="text-[12px] text-white/40">· {total.toLocaleString()} match</span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <select value={status} onChange={e => setStatus(e.target.value)}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {STATUSES.map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s ? s.replace('_', ' ') : 'all statuses'}</option>)}
        </select>
        <select value={severity} onChange={e => setSeverity(e.target.value)}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {SEVERITIES.map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s || 'all severities'}</option>)}
        </select>
        <label className="flex items-center gap-1.5 text-[12px] text-white/65 cursor-pointer">
          <input type="checkbox" checked={breachedOnly} onChange={e => setBreachedOnly(e.target.checked)} />
          SLA breached only
        </label>
      </div>

      <div className="space-y-1.5">
        {loading && rows.length === 0 ? (
          <div className="py-10 text-center"><Loader2 className="w-4 h-4 animate-spin inline text-white/40" /></div>
        ) : rows.length === 0 ? (
          <div className="py-10 text-center text-[13px] text-white/35">
            {status === 'open' ? 'No active incidents — quiet shift. ✅' : 'No incidents match these filters.'}
          </div>
        ) : rows.map(i => (
          <div key={i.id} onClick={() => setSelected(i.id)}
               className="flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer hover:bg-white/[0.025] transition-colors"
               style={{ background: 'rgba(255,255,255,0.015)', border: '1px solid rgba(255,255,255,0.06)' }}>
            <SevDot sev={i.severity} />
            <span className="font-mono text-[10px] text-white/40 w-16 shrink-0">INC-{String(i.number).padStart(4, '0')}</span>
            <div className="min-w-0 flex-1">
              <div className="text-[13px] text-white/90 truncate">{i.title}</div>
              <div className="text-[11px] text-white/40">
                {i.source} · {i.alert_count} alert{i.alert_count !== 1 ? 's' : ''}
                {i.last_seen_at ? ` · last ${new Date(i.last_seen_at).toLocaleString()}` : ''}
              </div>
            </div>
            <SLAPill incident={i} />
            <StatusBadge status={i.status} />
          </div>
        ))}
      </div>

      {selected && <Drawer id={selected} onClose={() => setSelected(null)} canOperate={canOperate} onChanged={load} />}
    </div>
  )
}
