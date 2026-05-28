'use client'

// SOC Alerts — live alert queue with triage (ack/resolve/assign/comment).

import { useCallback, useEffect, useState } from 'react'
import {
  BellRing, X, Check, CircleCheck, Loader2, MessageSquare, Clock,
} from 'lucide-react'
import { api, type AlertRow, type AlertDetail } from '@/lib/api'
import { useInternalMe, useControlEvents } from '../layout'

const ROLE_RANK: Record<string, number> = {
  none: 0, read_only: 10, billing: 20, support: 20, developer: 20,
  analyst: 30, admin: 90, super_admin: 100,
}

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6', info: '#8b94a6',
}
const STATUS_COLOR: Record<string, string> = {
  open: '#ef4444', acknowledged: '#f59e0b', resolved: '#8BFF3E', suppressed: 'rgba(255,255,255,0.4)',
}
const STATUSES = ['', 'open', 'acknowledged', 'resolved']
const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info']

function SevDot({ sev }: { sev: string }) {
  const c = SEV_COLOR[sev] ?? '#8b94a6'
  return <span className="w-2 h-2 rounded-full shrink-0" style={{ background: c, boxShadow: `0 0 6px ${c}` }} />
}

function StatusBadge({ status }: { status: string }) {
  const c = STATUS_COLOR[status] ?? 'rgba(255,255,255,0.5)'
  return (
    <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded capitalize"
          style={{ background: `${c}1a`, color: c, border: `1px solid ${c}33` }}>{status}</span>
  )
}

function Drawer({ id, onClose, canOperate, onChanged }: {
  id: string; onClose: () => void; canOperate: boolean; onChanged: () => void
}) {
  const [d, setD] = useState<AlertDetail | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [comment, setComment] = useState('')

  const load = useCallback(() => { api.internal.alertDetail(id).then(setD).catch(() => {}) }, [id])
  useEffect(() => { load() }, [load])

  const act = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(label)
    try { await fn(); load(); onChanged() } finally { setBusy(null) }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="w-full max-w-[560px] h-full overflow-auto p-6 bg-[#070b13] border-l border-white/[0.08]"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-start gap-2">
            {d && <div className="mt-1.5"><SevDot sev={d.severity} /></div>}
            <div>
              <h2 className="text-[15px] font-bold text-white leading-snug">{d?.title ?? 'Loading…'}</h2>
              {d && <p className="text-[11px] mt-0.5" style={{ color: 'rgba(255,255,255,0.4)' }}>
                {d.source} · seen {d.occurrences}× · last {d.last_seen_at ? new Date(d.last_seen_at).toLocaleString() : '—'}
              </p>}
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-white/5"><X className="w-4 h-4 text-white/60" /></button>
        </div>

        {!d ? (
          <div className="flex items-center gap-2 text-[12px] text-white/50"><Loader2 className="w-4 h-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            <div className="flex items-center gap-2 mb-3">
              <StatusBadge status={d.status} />
              {d.acknowledged_by && <span className="text-[11px] text-white/45">ack {d.acknowledged_by}</span>}
              {d.resolved_by && <span className="text-[11px] text-white/45">resolved {d.resolved_by}</span>}
            </div>

            {d.description && (
              <p className="text-[13px] text-white/75 mb-3 leading-relaxed">{d.description}</p>
            )}

            {Object.keys(d.detail ?? {}).length > 0 && (
              <pre className="text-[11px] rounded-lg p-2.5 mb-4 overflow-auto font-mono"
                   style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.6)' }}>
                {JSON.stringify(d.detail, null, 2)}
              </pre>
            )}

            {canOperate && d.status !== 'resolved' && (
              <div className="flex items-center gap-2 mb-5">
                {d.status === 'open' && (
                  <button disabled={busy !== null} onClick={() => act('ack', () => api.internal.ackAlert(id))}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                          style={{ background: 'rgba(245,158,11,0.1)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.3)' }}>
                    {busy === 'ack' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />} Acknowledge
                  </button>
                )}
                <button disabled={busy !== null} onClick={() => act('resolve', () => api.internal.resolveAlert(id))}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                        style={{ background: 'rgba(139,255,62,0.1)', color: '#8BFF3E', border: '1px solid rgba(139,255,62,0.3)' }}>
                  {busy === 'resolve' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CircleCheck className="w-3.5 h-3.5" />} Resolve
                </button>
              </div>
            )}

            {/* Timeline */}
            <div className="flex items-center gap-2 text-[12px] font-semibold text-white mb-2">
              <Clock className="w-3.5 h-3.5 text-white/50" /> Timeline
            </div>
            <div className="space-y-2 mb-4">
              {d.comments.length === 0 ? (
                <p className="text-[12px] text-white/35">No timeline entries yet.</p>
              ) : d.comments.map(c => (
                <div key={c.id} className="text-[12px] flex gap-2">
                  <span className="w-1 rounded-full shrink-0 mt-1 mb-1"
                        style={{ background: c.kind === 'comment' ? '#8BFF3E' : 'rgba(255,255,255,0.2)' }} />
                  <div className="flex-1">
                    <div className="text-white/80">{c.body}</div>
                    <div className="text-[10px] text-white/35">
                      {c.author ?? 'system'} · {c.at ? new Date(c.at).toLocaleString() : ''}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {canOperate && (
              <div className="flex items-center gap-2">
                <input value={comment} onChange={e => setComment(e.target.value)}
                       placeholder="Add a note…"
                       onKeyDown={e => { if (e.key === 'Enter' && comment.trim()) act('comment', async () => { await api.internal.commentAlert(id, comment.trim()); setComment('') }) }}
                       className="flex-1 px-3 py-1.5 rounded-lg bg-transparent outline-none text-[12px] text-white/90 placeholder:text-white/30"
                       style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
                <button disabled={!comment.trim() || busy !== null}
                        onClick={() => act('comment', async () => { await api.internal.commentAlert(id, comment.trim()); setComment('') })}
                        className="p-2 rounded-lg disabled:opacity-40"
                        style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
                  <MessageSquare className="w-3.5 h-3.5 text-white/70" />
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

export default function AlertsPage() {
  const me = useInternalMe()
  const { subscribe } = useControlEvents()
  const canOperate = (ROLE_RANK[me?.role ?? 'none'] ?? 0) >= ROLE_RANK.analyst

  const [rows, setRows] = useState<AlertRow[]>([])
  const [total, setTotal] = useState(0)
  const [status, setStatus] = useState('open')
  const [severity, setSeverity] = useState('')
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<string | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    api.internal.alerts({ status: status || undefined, severity: severity || undefined, limit: 100 })
      .then(r => { setRows(r.items); setTotal(r.total) })
      .finally(() => setLoading(false))
  }, [status, severity])

  useEffect(() => { load() }, [load])
  // Live: refresh on any SOC event pushed through the shared SSE stream.
  useEffect(() => subscribe(() => load()), [subscribe, load])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <BellRing className="w-5 h-5" style={{ color: '#8BFF3E' }} />
        <h1 className="text-[19px] font-bold text-white">SOC Alerts</h1>
        <span className="text-[12px] text-white/40">· {total.toLocaleString()} match</span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <select value={status} onChange={e => setStatus(e.target.value)}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {STATUSES.map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s || 'all statuses'}</option>)}
        </select>
        <select value={severity} onChange={e => setSeverity(e.target.value)}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {SEVERITIES.map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s || 'all severities'}</option>)}
        </select>
      </div>

      <div className="space-y-1.5">
        {loading && rows.length === 0 ? (
          <div className="py-10 text-center"><Loader2 className="w-4 h-4 animate-spin inline text-white/40" /></div>
        ) : rows.length === 0 ? (
          <div className="py-10 text-center text-[13px] text-white/35">
            {status === 'open' ? 'No open alerts — all clear. ✅' : 'No alerts match these filters.'}
          </div>
        ) : rows.map(a => (
          <div key={a.id} onClick={() => setSelected(a.id)}
               className="flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer transition-colors hover:bg-white/[0.025]"
               style={{ background: 'rgba(255,255,255,0.015)', border: '1px solid rgba(255,255,255,0.06)' }}>
            <SevDot sev={a.severity} />
            <div className="min-w-0 flex-1">
              <div className="text-[13px] text-white/90 truncate">{a.title}</div>
              <div className="text-[11px] text-white/40">
                {a.source}{a.occurrences > 1 ? ` · ${a.occurrences}×` : ''}
                {a.last_seen_at ? ` · ${new Date(a.last_seen_at).toLocaleString()}` : ''}
              </div>
            </div>
            {a.assignee_id && <span className="text-[10px] text-white/40">assigned</span>}
            <StatusBadge status={a.status} />
          </div>
        ))}
      </div>

      {selected && (
        <Drawer id={selected} onClose={() => setSelected(null)} canOperate={canOperate} onChanged={load} />
      )}
    </div>
  )
}
