'use client'

// Support / Fix Service — ticket queue + triage drawer (timeline, status,
// priority, assignment, verification rescan). SLA breach gets a red badge.

import { useCallback, useEffect, useState } from 'react'
import {
  Ticket, X, Loader2, Plus, Clock, AlertTriangle, MessageSquare, RotateCw, Activity,
} from 'lucide-react'
import { api, type TicketRow, type TicketDetail } from '@/lib/api'
import { useInternalMe, useControlEvents } from '../layout'

const ROLE_RANK: Record<string, number> = {
  none: 0, read_only: 10, billing: 20, support: 20, developer: 20,
  analyst: 30, admin: 90, super_admin: 100,
}

const STATUS_COLOR: Record<string, string> = {
  open: '#3b82f6', in_progress: '#f59e0b', awaiting_customer: '#a855f7',
  resolved: '#8BFF3E', closed: 'rgba(255,255,255,0.4)',
}
const PRIORITY_COLOR: Record<string, string> = {
  urgent: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6',
}
const STATUSES = ['', 'open', 'in_progress', 'awaiting_customer', 'resolved', 'closed']
const PRIORITIES = ['', 'urgent', 'high', 'medium', 'low']
const CATEGORIES = ['remediation', 'question', 'bug', 'billing'] as const

function PriorityDot({ p }: { p: string }) {
  const c = PRIORITY_COLOR[p] ?? 'rgba(255,255,255,0.4)'
  return <span className="w-2 h-2 rounded-full shrink-0" style={{ background: c, boxShadow: `0 0 6px ${c}` }} />
}

function StatusBadge({ status }: { status: string }) {
  const c = STATUS_COLOR[status] ?? 'rgba(255,255,255,0.5)'
  return (
    <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
          style={{ background: `${c}1a`, color: c, border: `1px solid ${c}33` }}>{status.replace('_', ' ')}</span>
  )
}

function SLAPill({ t }: { t: TicketRow }) {
  if (!t.sla_due_at) return null
  const due = new Date(t.sla_due_at)
  const ms = due.getTime() - Date.now()
  if (t.breached) {
    const hrs = Math.round(-ms / 3_600_000)
    return (
      <span className="flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded"
            style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)' }}>
        <AlertTriangle className="w-2.5 h-2.5" /> {hrs}h late
      </span>
    )
  }
  const hrs = Math.round(ms / 3_600_000)
  const warn = hrs <= 4
  return (
    <span className="flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded"
          style={{ background: 'rgba(255,255,255,0.04)',
                   color: warn ? '#f59e0b' : 'rgba(255,255,255,0.5)',
                   border: `1px solid ${warn ? 'rgba(245,158,11,0.3)' : 'rgba(255,255,255,0.08)'}` }}>
      <Clock className="w-2.5 h-2.5" /> {hrs}h
    </span>
  )
}

function NewTicketDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [subject, setSubject] = useState('')
  const [description, setDescription] = useState('')
  const [userId, setUserId] = useState('')
  const [category, setCategory] = useState('remediation')
  const [priority, setPriority] = useState('medium')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const submit = async () => {
    if (!subject.trim()) return
    setBusy(true); setErr(null)
    try {
      await api.internal.createTicket({
        user_id: userId || null,
        subject: subject.trim(),
        description: description.trim() || null,
        category, priority,
      })
      onCreated(); onClose()
    } catch (e) { setErr((e as Error).message || 'Failed to create') }
    finally { setBusy(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="w-full max-w-[480px] rounded-xl p-5 bg-[#070b13] border border-white/10"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-[14px] font-bold text-white">New ticket</h3>
          <button onClick={onClose} className="p-1 rounded hover:bg-white/5"><X className="w-4 h-4 text-white/60" /></button>
        </div>
        <div className="space-y-2.5">
          <input value={subject} onChange={e => setSubject(e.target.value)} placeholder="Subject"
                 className="w-full px-3 py-2 rounded-lg bg-transparent outline-none text-[13px] text-white/90 placeholder:text-white/30"
                 style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
          <textarea value={description} onChange={e => setDescription(e.target.value)} placeholder="Description (optional)"
                    rows={3}
                    className="w-full px-3 py-2 rounded-lg bg-transparent outline-none text-[12px] text-white/85 placeholder:text-white/30 resize-y"
                    style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
          <input value={userId} onChange={e => setUserId(e.target.value)} placeholder="Customer user_id (optional)"
                 className="w-full px-3 py-2 rounded-lg bg-transparent outline-none text-[12px] text-white/80 placeholder:text-white/25 font-mono"
                 style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
          <div className="grid grid-cols-2 gap-2">
            <select value={category} onChange={e => setCategory(e.target.value)}
                    className="px-3 py-2 rounded-lg text-[12px] text-white/80 outline-none"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {CATEGORIES.map(c => <option key={c} value={c} className="bg-[#0b0f17]">{c}</option>)}
            </select>
            <select value={priority} onChange={e => setPriority(e.target.value)}
                    className="px-3 py-2 rounded-lg text-[12px] text-white/80 outline-none"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {['urgent', 'high', 'medium', 'low'].map(p => <option key={p} value={p} className="bg-[#0b0f17]">{p}</option>)}
            </select>
          </div>
          {err && <div className="text-[11px] text-red-400">{err}</div>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose} className="px-3 py-1.5 rounded-lg text-[12px] text-white/65"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>Cancel</button>
            <button disabled={!subject.trim() || busy} onClick={submit}
                    className="px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                    style={{ background: 'rgba(139,255,62,0.1)', color: '#8BFF3E', border: '1px solid rgba(139,255,62,0.3)' }}>
              {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Create'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function Drawer({ id, onClose, canOperate, onChanged }: {
  id: string; onClose: () => void; canOperate: boolean; onChanged: () => void
}) {
  const [t, setT] = useState<TicketDetail | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [comment, setComment] = useState('')
  const [visibility, setVisibility] = useState<'public' | 'internal'>('public')

  const load = useCallback(() => { api.internal.ticketDetail(id).then(setT).catch(() => {}) }, [id])
  useEffect(() => { load() }, [load])

  const act = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(label); try { await fn(); load(); onChanged() } finally { setBusy(null) }
  }

  if (!t) {
    return (
      <div className="fixed inset-0 z-50 flex justify-end" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
        <div className="w-full max-w-[640px] h-full p-6 bg-[#070b13] border-l border-white/[0.08] flex items-center gap-2 text-[12px] text-white/50">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading…
        </div>
      </div>
    )
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="w-full max-w-[640px] h-full overflow-auto p-6 bg-[#070b13] border-l border-white/[0.08]"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-start gap-2.5">
            <div className="mt-1.5"><PriorityDot p={t.priority} /></div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-[11px] px-1.5 py-0.5 rounded"
                      style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.55)' }}>WH-{String(t.number).padStart(4, '0')}</span>
                <StatusBadge status={t.status} />
                <SLAPill t={t} />
              </div>
              <h2 className="text-[15px] font-bold text-white mt-1.5">{t.subject}</h2>
              <p className="text-[11px] mt-0.5" style={{ color: 'rgba(255,255,255,0.4)' }}>
                {t.user_email ?? '—'} · category {t.category} · priority {t.priority} · opened {t.opened_at ? new Date(t.opened_at).toLocaleString() : '—'}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-white/5"><X className="w-4 h-4 text-white/60" /></button>
        </div>

        {t.description && (
          <div className="rounded-lg p-2.5 mb-4 text-[13px] text-white/80 whitespace-pre-wrap"
               style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
            {t.description}
          </div>
        )}

        {canOperate && (
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <select value={t.status} disabled={busy !== null}
                    onChange={e => act('status', () => api.internal.setTicketStatus(id, e.target.value))}
                    className="px-2.5 py-1 rounded text-[11px] text-white/80 outline-none"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {['open', 'in_progress', 'awaiting_customer', 'resolved', 'closed'].map(s =>
                <option key={s} value={s} className="bg-[#0b0f17]">status → {s.replace('_', ' ')}</option>)}
            </select>
            <select value={t.priority} disabled={busy !== null}
                    onChange={e => act('priority', () => api.internal.setTicketPriority(id, e.target.value))}
                    className="px-2.5 py-1 rounded text-[11px] text-white/80 outline-none"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {['urgent', 'high', 'medium', 'low'].map(p =>
                <option key={p} value={p} className="bg-[#0b0f17]">priority → {p}</option>)}
            </select>
            {t.source_scan_id && (
              <button disabled={busy !== null}
                      onClick={() => act('rescan', () => api.internal.ticketVerifyRescan(id))}
                      className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold disabled:opacity-40"
                      style={{ background: 'rgba(139,255,62,0.1)', color: '#8BFF3E', border: '1px solid rgba(139,255,62,0.3)' }}>
                {busy === 'rescan' ? <Loader2 className="w-3 h-3 animate-spin" /> : <RotateCw className="w-3 h-3" />} Verify rescan
              </button>
            )}
            {t.verification_scan_id && (
              <span className="flex items-center gap-1 text-[10px] text-white/45">
                <Activity className="w-3 h-3" /> verified: <span className="font-mono">{t.verification_scan_id.slice(0, 8)}…</span>
              </span>
            )}
          </div>
        )}

        <div className="flex items-center gap-2 text-[12px] font-semibold text-white mb-2">
          <Clock className="w-3.5 h-3.5 text-white/50" /> Timeline ({t.events.length})
        </div>
        <div className="space-y-2 mb-4">
          {t.events.length === 0 ? (
            <p className="text-[12px] text-white/35">No timeline entries yet.</p>
          ) : t.events.map(e => {
            const isInternal = e.visibility === 'internal'
            return (
              <div key={e.id} className="text-[12px] flex gap-2">
                <span className="w-1 rounded-full shrink-0 mt-1 mb-1"
                      style={{ background: e.kind === 'comment' ? (isInternal ? '#f59e0b' : '#8BFF3E') : 'rgba(255,255,255,0.2)' }} />
                <div className="flex-1">
                  <div className="text-white/80 whitespace-pre-wrap">{e.body}</div>
                  <div className="text-[10px] text-white/35 flex items-center gap-1.5 mt-0.5">
                    <span>{e.author ?? 'system'}</span>
                    <span>· {e.at ? new Date(e.at).toLocaleString() : ''}</span>
                    {isInternal && <span className="px-1 py-0.5 rounded font-bold uppercase tracking-wider"
                                          style={{ background: 'rgba(245,158,11,0.1)', color: '#f59e0b' }}>internal</span>}
                  </div>
                </div>
              </div>
            )
          })}
        </div>

        {canOperate && (
          <div className="space-y-2">
            <textarea value={comment} onChange={e => setComment(e.target.value)}
                      placeholder={visibility === 'internal' ? 'Internal note (staff-only)…' : 'Reply to customer…'}
                      rows={3}
                      className="w-full px-3 py-2 rounded-lg bg-transparent outline-none text-[12px] text-white/90 placeholder:text-white/30 resize-y"
                      style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
            <div className="flex items-center gap-2">
              <select value={visibility} onChange={e => setVisibility(e.target.value as 'public' | 'internal')}
                      className="px-2.5 py-1 rounded text-[11px] text-white/80 outline-none"
                      style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
                <option value="public" className="bg-[#0b0f17]">public (customer-facing)</option>
                <option value="internal" className="bg-[#0b0f17]">internal (staff-only)</option>
              </select>
              <button disabled={!comment.trim() || busy !== null}
                      onClick={() => act('cmt', async () => { await api.internal.commentTicket(id, comment.trim(), visibility); setComment('') })}
                      className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                      style={{ background: 'rgba(139,255,62,0.1)', color: '#8BFF3E', border: '1px solid rgba(139,255,62,0.3)' }}>
                <MessageSquare className="w-3 h-3" /> Send
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function TicketsPage() {
  const me = useInternalMe()
  const { subscribe } = useControlEvents()
  const canOperate = (ROLE_RANK[me?.role ?? 'none'] ?? 0) >= ROLE_RANK.support

  const [rows, setRows] = useState<TicketRow[]>([])
  const [total, setTotal] = useState(0)
  const [status, setStatus] = useState('open')
  const [priority, setPriority] = useState('')
  const [breachedOnly, setBreachedOnly] = useState(false)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  const load = useCallback(() => {
    setLoading(true)
    api.internal.tickets({
      status: status || undefined,
      priority: priority || undefined,
      breached_only: breachedOnly,
      limit: 100,
    }).then(r => { setRows(r.items); setTotal(r.total) })
      .finally(() => setLoading(false))
  }, [status, priority, breachedOnly])
  useEffect(() => { load() }, [load])
  useEffect(() => subscribe(() => load()), [subscribe, load])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Ticket className="w-5 h-5" style={{ color: '#8BFF3E' }} />
        <h1 className="text-[19px] font-bold text-white">Support &amp; Fix Service</h1>
        <span className="text-[12px] text-white/40">· {total.toLocaleString()} match</span>
        {canOperate && (
          <button onClick={() => setCreating(true)}
                  className="ml-auto flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold"
                  style={{ background: 'rgba(139,255,62,0.1)', color: '#8BFF3E', border: '1px solid rgba(139,255,62,0.3)' }}>
            <Plus className="w-3 h-3" /> New ticket
          </button>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <select value={status} onChange={e => setStatus(e.target.value)}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {STATUSES.map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s ? s.replace('_', ' ') : 'all statuses'}</option>)}
        </select>
        <select value={priority} onChange={e => setPriority(e.target.value)}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {PRIORITIES.map(p => <option key={p} value={p} className="bg-[#0b0f17]">{p || 'all priorities'}</option>)}
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
            {status === 'open' ? 'Inbox zero — no open tickets. ✅' : 'No tickets match.'}
          </div>
        ) : rows.map(t => (
          <div key={t.id} onClick={() => setSelected(t.id)}
               className="flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer hover:bg-white/[0.025] transition-colors"
               style={{ background: 'rgba(255,255,255,0.015)', border: '1px solid rgba(255,255,255,0.06)' }}>
            <PriorityDot p={t.priority} />
            <span className="font-mono text-[10px] text-white/40 w-14">WH-{String(t.number).padStart(4, '0')}</span>
            <div className="min-w-0 flex-1">
              <div className="text-[13px] text-white/90 truncate">{t.subject}</div>
              <div className="text-[11px] text-white/40">
                {t.category} · {t.priority}
                {t.opened_at ? ` · ${new Date(t.opened_at).toLocaleString()}` : ''}
              </div>
            </div>
            <SLAPill t={t} />
            <StatusBadge status={t.status} />
          </div>
        ))}
      </div>

      {selected && <Drawer id={selected} onClose={() => setSelected(null)} canOperate={canOperate} onChanged={load} />}
      {creating && <NewTicketDialog onClose={() => setCreating(false)} onCreated={load} />}
    </div>
  )
}
