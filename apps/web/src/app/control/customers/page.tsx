'use client'

// Customer Operations Center — search, detail, suspend/reactivate/force-logout,
// plan override, internal notes. Role-gated actions (ADMIN for state changes).

import { useCallback, useEffect, useState } from 'react'
import {
  Users, Search, X, Loader2, Ban, Power, LogOut, StickyNote, Trash2, AtSign, Building2,
} from 'lucide-react'
import { api, type CustomerRow, type CustomerDetail, type CustomerNote } from '@/lib/api'
import { useInternalMe } from '../layout'

const LIME = '#8BFF3E'
const ROLE_RANK: Record<string, number> = {
  none: 0, read_only: 10, billing: 20, support: 20, developer: 20,
  analyst: 30, admin: 90, super_admin: 100,
}

const PLANS = ['', 'free', 'pro', 'shield', 'enterprise'] as const
const STATUSES = ['', 'active', 'suspended', 'staff'] as const
const PLAN_COLOR: Record<string, string> = {
  free: 'rgba(255,255,255,0.5)', pro: LIME, shield: '#3b82f6', enterprise: '#a855f7',
}

function PlanBadge({ plan }: { plan: string }) {
  const c = PLAN_COLOR[plan] ?? 'rgba(255,255,255,0.5)'
  return (
    <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded capitalize"
          style={{ background: `${c}1a`, color: c, border: `1px solid ${c}33` }}>{plan}</span>
  )
}

function StatusDot({ user }: { user: { is_active: boolean; banned_at: string | null } }) {
  const ok = user.is_active && !user.banned_at
  const c = ok ? LIME : '#ef4444'
  return <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: c, boxShadow: `0 0 6px ${c}` }} />
}

function Drawer({ id, onClose, isAdmin, isSupport, onChanged }: {
  id: string; onClose: () => void; isAdmin: boolean; isSupport: boolean; onChanged: () => void
}) {
  const [d, setD] = useState<CustomerDetail | null>(null)
  const [notes, setNotes] = useState<CustomerNote[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const [noteText, setNoteText] = useState('')

  const load = useCallback(() => {
    api.internal.customerDetail(id).then(setD).catch(() => {})
    api.internal.customerNotes(id).then(r => setNotes(r.items)).catch(() => {})
  }, [id])
  useEffect(() => { load() }, [load])

  const act = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(label); try { await fn(); load(); onChanged() } finally { setBusy(null) }
  }

  const suspended = !!d && (!d.is_active || !!d.banned_at)

  return (
    <div className="fixed inset-0 z-50 flex justify-end" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="w-full max-w-[640px] h-full overflow-auto p-6 bg-[#070b13] border-l border-white/[0.08]"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-start gap-2.5">
            {d && <div className="mt-1.5"><StatusDot user={d} /></div>}
            <div>
              <h2 className="text-[16px] font-bold text-white">{d?.full_name || d?.email || 'Loading…'}</h2>
              {d && (
                <div className="text-[11px] mt-0.5 flex items-center gap-2 flex-wrap" style={{ color: 'rgba(255,255,255,0.45)' }}>
                  <span className="flex items-center gap-1"><AtSign className="w-3 h-3" />{d.email}</span>
                  {d.company_name && <span className="flex items-center gap-1"><Building2 className="w-3 h-3" />{d.company_name}</span>}
                  <PlanBadge plan={d.plan} />
                  {d.admin_role !== 'none' && (
                    <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded"
                          style={{ background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.2)' }}>{d.admin_role}</span>
                  )}
                </div>
              )}
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-white/5"><X className="w-4 h-4 text-white/60" /></button>
        </div>

        {!d ? (
          <div className="flex items-center gap-2 text-[12px] text-white/50"><Loader2 className="w-4 h-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            {suspended && (
              <div className="rounded-lg p-3 mb-4 text-[12px]"
                   style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)' }}>
                <div className="font-semibold text-red-400 mb-0.5">Account suspended</div>
                <div className="text-white/65">{d.banned_reason || '(no reason recorded)'}</div>
                {d.banned_at && <div className="text-[10px] text-white/35 mt-1">{new Date(d.banned_at).toLocaleString()}</div>}
              </div>
            )}

            <div className="grid grid-cols-2 gap-2.5 mb-5">
              {[
                ['Websites', d.websites],
                ['Scans', d.scans],
                ['Failed 30d', d.failed_30d],
                ['Last scan', d.last_scan_at ? new Date(d.last_scan_at).toLocaleDateString() : '—'],
                ['Joined', d.created_at ? new Date(d.created_at).toLocaleDateString() : '—'],
                ['Last login', d.last_login_at ? new Date(d.last_login_at).toLocaleDateString() : '—'],
              ].map(([k, v], i) => (
                <div key={i} className="rounded-lg p-2.5" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'rgba(255,255,255,0.35)' }}>{k}</div>
                  <div className="text-[15px] font-semibold text-white/90">{v}</div>
                </div>
              ))}
            </div>

            {d.subscriptions.length > 0 && (
              <div className="mb-5">
                <div className="text-[12px] font-semibold text-white mb-2">Subscriptions ({d.subscriptions.length})</div>
                <div className="space-y-1">
                  {d.subscriptions.map(s => (
                    <div key={s.id} className="flex items-center gap-2 text-[11px] px-2.5 py-1.5 rounded"
                         style={{ background: 'rgba(255,255,255,0.02)' }}>
                      <PlanBadge plan={s.plan} />
                      <span className="text-white/65 capitalize">{s.status}</span>
                      {s.current_period_end && <span className="text-white/40">→ {new Date(s.current_period_end).toLocaleDateString()}</span>}
                      {s.cancel_at_period_end && <span className="text-orange-400">cancels</span>}
                      <span className="ml-auto font-mono text-[10px] text-white/35">{s.stripe_subscription_id?.slice(0, 14)}…</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {isAdmin && (
              <div className="flex flex-wrap items-center gap-2 mb-5">
                {suspended ? (
                  <button disabled={busy !== null} onClick={() => act('reactivate', () => api.internal.reactivateCustomer(id))}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                          style={{ background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.3)' }}>
                    {busy === 'reactivate' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Power className="w-3.5 h-3.5" />} Reactivate
                  </button>
                ) : (
                  <button disabled={busy !== null} onClick={() => {
                    const reason = window.prompt('Suspension reason (optional):') ?? ''
                    if (reason === null) return
                    act('suspend', () => api.internal.suspendCustomer(id, reason || null))
                  }}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                          style={{ background: 'rgba(239,68,68,0.1)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.3)' }}>
                    {busy === 'suspend' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Ban className="w-3.5 h-3.5" />} Suspend
                  </button>
                )}
                <button disabled={busy !== null} onClick={() => act('logout', () => api.internal.forceLogoutCustomer(id))}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                        style={{ background: 'rgba(245,158,11,0.1)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.3)' }}>
                  {busy === 'logout' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <LogOut className="w-3.5 h-3.5" />} Force logout
                </button>
                <select disabled={busy !== null} value={d.plan}
                        onChange={async e => {
                          const np = e.target.value as 'free' | 'pro' | 'shield' | 'enterprise'
                          if (np === d.plan) return
                          if (!confirm(`Change plan to ${np}? (override; not synced to Stripe)`)) return
                          await act('plan', () => api.internal.changeCustomerPlan(id, np))
                        }}
                        className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                        style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
                  {(['free', 'pro', 'shield', 'enterprise'] as const).map(p => <option key={p} value={p} className="bg-[#0b0f17]">override → {p}</option>)}
                </select>
              </div>
            )}

            {/* Notes */}
            <div className="flex items-center gap-2 text-[12px] font-semibold text-white mb-2">
              <StickyNote className="w-3.5 h-3.5 text-white/50" /> Internal notes ({notes.length})
            </div>
            <div className="space-y-1.5 mb-3">
              {notes.length === 0 ? (
                <p className="text-[12px] text-white/35">No notes yet.</p>
              ) : notes.map(n => (
                <div key={n.id} className="px-2.5 py-2 rounded text-[12px] flex gap-2"
                     style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div className="flex-1">
                    <div className="text-white/85 whitespace-pre-wrap">{n.body}</div>
                    <div className="text-[10px] text-white/35 mt-0.5">{n.author ?? 'system'} · {n.at ? new Date(n.at).toLocaleString() : ''}</div>
                  </div>
                  {isAdmin && (
                    <button onClick={() => { if (confirm('Delete this note?')) act('del', () => api.internal.deleteNote(n.id)) }}
                            className="p-1 rounded hover:bg-white/5 text-white/30 hover:text-red-400">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  )}
                </div>
              ))}
            </div>
            {isSupport && (
              <div className="flex items-center gap-2">
                <input value={noteText} onChange={e => setNoteText(e.target.value)}
                       placeholder="Add an internal note…"
                       onKeyDown={e => { if (e.key === 'Enter' && noteText.trim()) act('note', async () => { await api.internal.addCustomerNote(id, noteText.trim()); setNoteText('') }) }}
                       className="flex-1 px-3 py-1.5 rounded-lg bg-transparent outline-none text-[12px] text-white/90 placeholder:text-white/30"
                       style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
                <button disabled={!noteText.trim() || busy !== null}
                        onClick={() => act('note', async () => { await api.internal.addCustomerNote(id, noteText.trim()); setNoteText('') })}
                        className="px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                        style={{ background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.3)' }}>
                  Save
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

export default function CustomersPage() {
  const me = useInternalMe()
  const role = me?.role ?? 'none'
  const isAdmin = (ROLE_RANK[role] ?? 0) >= ROLE_RANK.admin
  const isSupport = (ROLE_RANK[role] ?? 0) >= ROLE_RANK.support

  const [rows, setRows] = useState<CustomerRow[]>([])
  const [total, setTotal] = useState(0)
  const [q, setQ] = useState('')
  const [plan, setPlan] = useState('')
  const [status, setStatus] = useState('')
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<string | null>(null)
  const limit = 50

  const load = useCallback(() => {
    setLoading(true)
    api.internal.customers({ q: q || undefined, plan: plan || undefined, status: status || undefined, limit, offset })
      .then(r => { setRows(r.items); setTotal(r.total) })
      .finally(() => setLoading(false))
  }, [q, plan, status, offset])
  useEffect(() => { load() }, [load])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Users className="w-5 h-5" style={{ color: LIME }} />
        <h1 className="text-[19px] font-bold text-white">Customers</h1>
        <span className="text-[12px] text-white/40">· {total.toLocaleString()} total</span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg flex-1 min-w-[260px]"
             style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <Search className="w-3.5 h-3.5 text-white/35" />
          <input value={q} onChange={e => { setOffset(0); setQ(e.target.value) }}
                 placeholder="Search email, name, company…"
                 className="bg-transparent outline-none text-[12px] text-white/90 w-full placeholder:text-white/30" />
        </div>
        <select value={plan} onChange={e => { setOffset(0); setPlan(e.target.value) }}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {PLANS.map(p => <option key={p} value={p} className="bg-[#0b0f17]">{p || 'all plans'}</option>)}
        </select>
        <select value={status} onChange={e => { setOffset(0); setStatus(e.target.value) }}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {STATUSES.map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s || 'all statuses'}</option>)}
        </select>
      </div>

      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-left" style={{ background: 'rgba(255,255,255,0.02)', color: 'rgba(255,255,255,0.4)' }}>
              <th className="font-semibold px-3 py-2.5 w-6"></th>
              <th className="font-semibold px-3 py-2.5">Email</th>
              <th className="font-semibold px-3 py-2.5">Name / Company</th>
              <th className="font-semibold px-3 py-2.5">Plan</th>
              <th className="font-semibold px-3 py-2.5">Joined</th>
              <th className="font-semibold px-3 py-2.5">Last login</th>
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <tr><td colSpan={6} className="px-3 py-8 text-center text-white/40">
                <Loader2 className="w-4 h-4 animate-spin inline" /></td></tr>
            ) : rows.length === 0 ? (
              <tr><td colSpan={6} className="px-3 py-8 text-center text-white/35">No customers match.</td></tr>
            ) : rows.map(c => (
              <tr key={c.id} onClick={() => setSelected(c.id)}
                  className="cursor-pointer border-t border-white/[0.04] hover:bg-white/[0.02] transition-colors">
                <td className="px-3 py-2.5"><StatusDot user={c} /></td>
                <td className="px-3 py-2.5 text-white/90 max-w-[240px] truncate">{c.email}</td>
                <td className="px-3 py-2.5 text-white/60 max-w-[200px] truncate">
                  {c.full_name || c.company_name || <span className="text-white/30">—</span>}
                </td>
                <td className="px-3 py-2.5"><PlanBadge plan={c.plan} /></td>
                <td className="px-3 py-2.5 text-white/50">{c.created_at ? new Date(c.created_at).toLocaleDateString() : '—'}</td>
                <td className="px-3 py-2.5 text-white/50">{c.last_login_at ? new Date(c.last_login_at).toLocaleDateString() : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {total > limit && (
        <div className="flex items-center justify-between text-[12px] text-white/50">
          <span>{offset + 1}–{Math.min(offset + limit, total)} of {total.toLocaleString()}</span>
          <div className="flex gap-2">
            <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}
                    className="px-3 py-1.5 rounded-lg disabled:opacity-30"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>Prev</button>
            <button disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)}
                    className="px-3 py-1.5 rounded-lg disabled:opacity-30"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>Next</button>
          </div>
        </div>
      )}

      {selected && (
        <Drawer id={selected} onClose={() => setSelected(null)}
                isAdmin={isAdmin} isSupport={isSupport} onChanged={load} />
      )}
    </div>
  )
}
