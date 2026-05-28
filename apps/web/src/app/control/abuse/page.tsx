'use client'

// Fraud & Abuse triage queue. Each flag is a deduped subject (usually a user)
// scored by independent signals (excessive scans, payment failures, IP/UA
// diversity, auth failures). Staff dismiss or escalate to ban.

import { useCallback, useEffect, useState } from 'react'
import {
  ShieldAlert, X, Loader2, Ban, Check, AlertTriangle, Activity,
} from 'lucide-react'
import { api, type AbuseFlagRow, type AbuseFlagDetail } from '@/lib/api'
import { useInternalMe, useControlEvents } from '../layout'

const ROLE_RANK: Record<string, number> = {
  none: 0, read_only: 10, billing: 20, support: 20, developer: 20,
  analyst: 30, admin: 90, super_admin: 100,
}

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6', info: '#8b94a6',
}
const STATUS_COLOR: Record<string, string> = {
  pending: '#ef4444', dismissed: 'rgba(255,255,255,0.4)', banned: '#a855f7',
}
const REASON_LABEL: Record<string, string> = {
  excessive_scans: 'Excessive scans',
  failed_payments: 'Payment failures',
  many_ips: 'Many IPs',
  many_user_agents: 'Many devices',
  auth_failures: 'Auth failures',
  high_fail_rate: 'High scan failure rate',
}

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

function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(100, score)
  const c = score >= 80 ? '#ef4444' : score >= 50 ? '#f97316' : score >= 30 ? '#f59e0b' : '#3b82f6'
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-24 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: c }} />
      </div>
      <span className="text-[11px] font-bold tabular-nums" style={{ color: c }}>{score}</span>
    </div>
  )
}

function Drawer({ id, onClose, isOp, isAdmin, onChanged }: {
  id: string; onClose: () => void; isOp: boolean; isAdmin: boolean; onChanged: () => void
}) {
  const [d, setD] = useState<AbuseFlagDetail | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const load = useCallback(() => { api.internal.abuseFlagDetail(id).then(setD).catch(() => {}) }, [id])
  useEffect(() => { load() }, [load])

  const act = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(label); try { await fn(); load(); onChanged() } finally { setBusy(null) }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="w-full max-w-[600px] h-full overflow-auto p-6 bg-[#070b13] border-l border-white/[0.08]"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-start gap-2.5">
            {d && <div className="mt-1.5"><SevDot sev={d.severity} /></div>}
            <div>
              <h2 className="text-[15px] font-bold text-white">Abuse flag</h2>
              {d && (
                <p className="text-[11px] mt-0.5" style={{ color: 'rgba(255,255,255,0.4)' }}>
                  {d.user_email || d.ip_address || d.dedup_key} · seen {d.occurrences}× · last {d.last_seen_at ? new Date(d.last_seen_at).toLocaleString() : '—'}
                </p>
              )}
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-white/5"><X className="w-4 h-4 text-white/60" /></button>
        </div>

        {!d ? (
          <div className="flex items-center gap-2 text-[12px] text-white/50"><Loader2 className="w-4 h-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            <div className="flex items-center gap-3 mb-4">
              <StatusBadge status={d.status} />
              <ScoreBar score={d.score} />
              {d.user_is_active === false && (
                <span className="text-[10px] font-bold text-red-400 uppercase tracking-wider">user suspended</span>
              )}
            </div>

            <div className="text-[12px] font-semibold text-white mb-1.5 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-white/50" /> Signals matched ({d.reasons.length})
            </div>
            <div className="space-y-1.5 mb-4">
              {d.reasons.map(r => (
                <div key={r} className="px-2.5 py-1.5 rounded text-[11px]"
                     style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div className="flex items-center justify-between">
                    <span className="text-white/85 font-semibold">{REASON_LABEL[r] ?? r}</span>
                    <span className="font-mono text-[10px] text-white/35">{r}</span>
                  </div>
                  {d.detail?.[r] && (
                    <div className="mt-1 text-white/55">
                      {Object.entries(d.detail[r]).map(([k, v]) => (
                        <span key={k} className="mr-3 text-[10px]">{k}=<span className="text-white/80">{String(v)}</span></span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {d.resolution_note && (
              <div className="rounded-lg p-2.5 mb-4 text-[12px]"
                   style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                <div className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'rgba(255,255,255,0.35)' }}>
                  Resolution
                </div>
                <div className="text-white/80">{d.resolution_note}</div>
                <div className="text-[10px] text-white/35 mt-1">
                  {d.resolved_by ?? 'system'} · {d.resolved_at ? new Date(d.resolved_at).toLocaleString() : ''}
                </div>
              </div>
            )}

            {d.status === 'pending' && (
              <div className="flex flex-wrap items-center gap-2 mb-4">
                {isOp && (
                  <button disabled={busy !== null} onClick={() => {
                    const note = window.prompt('Dismissal note (optional):') ?? ''
                    act('dismiss', () => api.internal.dismissAbuseFlag(id, note || null))
                  }}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                          style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.8)', border: '1px solid rgba(255,255,255,0.1)' }}>
                    {busy === 'dismiss' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />} Dismiss
                  </button>
                )}
                {isAdmin && d.user_id && (
                  <button disabled={busy !== null} onClick={() => {
                    if (!confirm(`Ban this user? They'll be suspended and force-logged-out.`)) return
                    act('ban', () => api.internal.banFromAbuseFlag(id, null))
                  }}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                          style={{ background: 'rgba(239,68,68,0.1)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.3)' }}>
                    {busy === 'ban' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Ban className="w-3.5 h-3.5" />} Escalate to ban
                  </button>
                )}
                {isOp && d.user_id && (
                  <button disabled={busy !== null} onClick={() => act('re', () => api.internal.evaluateAbuse(d.user_id!))}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                          style={{ background: 'rgba(139,255,62,0.08)', color: '#8BFF3E', border: '1px solid rgba(139,255,62,0.2)' }}>
                    {busy === 're' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />} Re-evaluate
                  </button>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

const STATUSES = ['', 'pending', 'dismissed', 'banned']
const SEVERITIES = ['', 'critical', 'high', 'medium', 'low']

export default function AbusePage() {
  const me = useInternalMe()
  const { subscribe } = useControlEvents()
  const role = me?.role ?? 'none'
  const isOp = (ROLE_RANK[role] ?? 0) >= ROLE_RANK.analyst
  const isAdmin = (ROLE_RANK[role] ?? 0) >= ROLE_RANK.admin

  const [rows, setRows] = useState<AbuseFlagRow[]>([])
  const [total, setTotal] = useState(0)
  const [status, setStatus] = useState('pending')
  const [severity, setSeverity] = useState('')
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<string | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    api.internal.abuseFlags({ status: status || undefined, severity: severity || undefined, limit: 100 })
      .then(r => { setRows(r.items); setTotal(r.total) })
      .finally(() => setLoading(false))
  }, [status, severity])
  useEffect(() => { load() }, [load])
  useEffect(() => subscribe(() => load()), [subscribe, load])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <ShieldAlert className="w-5 h-5" style={{ color: '#ef4444' }} />
        <h1 className="text-[19px] font-bold text-white">Fraud &amp; Abuse</h1>
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
            {status === 'pending' ? 'No pending flags — fraud detection is quiet. ✅' : 'No flags match.'}
          </div>
        ) : rows.map(f => (
          <div key={f.id} onClick={() => setSelected(f.id)}
               className="flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer hover:bg-white/[0.025] transition-colors"
               style={{ background: 'rgba(255,255,255,0.015)', border: '1px solid rgba(255,255,255,0.06)' }}>
            <SevDot sev={f.severity} />
            <ScoreBar score={f.score} />
            <div className="min-w-0 flex-1">
              <div className="text-[13px] text-white/90 truncate">{f.dedup_key}</div>
              <div className="text-[11px] text-white/40">
                {f.reasons.slice(0, 4).map(r => REASON_LABEL[r] ?? r).join(' · ')}
                {f.reasons.length > 4 ? ` +${f.reasons.length - 4}` : ''}
                {f.last_seen_at ? ` · ${new Date(f.last_seen_at).toLocaleString()}` : ''}
              </div>
            </div>
            <StatusBadge status={f.status} />
          </div>
        ))}
      </div>

      {selected && <Drawer id={selected} onClose={() => setSelected(null)} isOp={isOp} isAdmin={isAdmin} onChanged={load} />}
    </div>
  )
}
