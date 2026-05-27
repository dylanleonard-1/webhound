'use client'

// Scan Operations Center — live scan list, filters, detail drawer, cancel/rescan.

import { useCallback, useEffect, useState } from 'react'
import {
  ScanLine, Search, X, RotateCw, Ban, Loader2, ChevronRight,
} from 'lucide-react'
import { api, type ScanRow, type ScanDetail } from '@/lib/api'
import { useInternalMe } from '../layout'

const LIME = '#8BFF3E'
const ROLE_RANK: Record<string, number> = {
  none: 0, read_only: 10, billing: 20, support: 20, developer: 20,
  analyst: 30, admin: 90, super_admin: 100,
}

const STATUS_COLOR: Record<string, string> = {
  completed: LIME, running: '#f59e0b', queued: '#3b82f6',
  failed: '#ef4444', cancelled: 'rgba(255,255,255,0.4)',
}

const STATUSES = ['', 'queued', 'running', 'completed', 'failed', 'cancelled']
const PROFILES = ['', 'quick', 'standard', 'deep']

function StatusBadge({ status }: { status: string }) {
  const c = STATUS_COLOR[status] ?? 'rgba(255,255,255,0.5)'
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold capitalize">
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: c, boxShadow: `0 0 6px ${c}` }} />
      <span style={{ color: c }}>{status}</span>
    </span>
  )
}

function DetailDrawer({ id, onClose, canOperate, onChanged }: {
  id: string; onClose: () => void; canOperate: boolean; onChanged: () => void
}) {
  const [detail, setDetail] = useState<ScanDetail | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)

  const load = useCallback(() => {
    api.internal.scanDetail(id).then(setDetail).catch(() => setMsg('Failed to load detail'))
  }, [id])
  useEffect(() => { load() }, [load])

  const cancel = async () => {
    setBusy('cancel'); setMsg(null)
    try { await api.internal.cancelScan(id); setMsg('Scan cancelled'); load(); onChanged() }
    catch (e) { setMsg((e as Error).message || 'Cancel failed') }
    finally { setBusy(null) }
  }
  const rescan = async () => {
    setBusy('rescan'); setMsg(null)
    try { const r = await api.internal.rescan(id); setMsg(`Rescan queued (${r.new_scan_id.slice(0, 8)})`); onChanged() }
    catch (e) { setMsg((e as Error).message || 'Rescan failed') }
    finally { setBusy(null) }
  }

  const cancellable = detail && (detail.status === 'queued' || detail.status === 'running')

  return (
    <div className="fixed inset-0 z-50 flex justify-end" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="w-full max-w-[560px] h-full overflow-auto p-6 bg-[#070b13] border-l border-white/[0.08]"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="text-[15px] font-bold text-white">Scan detail</h2>
            <p className="font-mono text-[11px]" style={{ color: 'rgba(255,255,255,0.4)' }}>{id}</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-white/5"><X className="w-4 h-4 text-white/60" /></button>
        </div>

        {!detail ? (
          <div className="flex items-center gap-2 text-[12px] text-white/50"><Loader2 className="w-4 h-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-3 mb-4">
              {[
                ['Status', <StatusBadge key="s" status={detail.status} />],
                ['Profile', detail.profile],
                ['Owner', detail.owner ?? '—'],
                ['Host', detail.hostname ?? '—'],
                ['Duration', detail.duration_s != null ? `${detail.duration_s}s` : '—'],
                ['Created', detail.created_at ? new Date(detail.created_at).toLocaleString() : '—'],
              ].map(([k, v], i) => (
                <div key={i} className="rounded-lg p-2.5" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'rgba(255,255,255,0.35)' }}>{k}</div>
                  <div className="text-[13px] text-white/90 truncate">{v}</div>
                </div>
              ))}
            </div>

            <div className="rounded-lg p-2.5 mb-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'rgba(255,255,255,0.35)' }}>URL</div>
              <div className="text-[12px] font-mono text-white/80 break-all">{detail.url}</div>
            </div>

            {detail.error && (
              <div className="rounded-lg p-2.5 mb-4 text-[12px]" style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', color: '#fca5a5' }}>
                {detail.error}
              </div>
            )}

            {canOperate && (
              <div className="flex items-center gap-2 mb-5">
                <button disabled={!cancellable || busy !== null} onClick={cancel}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                        style={{ background: 'rgba(239,68,68,0.1)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.25)' }}>
                  {busy === 'cancel' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Ban className="w-3.5 h-3.5" />} Cancel
                </button>
                <button disabled={busy !== null} onClick={rescan}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                        style={{ background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.25)' }}>
                  {busy === 'rescan' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCw className="w-3.5 h-3.5" />} Force rescan
                </button>
                {msg && <span className="text-[11px] text-white/55">{msg}</span>}
              </div>
            )}

            <div className="text-[12px] font-semibold text-white mb-2">Engine diagnostics ({detail.engines.length})</div>
            {detail.engines.length === 0 ? (
              <p className="text-[12px] text-white/35">No engine diagnostics recorded for this scan.</p>
            ) : (
              <div className="space-y-1">
                {detail.engines.map((e, i) => (
                  <div key={i} className="flex items-center gap-2 text-[12px] py-1.5 px-2 rounded"
                       style={{ background: 'rgba(255,255,255,0.015)' }}>
                    <span className="font-mono text-white/80 w-36 truncate">{e.engine}</span>
                    <StatusBadge status={e.status} />
                    <span className="text-white/45">{e.findings} findings</span>
                    <span className="ml-auto text-white/40">{e.duration_ms != null ? `${Math.round(e.duration_ms)}ms` : '—'}</span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

export default function ScanOpsPage() {
  const me = useInternalMe()
  const canOperate = (ROLE_RANK[me?.role ?? 'none'] ?? 0) >= ROLE_RANK.analyst

  const [rows, setRows] = useState<ScanRow[]>([])
  const [total, setTotal] = useState(0)
  const [status, setStatus] = useState('')
  const [profile, setProfile] = useState('')
  const [q, setQ] = useState('')
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<string | null>(null)
  const limit = 50

  const load = useCallback(() => {
    setLoading(true)
    api.internal.scans({ status: status || undefined, profile: profile || undefined, q: q || undefined, limit, offset })
      .then(r => { setRows(r.items); setTotal(r.total) })
      .finally(() => setLoading(false))
  }, [status, profile, q, offset])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    const id = setInterval(load, 10000)
    return () => clearInterval(id)
  }, [load])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <ScanLine className="w-5 h-5" style={{ color: LIME }} />
        <h1 className="text-[19px] font-bold text-white">Scan Operations</h1>
        <span className="text-[12px] text-white/40">· {total.toLocaleString()} total</span>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg flex-1 min-w-[220px]"
             style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <Search className="w-3.5 h-3.5 text-white/35" />
          <input value={q} onChange={e => { setOffset(0); setQ(e.target.value) }}
                 placeholder="Search URL or owner email…"
                 className="bg-transparent outline-none text-[12px] text-white/90 w-full placeholder:text-white/30" />
        </div>
        <select value={status} onChange={e => { setOffset(0); setStatus(e.target.value) }}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {STATUSES.map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s || 'all statuses'}</option>)}
        </select>
        <select value={profile} onChange={e => { setOffset(0); setProfile(e.target.value) }}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {PROFILES.map(p => <option key={p} value={p} className="bg-[#0b0f17]">{p || 'all profiles'}</option>)}
        </select>
      </div>

      {/* Table */}
      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-left" style={{ background: 'rgba(255,255,255,0.02)', color: 'rgba(255,255,255,0.4)' }}>
              <th className="font-semibold px-3 py-2.5">Status</th>
              <th className="font-semibold px-3 py-2.5">Target</th>
              <th className="font-semibold px-3 py-2.5">Owner</th>
              <th className="font-semibold px-3 py-2.5">Profile</th>
              <th className="font-semibold px-3 py-2.5">Duration</th>
              <th className="font-semibold px-3 py-2.5">Created</th>
              <th className="px-3 py-2.5"></th>
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <tr><td colSpan={7} className="px-3 py-8 text-center text-white/40">
                <Loader2 className="w-4 h-4 animate-spin inline" /></td></tr>
            ) : rows.length === 0 ? (
              <tr><td colSpan={7} className="px-3 py-8 text-center text-white/35">No scans match these filters.</td></tr>
            ) : rows.map(r => (
              <tr key={r.id} onClick={() => setSelected(r.id)}
                  className="cursor-pointer border-t border-white/[0.04] hover:bg-white/[0.02] transition-colors">
                <td className="px-3 py-2.5"><StatusBadge status={r.status} /></td>
                <td className="px-3 py-2.5 text-white/85 max-w-[260px] truncate">{r.hostname ?? r.url}</td>
                <td className="px-3 py-2.5 text-white/55 max-w-[200px] truncate">{r.owner ?? '—'}</td>
                <td className="px-3 py-2.5 text-white/55 capitalize">{r.profile}</td>
                <td className="px-3 py-2.5 text-white/55">{r.duration_s != null ? `${r.duration_s}s` : '—'}</td>
                <td className="px-3 py-2.5 text-white/45">{r.created_at ? new Date(r.created_at).toLocaleString() : '—'}</td>
                <td className="px-3 py-2.5"><ChevronRight className="w-4 h-4 text-white/30" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
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
        <DetailDrawer id={selected} onClose={() => setSelected(null)} canOperate={canOperate} onChanged={load} />
      )}
    </div>
  )
}
