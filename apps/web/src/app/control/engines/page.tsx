'use client'

// Engine Reliability — per-engine scorecards + operational state machine +
// maintenance toggle / auto-disable threshold (ANALYST+ toggle, ADMIN sets
// the threshold).

import { useCallback, useEffect, useState } from 'react'
import { Cpu, Loader2, Wrench, AlertTriangle, ShieldCheck } from 'lucide-react'
import { api, type EngineHealthRow } from '@/lib/api'
import { useInternalMe } from '../layout'

const LIME = '#8BFF3E'
const ROLE_RANK: Record<string, number> = {
  none: 0, read_only: 10, billing: 20, support: 20, developer: 20,
  analyst: 30, admin: 90, super_admin: 100,
}

// State → color + label. Critical means very high failure rate; unstable is
// the warning zone; degraded is mild; maintenance is staff-paused.
const STATE_TONE: Record<string, { color: string; label: string }> = {
  healthy:     { color: LIME, label: 'Healthy' },
  degraded:    { color: '#f59e0b', label: 'Degraded' },
  unstable:    { color: '#f97316', label: 'Unstable' },
  critical:    { color: '#ef4444', label: 'Critical' },
  maintenance: { color: '#a855f7', label: 'Maintenance' },
}

function StatePill({ state }: { state?: string }) {
  const t = STATE_TONE[state ?? 'healthy'] ?? STATE_TONE.healthy
  return (
    <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
          style={{ background: `${t.color}1a`, color: t.color, border: `1px solid ${t.color}33` }}>
      {t.label}
    </span>
  )
}

function relColor(r: number | null): string {
  if (r == null) return 'rgba(255,255,255,0.4)'
  if (r >= 99) return LIME
  if (r >= 95) return '#a3e635'
  if (r >= 85) return '#f59e0b'
  return '#ef4444'
}

function Bar({ pct, color }: { pct: number; color: string }) {
  return (
    <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
      <div className="h-full rounded-full" style={{ width: `${Math.min(100, pct)}%`, background: color }} />
    </div>
  )
}

export default function EnginesPage() {
  const me = useInternalMe()
  const role = me?.role ?? 'none'
  const isOp = (ROLE_RANK[role] ?? 0) >= ROLE_RANK.analyst
  const isAdmin = (ROLE_RANK[role] ?? 0) >= ROLE_RANK.admin

  const [engines, setEngines] = useState<EngineHealthRow[] | null>(null)
  const [err, setErr] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)

  const load = useCallback(() => {
    api.internal.engines()
      .then(d => { setEngines(d.engines as EngineHealthRow[]); setErr(false) })
      .catch(() => setErr(true))
  }, [])
  useEffect(() => {
    load()
    const id = setInterval(load, 15000)
    return () => clearInterval(id)
  }, [load])

  const toggleMaintenance = async (e: EngineHealthRow) => {
    const target = !e.maintenance_mode
    if (!confirm(`${target ? 'Engage' : 'Disengage'} maintenance for '${e.engine}'?`)) return
    setBusy(e.engine)
    try { await api.internal.engineMaintenance(e.engine, target); load() }
    finally { setBusy(null) }
  }

  const setThreshold = async (e: EngineHealthRow) => {
    const current = e.auto_disable_at_failure_pct ?? ''
    const raw = window.prompt(
      `Auto-disable threshold for '${e.engine}' (failure %, 0–100, blank to clear):`,
      String(current),
    )
    if (raw === null) return
    const pct = raw.trim() === '' ? null : Math.max(0, Math.min(100, parseInt(raw, 10) || 0))
    setBusy(e.engine)
    try { await api.internal.engineThreshold(e.engine, pct); load() }
    finally { setBusy(null) }
  }

  // Surface the worst state at the top so staff see issues immediately. The
  // backend already sorts critical-first, but pre-counting per state lets us
  // render a tiny health summary header.
  const counts = (engines ?? []).reduce<Record<string, number>>((m, e) => {
    const k = e.state ?? 'healthy'
    m[k] = (m[k] ?? 0) + 1
    return m
  }, {})

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Cpu className="w-5 h-5" style={{ color: LIME }} />
        <h1 className="text-[19px] font-bold text-white">Engine Health</h1>
        {engines && <span className="text-[12px] text-white/40">· {engines.length} engines</span>}
        {err && <span className="ml-auto text-[12px] text-red-400">unavailable — retrying…</span>}
      </div>
      <p className="text-[12px] text-white/40">
        Reliability = share of runs that neither failed nor were skipped, last 7 days.
        State machine: healthy / degraded / unstable / critical / maintenance.
      </p>

      {engines && engines.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          {(['critical', 'unstable', 'degraded', 'maintenance', 'healthy'] as const).map(s => {
            const n = counts[s] ?? 0
            if (!n) return null
            const t = STATE_TONE[s]
            return (
              <span key={s} className="text-[11px] font-semibold px-2 py-0.5 rounded"
                    style={{ background: `${t.color}1a`, color: t.color, border: `1px solid ${t.color}33` }}>
                {n} {t.label.toLowerCase()}
              </span>
            )
          })}
        </div>
      )}

      {engines === null ? (
        <div className="flex items-center gap-2 text-[12px] text-white/50 py-8">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading scorecards…
        </div>
      ) : engines.length === 0 ? (
        <p className="text-[12px] text-white/35 py-8">No engine diagnostics recorded yet.</p>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {engines.map(e => {
            const c = relColor(e.reliability)
            const stateTone = STATE_TONE[e.state ?? 'healthy']
            return (
              <div key={e.engine} className="rounded-xl p-4"
                   style={{ background: e.maintenance_mode ? 'rgba(168,85,247,0.04)' : 'rgba(255,255,255,0.02)',
                            border: `1px solid ${e.maintenance_mode ? 'rgba(168,85,247,0.25)' : 'rgba(255,255,255,0.07)'}` }}>
                <div className="flex items-center justify-between mb-2">
                  <div className="min-w-0 flex-1">
                    <div className="font-mono text-[13px] text-white/90 truncate">{e.engine}</div>
                    <div className="mt-1"><StatePill state={e.state} /></div>
                  </div>
                  <span className="text-[18px] font-bold" style={{ color: c }}>
                    {e.reliability != null ? `${e.reliability}%` : '—'}
                  </span>
                </div>
                <Bar pct={e.reliability ?? 0} color={c} />
                <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 mt-3 text-[11px]">
                  <div className="flex justify-between"><span className="text-white/40">Runs</span><span className="text-white/80">{e.runs.toLocaleString()}</span></div>
                  <div className="flex justify-between"><span className="text-white/40">Avg time</span><span className="text-white/80">{e.avg_ms != null ? `${Math.round(e.avg_ms)}ms` : '—'}</span></div>
                  <div className="flex justify-between"><span className="text-white/40">Failures</span><span style={{ color: e.failed ? '#fca5a5' : 'rgba(255,255,255,0.8)' }}>{e.failed} ({e.failure_rate}%)</span></div>
                  <div className="flex justify-between"><span className="text-white/40">Skipped</span><span className="text-white/80">{e.skipped}</span></div>
                  <div className="flex justify-between col-span-2"><span className="text-white/40">Empty-result rate</span><span className="text-white/80">{e.empty_rate}%</span></div>
                  {e.max_ms != null && (
                    <div className="flex justify-between col-span-2">
                      <span className="text-white/40">Slowest run</span>
                      <span className="text-white/80">{Math.round(e.max_ms)}ms</span>
                    </div>
                  )}
                  {e.auto_disable_at_failure_pct != null && (
                    <div className="flex justify-between col-span-2">
                      <span className="text-white/40">Auto-disable at</span>
                      <span className="text-white/80">≥ {e.auto_disable_at_failure_pct}% failures</span>
                    </div>
                  )}
                </div>

                {(isOp || isAdmin) && (
                  <div className="flex items-center gap-2 mt-3 pt-3 border-t border-white/[0.05]">
                    {isOp && (
                      <button disabled={busy === e.engine}
                              onClick={() => toggleMaintenance(e)}
                              className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold disabled:opacity-40"
                              style={e.maintenance_mode
                                ? { background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.3)' }
                                : { background: 'rgba(168,85,247,0.1)', color: '#a855f7', border: '1px solid rgba(168,85,247,0.3)' }}>
                        {busy === e.engine ? <Loader2 className="w-3 h-3 animate-spin" />
                          : e.maintenance_mode ? <ShieldCheck className="w-3 h-3" /> : <Wrench className="w-3 h-3" />}
                        {e.maintenance_mode ? 'Resume' : 'Maintenance'}
                      </button>
                    )}
                    {isAdmin && (
                      <button disabled={busy === e.engine} onClick={() => setThreshold(e)}
                              className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold disabled:opacity-40"
                              style={{ background: 'rgba(255,255,255,0.03)', color: 'rgba(255,255,255,0.7)', border: '1px solid rgba(255,255,255,0.08)' }}>
                        <AlertTriangle className="w-3 h-3" /> Threshold
                      </button>
                    )}
                    {e.notes && (
                      <span className="ml-auto text-[10px] text-white/45 truncate" title={e.notes}>{e.notes}</span>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
