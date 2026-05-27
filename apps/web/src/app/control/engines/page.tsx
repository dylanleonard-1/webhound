'use client'

// Engine Reliability — per-engine scorecards from engine_diagnostics.

import { useEffect, useState } from 'react'
import { Cpu, Loader2 } from 'lucide-react'
import { api, type EngineScorecard } from '@/lib/api'

const LIME = '#8BFF3E'

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
  const [engines, setEngines] = useState<EngineScorecard[] | null>(null)
  const [err, setErr] = useState(false)

  useEffect(() => {
    let cancelled = false
    const load = () => api.internal.engines()
      .then(d => { if (!cancelled) { setEngines(d.engines); setErr(false) } })
      .catch(() => { if (!cancelled) setErr(true) })
    load()
    const id = setInterval(load, 15000)
    return () => { cancelled = true; clearInterval(id) }
  }, [])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Cpu className="w-5 h-5" style={{ color: LIME }} />
        <h1 className="text-[19px] font-bold text-white">Engine Reliability</h1>
        {engines && <span className="text-[12px] text-white/40">· {engines.length} engines</span>}
        {err && <span className="ml-auto text-[12px] text-red-400">unavailable — retrying…</span>}
      </div>
      <p className="text-[12px] text-white/40">
        Reliability = share of runs that neither failed nor were skipped, across all recorded scans.
      </p>

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
            return (
              <div key={e.engine} className="rounded-xl p-4"
                   style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)' }}>
                <div className="flex items-center justify-between mb-3">
                  <span className="font-mono text-[13px] text-white/90 truncate">{e.engine}</span>
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
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
