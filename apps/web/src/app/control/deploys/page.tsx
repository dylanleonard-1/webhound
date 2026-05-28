'use client'

// Deploys — manual deploy history + the live RAILWAY_GIT_COMMIT_SHA running
// this very API. Recording new deploys is ADMIN-only and audited.

import { useCallback, useEffect, useState } from 'react'
import {
  Rocket, Loader2, Plus, X, GitCommit,
} from 'lucide-react'
import { api, type DeployRow } from '@/lib/api'
import { useInternalMe } from '../layout'

const LIME = '#8BFF3E'
const ROLE_RANK: Record<string, number> = {
  none: 0, read_only: 10, billing: 20, support: 20, developer: 20,
  analyst: 30, admin: 90, super_admin: 100,
}

const SERVICES = ['', 'api', 'worker', 'web', 'scanner', 'other'] as const
const STATUS_COLOR: Record<string, string> = {
  succeeded: LIME, in_progress: '#f59e0b', failed: '#ef4444', rolled_back: '#a855f7',
}

function NewDeployDialog({ onClose, onRecorded }: { onClose: () => void; onRecorded: () => void }) {
  const [service, setService] = useState('api')
  const [sha, setSha] = useState('')
  const [status, setStatus] = useState('succeeded')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const submit = async () => {
    if (sha.trim().length < 7) { setErr('sha must be at least 7 chars'); return }
    setBusy(true); setErr(null)
    try {
      await api.internal.recordDeploy({ service, sha: sha.trim(), status, note: note.trim() || null })
      onRecorded(); onClose()
    } catch (e) { setErr((e as Error).message || 'Failed to record') }
    finally { setBusy(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="w-full max-w-[440px] rounded-xl p-5 bg-[#070b13] border border-white/10"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-[14px] font-bold text-white">Record deploy</h3>
          <button onClick={onClose} className="p-1 rounded hover:bg-white/5"><X className="w-4 h-4 text-white/60" /></button>
        </div>
        <div className="space-y-2.5">
          <div className="grid grid-cols-2 gap-2">
            <select value={service} onChange={e => setService(e.target.value)}
                    className="px-3 py-2 rounded-lg text-[12px] text-white/85 outline-none"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {SERVICES.filter(s => s).map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s}</option>)}
            </select>
            <select value={status} onChange={e => setStatus(e.target.value)}
                    className="px-3 py-2 rounded-lg text-[12px] text-white/85 outline-none"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {['succeeded', 'in_progress', 'failed', 'rolled_back'].map(s =>
                <option key={s} value={s} className="bg-[#0b0f17]">{s}</option>)}
            </select>
          </div>
          <input value={sha} onChange={e => setSha(e.target.value)} placeholder="commit sha (7+ chars)"
                 className="w-full px-3 py-2 rounded-lg bg-transparent outline-none text-[12px] text-white/90 placeholder:text-white/30 font-mono"
                 style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
          <textarea value={note} onChange={e => setNote(e.target.value)} placeholder="Note (optional)"
                    rows={2}
                    className="w-full px-3 py-2 rounded-lg bg-transparent outline-none text-[12px] text-white/85 placeholder:text-white/30 resize-y"
                    style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
          {err && <div className="text-[11px] text-red-400">{err}</div>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose} className="px-3 py-1.5 rounded-lg text-[12px] text-white/65"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>Cancel</button>
            <button disabled={!sha.trim() || busy} onClick={submit}
                    className="px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                    style={{ background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.3)' }}>
              {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Record'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function DeploysPage() {
  const me = useInternalMe()
  const isAdmin = (ROLE_RANK[me?.role ?? 'none'] ?? 0) >= ROLE_RANK.admin

  const [items, setItems] = useState<DeployRow[]>([])
  const [currentSha, setCurrentSha] = useState<string | null>(null)
  const [service, setService] = useState('')
  const [creating, setCreating] = useState(false)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    api.internal.deploys(service || undefined)
      .then(r => { setItems(r.items); setCurrentSha(r.current_sha) })
      .finally(() => setLoading(false))
  }, [service])
  useEffect(() => { load() }, [load])

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <Rocket className="w-5 h-5" style={{ color: LIME }} />
        <h1 className="text-[19px] font-bold text-white">Deploys</h1>
        {isAdmin && (
          <button onClick={() => setCreating(true)}
                  className="ml-auto flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold"
                  style={{ background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.3)' }}>
            <Plus className="w-3 h-3" /> Record deploy
          </button>
        )}
      </div>

      <div className="rounded-xl p-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)' }}>
        <div className="flex items-center gap-2">
          <GitCommit className="w-4 h-4" style={{ color: LIME }} />
          <span className="text-[12px] font-semibold text-white/85">Currently running (API service)</span>
        </div>
        <div className="mt-2 font-mono text-[18px] font-bold text-white">
          {currentSha ? (
            <a href={`https://github.com/dylanleonard-1/webhound/commit/${currentSha}`} target="_blank"
               rel="noreferrer" className="hover:text-[color:#8BFF3E] transition-colors">
              {currentSha.slice(0, 12)}
            </a>
          ) : <span className="text-white/30 text-[14px]">unknown (env not set)</span>}
        </div>
      </div>

      <div className="flex items-center gap-2">
        <select value={service} onChange={e => setService(e.target.value)}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {SERVICES.map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s || 'all services'}</option>)}
        </select>
        <span className="text-[12px] text-white/40">{items.length} recorded</span>
      </div>

      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-left" style={{ background: 'rgba(255,255,255,0.02)', color: 'rgba(255,255,255,0.4)' }}>
              <th className="font-semibold px-3 py-2.5">Service</th>
              <th className="font-semibold px-3 py-2.5">Commit</th>
              <th className="font-semibold px-3 py-2.5">Status</th>
              <th className="font-semibold px-3 py-2.5">Actor</th>
              <th className="font-semibold px-3 py-2.5">Started</th>
              <th className="font-semibold px-3 py-2.5">Note</th>
            </tr>
          </thead>
          <tbody>
            {loading && items.length === 0 ? (
              <tr><td colSpan={6} className="px-3 py-8 text-center text-white/40">
                <Loader2 className="w-4 h-4 animate-spin inline" /></td></tr>
            ) : items.length === 0 ? (
              <tr><td colSpan={6} className="px-3 py-8 text-center text-white/35">No deploys recorded yet — use the button above to log one.</td></tr>
            ) : items.map(d => {
              const c = STATUS_COLOR[d.status] ?? 'rgba(255,255,255,0.5)'
              return (
                <tr key={d.id} className="border-t border-white/[0.04]">
                  <td className="px-3 py-2 text-white/80 capitalize">{d.service}</td>
                  <td className="px-3 py-2 font-mono text-[11px] text-white/85">
                    <a href={`https://github.com/dylanleonard-1/webhound/commit/${d.sha}`} target="_blank"
                       rel="noreferrer" className="hover:text-[color:#8BFF3E] transition-colors">
                      {d.sha.slice(0, 10)}
                    </a>
                    {currentSha && d.sha.startsWith(currentSha.slice(0, 10)) && (
                      <span className="ml-1.5 text-[9px] font-bold px-1 py-0.5 rounded uppercase"
                            style={{ background: 'rgba(139,255,62,0.1)', color: LIME }}>live</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <span className="text-[11px] font-semibold capitalize" style={{ color: c }}>{d.status.replace('_', ' ')}</span>
                  </td>
                  <td className="px-3 py-2 text-white/55">{d.actor ?? 'system'}</td>
                  <td className="px-3 py-2 text-white/50">{d.started_at ? new Date(d.started_at).toLocaleString() : '—'}</td>
                  <td className="px-3 py-2 text-white/60 max-w-[280px] truncate">{d.note ?? <span className="text-white/25">—</span>}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {creating && <NewDeployDialog onClose={() => setCreating(false)} onRecorded={load} />}
    </div>
  )
}
