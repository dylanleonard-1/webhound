'use client'

// Threat Intelligence — manage known-bad indicators (IP / domain / URL /
// hash / CVE) that the fraud evaluator + scanner consult. Reads are
// READ_ONLY+, manual add is ANALYST+, delete + bulk import are ADMIN.

import { useCallback, useEffect, useState } from 'react'
import {
  Radar, Loader2, Search, Plus, Upload, Trash2, X, Target,
} from 'lucide-react'
import { api, type ThreatIndicatorRow } from '@/lib/api'
import { useInternalMe } from '../layout'

const LIME = '#8BFF3E'
const ROLE_RANK: Record<string, number> = {
  none: 0, read_only: 10, billing: 20, support: 20, developer: 20,
  analyst: 30, admin: 90, super_admin: 100,
}

const KINDS = ['', 'ip', 'domain', 'url', 'hash', 'cve'] as const
const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'] as const
const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6',
}

function SevPill({ s }: { s: string }) {
  const c = SEV_COLOR[s] ?? '#6b7280'
  return (
    <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
          style={{ background: `${c}1a`, color: c, border: `1px solid ${c}33` }}>{s}</span>
  )
}

function AddDialog({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const [kind, setKind] = useState('ip')
  const [value, setValue] = useState('')
  const [source, setSource] = useState('manual')
  const [severity, setSeverity] = useState('medium')
  const [confidence, setConfidence] = useState(80)
  const [notes, setNotes] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const submit = async () => {
    if (!value.trim()) return
    setBusy(true); setErr(null)
    try {
      await api.internal.addThreatIndicator({
        kind, value: value.trim(), source, severity,
        confidence: Math.max(0, Math.min(100, confidence)),
        notes: notes.trim() || null,
      })
      onAdded(); onClose()
    } catch (e) { setErr((e as Error).message || 'Failed to add') }
    finally { setBusy(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="w-full max-w-[460px] rounded-xl p-5 bg-[#070b13] border border-white/10"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-[14px] font-bold text-white">Add indicator</h3>
          <button onClick={onClose} className="p-1 rounded hover:bg-white/5"><X className="w-4 h-4 text-white/60" /></button>
        </div>
        <div className="space-y-2.5">
          <div className="grid grid-cols-2 gap-2">
            <select value={kind} onChange={e => setKind(e.target.value)}
                    className="px-3 py-2 rounded-lg text-[12px] text-white/85 outline-none"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {KINDS.filter(k => k).map(k => <option key={k} value={k} className="bg-[#0b0f17]">{k}</option>)}
            </select>
            <select value={severity} onChange={e => setSeverity(e.target.value)}
                    className="px-3 py-2 rounded-lg text-[12px] text-white/85 outline-none"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {SEVERITIES.filter(s => s).map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s}</option>)}
            </select>
          </div>
          <input value={value} onChange={e => setValue(e.target.value)} placeholder="value (e.g. 1.2.3.4 or evil.example.com)"
                 className="w-full px-3 py-2 rounded-lg bg-transparent outline-none text-[12px] text-white/90 placeholder:text-white/30 font-mono"
                 style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
          <div className="grid grid-cols-2 gap-2">
            <input value={source} onChange={e => setSource(e.target.value)} placeholder="source"
                   className="px-3 py-2 rounded-lg bg-transparent outline-none text-[12px] text-white/85 placeholder:text-white/30"
                   style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
            <input type="number" min={0} max={100} value={confidence}
                   onChange={e => setConfidence(parseInt(e.target.value || '0', 10))}
                   placeholder="confidence 0-100"
                   className="px-3 py-2 rounded-lg bg-transparent outline-none text-[12px] text-white/85"
                   style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
          </div>
          <textarea value={notes} onChange={e => setNotes(e.target.value)} placeholder="Notes (optional)"
                    rows={2}
                    className="w-full px-3 py-2 rounded-lg bg-transparent outline-none text-[12px] text-white/85 placeholder:text-white/30 resize-y"
                    style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
          {err && <div className="text-[11px] text-red-400">{err}</div>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose} className="px-3 py-1.5 rounded-lg text-[12px] text-white/65"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>Cancel</button>
            <button disabled={!value.trim() || busy} onClick={submit}
                    className="px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                    style={{ background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.3)' }}>
              {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Add'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function ImportDialog({ onClose, onImported }: { onClose: () => void; onImported: () => void }) {
  const [source, setSource] = useState('')
  const [text, setText] = useState('')
  const [defaultKind, setDefaultKind] = useState('ip')
  const [defaultSeverity, setDefaultSeverity] = useState('medium')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [result, setResult] = useState<{ created: number; updated: number; skipped: number } | null>(null)

  const submit = async () => {
    setBusy(true); setErr(null); setResult(null)
    try {
      // One value per line. Each line becomes { kind: defaultKind, value }.
      const rows = text.split('\n').map(l => l.trim()).filter(Boolean)
        .map(value => ({ kind: defaultKind, value }))
      if (!source.trim() || rows.length === 0) {
        setErr('Source and at least one indicator required'); setBusy(false); return
      }
      const r = await api.internal.importThreatFeed({
        source: source.trim(), rows, default_severity: defaultSeverity,
      })
      setResult({ created: r.created, updated: r.updated, skipped: r.skipped })
      onImported()
    } catch (e) { setErr((e as Error).message || 'Import failed') }
    finally { setBusy(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.6)' }} onClick={onClose}>
      <div className="w-full max-w-[540px] rounded-xl p-5 bg-[#070b13] border border-white/10"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-[14px] font-bold text-white">Bulk import feed</h3>
          <button onClick={onClose} className="p-1 rounded hover:bg-white/5"><X className="w-4 h-4 text-white/60" /></button>
        </div>
        <div className="space-y-2.5">
          <div className="grid grid-cols-3 gap-2">
            <input value={source} onChange={e => setSource(e.target.value)} placeholder="feed name (e.g. alienvault)"
                   className="px-3 py-2 rounded-lg bg-transparent outline-none text-[12px] text-white/90 placeholder:text-white/30"
                   style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
            <select value={defaultKind} onChange={e => setDefaultKind(e.target.value)}
                    className="px-3 py-2 rounded-lg text-[12px] text-white/85 outline-none"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {KINDS.filter(k => k).map(k => <option key={k} value={k} className="bg-[#0b0f17]">{k}</option>)}
            </select>
            <select value={defaultSeverity} onChange={e => setDefaultSeverity(e.target.value)}
                    className="px-3 py-2 rounded-lg text-[12px] text-white/85 outline-none"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {SEVERITIES.filter(s => s).map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s}</option>)}
            </select>
          </div>
          <textarea value={text} onChange={e => setText(e.target.value)}
                    placeholder="One indicator per line…"
                    rows={8}
                    className="w-full px-3 py-2 rounded-lg bg-transparent outline-none text-[11px] text-white/85 placeholder:text-white/30 resize-y font-mono"
                    style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
          {result && (
            <div className="text-[12px] rounded p-2"
                 style={{ background: 'rgba(139,255,62,0.06)', color: LIME, border: '1px solid rgba(139,255,62,0.2)' }}>
              created {result.created} · updated {result.updated} · skipped {result.skipped}
            </div>
          )}
          {err && <div className="text-[11px] text-red-400">{err}</div>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose} className="px-3 py-1.5 rounded-lg text-[12px] text-white/65"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>Done</button>
            <button disabled={!source.trim() || !text.trim() || busy} onClick={submit}
                    className="px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                    style={{ background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.3)' }}>
              {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Import'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function MatchProbe() {
  const [kind, setKind] = useState('ip')
  const [value, setValue] = useState('')
  const [result, setResult] = useState<{ hits: ThreatIndicatorRow[]; count: number } | null>(null)
  const [busy, setBusy] = useState(false)

  const probe = async () => {
    if (!value.trim()) return
    setBusy(true)
    try { setResult(await api.internal.threatMatch(kind, value.trim())) }
    finally { setBusy(false) }
  }

  return (
    <div className="rounded-xl p-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)' }}>
      <div className="flex items-center gap-2 mb-2">
        <Target className="w-4 h-4" style={{ color: LIME }} />
        <span className="text-[12px] font-semibold text-white">Match probe</span>
        <span className="text-[11px] text-white/40">— does this atom appear in any feed?</span>
      </div>
      <div className="flex items-center gap-2">
        <select value={kind} onChange={e => setKind(e.target.value)}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/85 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {KINDS.filter(k => k).map(k => <option key={k} value={k} className="bg-[#0b0f17]">{k}</option>)}
        </select>
        <input value={value} onChange={e => setValue(e.target.value)}
               onKeyDown={e => { if (e.key === 'Enter') probe() }}
               placeholder="value to probe…"
               className="flex-1 px-3 py-1.5 rounded-lg bg-transparent outline-none text-[12px] text-white/90 placeholder:text-white/30 font-mono"
               style={{ border: '1px solid rgba(255,255,255,0.08)' }} />
        <button disabled={!value.trim() || busy} onClick={probe}
                className="px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.8)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Probe'}
        </button>
      </div>
      {result && (
        <div className="mt-2 text-[12px]">
          {result.count === 0 ? (
            <span className="text-white/50">No hits — atom is clean across {result.count} feeds.</span>
          ) : (
            <div className="space-y-1">
              <div style={{ color: '#ef4444' }} className="font-semibold">⚠ {result.count} hit{result.count > 1 ? 's' : ''}:</div>
              {result.hits.map(h => (
                <div key={h.id} className="flex items-center gap-2">
                  <SevPill s={h.severity} />
                  <span className="text-white/80">{h.source}</span>
                  <span className="text-white/40">conf {h.confidence}</span>
                  {h.notes && <span className="text-white/55 truncate">— {h.notes}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function ThreatIntelPage() {
  const me = useInternalMe()
  const role = me?.role ?? 'none'
  const isOp = (ROLE_RANK[role] ?? 0) >= ROLE_RANK.analyst
  const isAdmin = (ROLE_RANK[role] ?? 0) >= ROLE_RANK.admin

  const [rows, setRows] = useState<ThreatIndicatorRow[]>([])
  const [total, setTotal] = useState(0)
  const [kind, setKind] = useState('')
  const [severity, setSeverity] = useState('')
  const [q, setQ] = useState('')
  const [includeExpired, setIncludeExpired] = useState(false)
  const [loading, setLoading] = useState(true)
  const [adding, setAdding] = useState(false)
  const [importing, setImporting] = useState(false)

  const load = useCallback(() => {
    setLoading(true)
    api.internal.threatIndicators({
      kind: kind || undefined,
      severity: severity || undefined,
      q: q || undefined,
      include_expired: includeExpired,
      limit: 200,
    }).then(r => { setRows(r.items); setTotal(r.total) })
      .finally(() => setLoading(false))
  }, [kind, severity, q, includeExpired])
  useEffect(() => { load() }, [load])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Radar className="w-5 h-5" style={{ color: LIME }} />
        <h1 className="text-[19px] font-bold text-white">Threat Intelligence</h1>
        <span className="text-[12px] text-white/40">· {total.toLocaleString()} indicators</span>
        {isOp && (
          <button onClick={() => setAdding(true)} className="ml-auto flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold"
                  style={{ background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.3)' }}>
            <Plus className="w-3 h-3" /> Add
          </button>
        )}
        {isAdmin && (
          <button onClick={() => setImporting(true)} className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold"
                  style={{ background: 'rgba(255,255,255,0.03)', color: 'rgba(255,255,255,0.8)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <Upload className="w-3 h-3" /> Import feed
          </button>
        )}
      </div>

      <MatchProbe />

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg flex-1 min-w-[260px]"
             style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <Search className="w-3.5 h-3.5 text-white/35" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search value…"
                 className="bg-transparent outline-none text-[12px] text-white/90 w-full placeholder:text-white/30 font-mono" />
        </div>
        <select value={kind} onChange={e => setKind(e.target.value)}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {KINDS.map(k => <option key={k} value={k} className="bg-[#0b0f17]">{k || 'all kinds'}</option>)}
        </select>
        <select value={severity} onChange={e => setSeverity(e.target.value)}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {SEVERITIES.map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s || 'all severities'}</option>)}
        </select>
        <label className="flex items-center gap-1.5 text-[12px] text-white/65 cursor-pointer">
          <input type="checkbox" checked={includeExpired} onChange={e => setIncludeExpired(e.target.checked)} />
          show expired
        </label>
      </div>

      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-left" style={{ background: 'rgba(255,255,255,0.02)', color: 'rgba(255,255,255,0.4)' }}>
              <th className="font-semibold px-3 py-2.5">Severity</th>
              <th className="font-semibold px-3 py-2.5">Kind</th>
              <th className="font-semibold px-3 py-2.5">Value</th>
              <th className="font-semibold px-3 py-2.5">Source</th>
              <th className="font-semibold px-3 py-2.5">Conf</th>
              <th className="font-semibold px-3 py-2.5">Last seen</th>
              {isAdmin && <th className="px-3 py-2.5 w-8"></th>}
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <tr><td colSpan={7} className="px-3 py-8 text-center text-white/40">
                <Loader2 className="w-4 h-4 animate-spin inline" /></td></tr>
            ) : rows.length === 0 ? (
              <tr><td colSpan={7} className="px-3 py-8 text-center text-white/35">No indicators — add one or import a feed.</td></tr>
            ) : rows.map(r => (
              <tr key={r.id} className="border-t border-white/[0.04]">
                <td className="px-3 py-2"><SevPill s={r.severity} /></td>
                <td className="px-3 py-2 text-white/65 uppercase font-mono text-[10px]">{r.kind}</td>
                <td className="px-3 py-2 font-mono text-white/90 max-w-[320px] truncate">{r.value}</td>
                <td className="px-3 py-2 text-white/55">{r.source}</td>
                <td className="px-3 py-2 text-white/55">{r.confidence}</td>
                <td className="px-3 py-2 text-white/45">{r.last_seen_at ? new Date(r.last_seen_at).toLocaleDateString() : '—'}</td>
                {isAdmin && (
                  <td className="px-3 py-2 text-right">
                    <button onClick={async () => {
                      if (!confirm(`Delete indicator ${r.value}?`)) return
                      await api.internal.deleteThreatIndicator(r.id); load()
                    }}
                            className="p-1 rounded hover:bg-white/5 text-white/30 hover:text-red-400">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {adding && <AddDialog onClose={() => setAdding(false)} onAdded={load} />}
      {importing && <ImportDialog onClose={() => setImporting(false)} onImported={load} />}
    </div>
  )
}
