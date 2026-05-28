'use client'

// Log Explorer + Audit browser — Splunk-style search across the application
// log store and the privileged-action audit trail. Both surfaces support
// filter, free-text search, and CSV export.

import { useCallback, useEffect, useState } from 'react'
import {
  FileSearch, Loader2, Search, Download, ChevronDown, ChevronRight, ScrollText,
} from 'lucide-react'
import {
  api, getStoredToken, type LogRow, type AuditRow,
  type LogSearchParams, type AuditSearchParams,
} from '@/lib/api'

const LIME = '#8BFF3E'
const BASE_URL = (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_API_URL) || 'https://api.webhoundsecurity.com'

const SEVERITY_COLOR: Record<string, string> = {
  debug: '#6b7280', info: '#3b82f6', warning: '#f59e0b',
  error: '#ef4444', critical: '#a855f7',
}
const SEVERITIES = ['', 'debug', 'info', 'warning', 'error', 'critical']
const SOURCES = ['', 'api', 'worker', 'web', 'scanner']

function SevPill({ s }: { s: string }) {
  const c = SEVERITY_COLOR[s] ?? '#6b7280'
  return (
    <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
          style={{ background: `${c}1a`, color: c, border: `1px solid ${c}33` }}>{s}</span>
  )
}

async function downloadCsv(path: string, filename: string) {
  const tok = getStoredToken()
  const r = await fetch(`${BASE_URL}${path}`, {
    headers: tok ? { Authorization: `Bearer ${tok}` } : {},
  })
  if (!r.ok) return
  const blob = await r.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename
  document.body.appendChild(a); a.click(); a.remove()
  URL.revokeObjectURL(url)
}

function LogsPanel() {
  const [rows, setRows] = useState<LogRow[]>([])
  const [total, setTotal] = useState(0)
  const [source, setSource] = useState('')
  const [severity, setSeverity] = useState('')
  const [severityAtLeast, setSAL] = useState('')
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState<string | null>(null)

  const params: LogSearchParams = {
    source: source || undefined,
    severity: severity || undefined,
    severity_at_least: severityAtLeast || undefined,
    q: q || undefined,
    limit: 200,
  }

  const load = useCallback(() => {
    setLoading(true)
    api.internal.searchLogs(params)
      .then(r => { setRows(r.items); setTotal(r.total) })
      .finally(() => setLoading(false))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source, severity, severityAtLeast, q])
  useEffect(() => { load() }, [load])

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg flex-1 min-w-[260px]"
             style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <Search className="w-3.5 h-3.5 text-white/35" />
          <input value={q} onChange={e => setQ(e.target.value)}
                 placeholder="Search message text…"
                 className="bg-transparent outline-none text-[12px] text-white/90 w-full placeholder:text-white/30" />
        </div>
        <select value={source} onChange={e => setSource(e.target.value)}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {SOURCES.map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s || 'all sources'}</option>)}
        </select>
        <select value={severity} onChange={e => { setSeverity(e.target.value); if (e.target.value) setSAL('') }}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {SEVERITIES.map(s => <option key={s} value={s} className="bg-[#0b0f17]">{s || 'any severity'}</option>)}
        </select>
        <select value={severityAtLeast} onChange={e => { setSAL(e.target.value); if (e.target.value) setSeverity('') }}
                className="px-3 py-1.5 rounded-lg text-[12px] text-white/80 outline-none"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <option value="" className="bg-[#0b0f17]">severity ≥ any</option>
          {SEVERITIES.filter(s => s).map(s => <option key={s} value={s} className="bg-[#0b0f17]">≥ {s}</option>)}
        </select>
        <span className="text-[12px] text-white/40">{total.toLocaleString()} match</span>
        <button onClick={() => downloadCsv(api.internal.logsCsvUrl({ ...params, limit: 5000 }), 'logs.csv')}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold"
                style={{ background: 'rgba(255,255,255,0.03)', color: 'rgba(255,255,255,0.7)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <Download className="w-3 h-3" /> Export CSV
        </button>
      </div>

      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
        {loading && rows.length === 0 ? (
          <div className="py-10 text-center"><Loader2 className="w-4 h-4 animate-spin inline text-white/40" /></div>
        ) : rows.length === 0 ? (
          <div className="py-10 text-center text-[13px] text-white/35">No log entries match. 🌅</div>
        ) : (
          <div className="divide-y divide-white/[0.04]">
            {rows.map(r => {
              const open = expanded === r.id
              const hasContext = Object.keys(r.context ?? {}).length > 0
              return (
                <div key={r.id}
                     className="px-3 py-2 cursor-pointer hover:bg-white/[0.02]"
                     onClick={() => setExpanded(open ? null : r.id)}>
                  <div className="flex items-center gap-2 text-[12px]">
                    {hasContext ? (open ? <ChevronDown className="w-3 h-3 text-white/40" /> : <ChevronRight className="w-3 h-3 text-white/40" />) : <span className="w-3" />}
                    <span className="text-white/45 font-mono w-[170px] shrink-0">{r.timestamp ? new Date(r.timestamp).toLocaleString() : '—'}</span>
                    <SevPill s={r.severity} />
                    <span className="font-mono text-[10px] text-white/40 uppercase w-14">{r.source}</span>
                    <span className="text-white/85 truncate flex-1">{r.message}</span>
                    {r.request_id && <span className="font-mono text-[10px] text-white/30">{r.request_id.slice(0, 8)}</span>}
                  </div>
                  {open && hasContext && (
                    <pre className="ml-5 mt-1.5 text-[11px] rounded p-2 overflow-auto font-mono"
                         style={{ background: 'rgba(255,255,255,0.02)', color: 'rgba(255,255,255,0.65)' }}>
                      {JSON.stringify(r.context, null, 2)}
                    </pre>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

function AuditPanel() {
  const [rows, setRows] = useState<AuditRow[]>([])
  const [total, setTotal] = useState(0)
  const [action, setAction] = useState('')
  const [actor, setActor] = useState('')
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState<string | null>(null)

  const params: AuditSearchParams = {
    action: action || undefined,
    actor_email: actor || undefined,
    q: q || undefined,
    limit: 200,
  }

  const load = useCallback(() => {
    setLoading(true)
    api.internal.searchAudit(params)
      .then(r => { setRows(r.items); setTotal(r.total) })
      .finally(() => setLoading(false))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [action, actor, q])
  useEffect(() => { load() }, [load])

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg flex-1 min-w-[260px]"
             style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <Search className="w-3.5 h-3.5 text-white/35" />
          <input value={q} onChange={e => setQ(e.target.value)}
                 placeholder="Search action / actor / target id…"
                 className="bg-transparent outline-none text-[12px] text-white/90 w-full placeholder:text-white/30" />
        </div>
        <input value={action} onChange={e => setAction(e.target.value)}
               placeholder="exact action (e.g. customer.suspend)"
               className="px-3 py-1.5 rounded-lg text-[12px] text-white/85 outline-none w-[260px]"
               style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }} />
        <input value={actor} onChange={e => setActor(e.target.value)}
               placeholder="actor email"
               className="px-3 py-1.5 rounded-lg text-[12px] text-white/85 outline-none w-[220px]"
               style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }} />
        <span className="text-[12px] text-white/40">{total.toLocaleString()} match</span>
        <button onClick={() => downloadCsv(api.internal.auditCsvUrl({ ...params, limit: 5000 }), 'audit.csv')}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold"
                style={{ background: 'rgba(255,255,255,0.03)', color: 'rgba(255,255,255,0.7)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <Download className="w-3 h-3" /> Export CSV
        </button>
      </div>

      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
        {loading && rows.length === 0 ? (
          <div className="py-10 text-center"><Loader2 className="w-4 h-4 animate-spin inline text-white/40" /></div>
        ) : rows.length === 0 ? (
          <div className="py-10 text-center text-[13px] text-white/35">No audit entries match.</div>
        ) : (
          <div className="divide-y divide-white/[0.04]">
            {rows.map(r => {
              const open = expanded === r.id
              const hasDetail = Object.keys(r.detail ?? {}).length > 0
              return (
                <div key={r.id}
                     className="px-3 py-2 cursor-pointer hover:bg-white/[0.02]"
                     onClick={() => setExpanded(open ? null : r.id)}>
                  <div className="flex items-center gap-2 text-[12px]">
                    {hasDetail ? (open ? <ChevronDown className="w-3 h-3 text-white/40" /> : <ChevronRight className="w-3 h-3 text-white/40" />) : <span className="w-3" />}
                    <span className="text-white/45 font-mono w-[170px] shrink-0">{r.at ? new Date(r.at).toLocaleString() : '—'}</span>
                    <span className="font-mono px-1.5 py-0.5 rounded text-[10px]"
                          style={{ background: 'rgba(139,255,62,0.08)', color: LIME }}>{r.action}</span>
                    <span className="text-white/70 truncate flex-1">
                      {r.actor_email ?? 'system'}
                      {r.target_type && <span className="text-white/35"> · {r.target_type}{r.target_id ? `:${r.target_id.slice(0, 8)}` : ''}</span>}
                    </span>
                    {r.ip_address && <span className="font-mono text-[10px] text-white/30">{r.ip_address}</span>}
                  </div>
                  {open && hasDetail && (
                    <pre className="ml-5 mt-1.5 text-[11px] rounded p-2 overflow-auto font-mono"
                         style={{ background: 'rgba(255,255,255,0.02)', color: 'rgba(255,255,255,0.65)' }}>
                      {JSON.stringify(r.detail, null, 2)}
                    </pre>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

export default function LogsPage() {
  const [tab, setTab] = useState<'logs' | 'audit'>('logs')

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <FileSearch className="w-5 h-5" style={{ color: LIME }} />
        <h1 className="text-[19px] font-bold text-white">Log Explorer</h1>
      </div>

      <div className="flex items-center gap-1">
        {(['logs', 'audit'] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-medium transition-colors"
                  style={tab === t
                    ? { background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.2)' }
                    : { color: 'rgba(255,255,255,0.5)', border: '1px solid transparent' }}>
            {t === 'logs' ? <FileSearch className="w-3.5 h-3.5" /> : <ScrollText className="w-3.5 h-3.5" />}
            {t === 'logs' ? 'Application logs' : 'Audit trail'}
          </button>
        ))}
      </div>

      {tab === 'logs' ? <LogsPanel /> : <AuditPanel />}
    </div>
  )
}
