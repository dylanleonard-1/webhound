'use client'

import { useEffect, useMemo, useState } from 'react'
import {
  FileSearch, GitBranch, FormInput, Plug, Boxes, Globe2, Route, ShieldCheck,
  ChevronRight, ChevronDown, AlertTriangle, Ban, Map,
} from 'lucide-react'
import { api, type VisibilityReport } from '@/lib/api'

const ACCENT = '#8BFF3E'

function Stat({ icon: Icon, label, value, accent = ACCENT }: {
  icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }>
  label: string
  value: number | string
  accent?: string
}) {
  return (
    <div
      className="rounded-[10px] px-3 py-2.5 flex items-center gap-2.5"
      style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}
    >
      <div
        className="w-7 h-7 rounded-[8px] flex items-center justify-center flex-shrink-0"
        style={{ background: `${accent}14`, border: `1px solid ${accent}30` }}
      >
        <Icon className="w-3.5 h-3.5" style={{ color: accent }} />
      </div>
      <div className="min-w-0">
        <div className="text-[15px] font-bold text-white leading-none">{value}</div>
        <div className="text-[10px] mt-1" style={{ color: 'rgba(255,255,255,0.4)' }}>{label}</div>
      </div>
    </div>
  )
}

function ScoreRing({ score }: { score: number }) {
  const color = score >= 80 ? ACCENT : score >= 55 ? '#f5c451' : '#f97316'
  const r = 26
  const c = 2 * Math.PI * r
  const off = c * (1 - Math.max(0, Math.min(100, score)) / 100)
  return (
    <div className="relative w-[68px] h-[68px] flex-shrink-0">
      <svg width="68" height="68" className="-rotate-90">
        <circle cx="34" cy="34" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="6" />
        <circle cx="34" cy="34" r={r} fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={c} strokeDashoffset={off} strokeLinecap="round" />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-[18px] font-bold leading-none" style={{ color }}>{score}</span>
        <span className="text-[8px] mt-0.5" style={{ color: 'rgba(255,255,255,0.4)' }}>/ 100</span>
      </div>
    </div>
  )
}

function Bars({ data, accent = ACCENT }: { data: Record<string, number>; accent?: string }) {
  const entries = Object.entries(data || {}).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1])
  if (entries.length === 0) return null
  const max = Math.max(...entries.map(([, v]) => v))
  return (
    <div className="space-y-1.5">
      {entries.map(([k, v]) => (
        <div key={k} className="flex items-center gap-2">
          <span className="text-[10px] w-28 flex-shrink-0 truncate" style={{ color: 'rgba(255,255,255,0.55)' }}>{k}</span>
          <div className="flex-1 h-[6px] rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
            <div className="h-full rounded-full" style={{ width: `${(v / max) * 100}%`, background: accent }} />
          </div>
          <span className="text-[10px] font-mono w-7 text-right" style={{ color: 'rgba(255,255,255,0.7)' }}>{v}</span>
        </div>
      ))}
    </div>
  )
}

const STATUS_COLOR: Record<string, string> = {
  crawled: ACCENT, skipped: '#f97316', failed: '#ef4444', queued: '#4F9CF9', pending: 'rgba(255,255,255,0.4)',
}

function shortPath(url: string): string {
  try {
    const u = new URL(url)
    return (u.pathname || '/') + (u.search || '')
  } catch { return url }
}

function TreeNode({ url, edges, statusByUrl, depth }: {
  url: string
  edges: Record<string, string[]>
  statusByUrl: Record<string, string>
  depth: number
}) {
  const children = edges[url] || []
  const [open, setOpen] = useState(depth < 1)
  const status = statusByUrl[url] || 'pending'
  const hasKids = children.length > 0
  return (
    <div>
      <div className="flex items-center gap-1.5 py-0.5" style={{ paddingLeft: depth * 14 }}>
        {hasKids ? (
          <button onClick={() => setOpen(o => !o)} className="flex-shrink-0">
            {open ? <ChevronDown className="w-3 h-3" style={{ color: 'rgba(255,255,255,0.4)' }} />
              : <ChevronRight className="w-3 h-3" style={{ color: 'rgba(255,255,255,0.4)' }} />}
          </button>
        ) : <span className="w-3 flex-shrink-0" />}
        <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: STATUS_COLOR[status] || 'rgba(255,255,255,0.4)' }} />
        <span className="text-[11px] font-mono truncate" style={{ color: 'rgba(255,255,255,0.7)' }} title={url}>
          {shortPath(url)}
        </span>
        {hasKids && <span className="text-[9px]" style={{ color: 'rgba(255,255,255,0.3)' }}>({children.length})</span>}
      </div>
      {open && hasKids && children.slice(0, 80).map(c => (
        <TreeNode key={c} url={c} edges={edges} statusByUrl={statusByUrl} depth={depth + 1} />
      ))}
    </div>
  )
}

export function SiteVisibilityMap({ scanResultId }: { scanResultId: string }) {
  const [report, setReport] = useState<VisibilityReport | null>(null)
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    api.scanResults.visibility(scanResultId)
      .then(setReport)
      .catch(() => setReport(null))   // 404 = scan didn't run the visibility layer
      .finally(() => setLoaded(true))
  }, [scanResultId])

  const statusByUrl = useMemo(() => {
    const m: Record<string, string> = {}
    for (const u of report?.discovered_urls || []) m[u.normalized] = u.status
    return m
  }, [report])

  if (!loaded || !report) return null   // render nothing for non-visibility scans

  const tree = report.site_graph?.page_tree
  const skipEntries = Object.entries(report.skip_reason_counts || {}).sort((a, b) => b[1] - a[1])

  return (
    <div className="space-y-3">
      {/* Section header (owned here so the whole block hides on non-visibility scans) */}
      <div className="flex items-center gap-3 mt-2 mb-1">
        <div
          className="w-7 h-7 rounded-[8px] flex items-center justify-center flex-shrink-0"
          style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
        >
          <Map className="w-3.5 h-3.5" style={{ color: ACCENT }} />
        </div>
        <div className="min-w-0">
          <h2 className="text-[13px] font-semibold text-white tracking-tight">Site Visibility Map</h2>
          <p className="text-[11px]" style={{ color: 'rgba(255,255,255,0.4)' }}>
            Everything the crawler discovered — pages, routes, forms, APIs, assets, third parties — with a coverage score and site tree.
          </p>
        </div>
        <div className="flex-1 h-px" style={{ background: 'rgba(255,255,255,0.06)' }} />
      </div>

      {/* Headline: score + coverage counts */}
      <div
        className="rounded-[12px] p-4 flex flex-col sm:flex-row gap-4 items-start"
        style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}
      >
        {report.visibility_score != null && <ScoreRing score={report.visibility_score} />}
        <div className="flex-1 grid grid-cols-2 sm:grid-cols-4 gap-2 w-full">
          <Stat icon={FileSearch} label="Pages found" value={report.pages_found} />
          <Stat icon={GitBranch} label="Pages crawled" value={report.pages_crawled} />
          <Stat icon={Route} label="JS routes" value={report.js_routes} accent="#a78bfa" />
          <Stat icon={FormInput} label="Forms" value={report.forms?.count ?? 0} accent="#4F9CF9" />
          <Stat icon={Plug} label="API endpoints" value={report.api?.count ?? 0} accent="#22d3ee" />
          <Stat icon={Boxes} label="Assets" value={report.assets?.count ?? 0} accent="#f5c451" />
          <Stat icon={Globe2} label="Third parties" value={report.third_party?.count ?? 0} accent="#f97316" />
          {report.authenticated?.enabled && (
            <Stat icon={ShieldCheck} label="Auth pages" value={report.authenticated.pages ?? 0} accent={ACCENT} />
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* Discovery sources */}
        <div className="rounded-[10px] p-3.5" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <div className="text-[11px] font-semibold text-white mb-2.5">How pages were discovered</div>
          <Bars data={report.source_counts} />
        </div>

        {/* Skip reasons */}
        <div className="rounded-[10px] p-3.5" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <div className="text-[11px] font-semibold text-white mb-2.5 flex items-center gap-1.5">
            <Ban className="w-3 h-3" style={{ color: '#f97316' }} /> Why URLs were skipped
          </div>
          {skipEntries.length === 0 ? (
            <p className="text-[11px]" style={{ color: 'rgba(255,255,255,0.4)' }}>No URLs were skipped.</p>
          ) : (
            <div className="space-y-1.5">
              {skipEntries.map(([reason, n]) => (
                <div key={reason} className="flex items-start gap-2 text-[11px]">
                  <span className="font-mono flex-shrink-0" style={{ color: '#f97316' }}>{n}</span>
                  <span style={{ color: 'rgba(255,255,255,0.55)' }}>{reason}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Limitations */}
      {report.limitations && report.limitations.length > 0 && (
        <div className="rounded-[10px] p-3.5" style={{ background: 'rgba(245,196,81,0.04)', border: '1px solid rgba(245,196,81,0.18)' }}>
          <div className="text-[11px] font-semibold mb-2 flex items-center gap-1.5" style={{ color: '#f5c451' }}>
            <AlertTriangle className="w-3 h-3" /> Coverage limitations
          </div>
          <ul className="space-y-1">
            {report.limitations.map((l, i) => (
              <li key={i} className="text-[11px] flex gap-2" style={{ color: 'rgba(255,255,255,0.6)' }}>
                <span style={{ color: '#f5c451' }}>•</span>{l}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Page tree */}
      {tree && tree.roots.length > 0 && (
        <div className="rounded-[10px] p-3.5" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <div className="text-[11px] font-semibold text-white mb-1 flex items-center gap-1.5">
            <GitBranch className="w-3 h-3" style={{ color: ACCENT }} /> Site map
            <span className="text-[10px] font-normal" style={{ color: 'rgba(255,255,255,0.35)' }}>
              {tree.node_count} pages · {tree.edge_count} links
            </span>
          </div>
          <div className="mt-2 max-h-[360px] overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
            {tree.roots.slice(0, 40).map(r => (
              <TreeNode key={r} url={r} edges={tree.edges} statusByUrl={statusByUrl} depth={0} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
