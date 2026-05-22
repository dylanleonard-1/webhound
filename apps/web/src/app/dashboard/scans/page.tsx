'use client'

import { useEffect, useState, useCallback } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { ScanLine, Clock, CheckCircle, XCircle, Loader2, ChevronRight, RefreshCw, Plus, Filter } from 'lucide-react'
import { api, type ScanJobResponse, type ScanStatus } from '@/lib/api'
import { LoadingState } from '@/components/loading-state'
import { ErrorState } from '@/components/error-state'
import { cn } from '@/lib/utils'

const STATUS: Record<ScanStatus, { label: string; color: string; bg: string; border: string; icon: React.FC<{ className?: string; style?: React.CSSProperties }> }> = {
  queued:    { label: 'Queued',    color: '#9ca3af', bg: 'rgba(107,114,128,0.08)', border: 'rgba(107,114,128,0.2)',  icon: Clock       },
  running:   { label: 'Running',   color: '#4F9CF9', bg: 'rgba(79,156,249,0.1)',   border: 'rgba(79,156,249,0.25)',  icon: Loader2     },
  completed: { label: 'Completed', color: '#8BFF3E', bg: 'rgba(139,255,62,0.08)',  border: 'rgba(139,255,62,0.22)', icon: CheckCircle },
  failed:    { label: 'Failed',    color: '#ef4444', bg: 'rgba(239,68,68,0.1)',    border: 'rgba(239,68,68,0.25)',  icon: XCircle     },
  cancelled: { label: 'Cancelled', color: '#6b7280', bg: 'rgba(107,114,128,0.06)', border: 'rgba(107,114,128,0.15)', icon: XCircle    },
}

function timeAgo(ts: string) {
  const diff = Date.now() - new Date(ts).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

function formatDuration(start: string | null, end: string | null) {
  if (!start || !end) return null
  const ms = new Date(end).getTime() - new Date(start).getTime()
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
}

const PROFILE_COLOR: Record<string, string> = {
  quick:    '#22d3ee',
  standard: '#8BFF3E',
  deep:     '#a78bfa',
  monitor:  '#f97316',
}

export default function ScansPage() {
  const [items, setItems] = useState<ScanJobResponse[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState<ScanStatus | 'all'>('all')

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.scanJobs.list({ limit: 100 })
      setItems(res.items)
      setTotal(res.total)
    } catch {
      setError('Failed to load scans.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const filtered = filter === 'all' ? items : items.filter(i => i.status === filter)
  const counts = items.reduce<Record<string, number>>((acc, i) => {
    acc[i.status] = (acc[i.status] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
      <div className="max-w-[1100px] mx-auto px-4 py-5 sm:px-6 sm:py-8 space-y-6">

        {/* Header */}
        <motion.div
          className="flex items-start justify-between"
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}
        >
          <div>
            <h1 className="text-[22px] font-bold text-white tracking-tight">Scans</h1>
            <p className="text-[13px] mt-0.5" style={{ color: 'rgba(255,255,255,0.35)' }}>
              {loading ? '—' : `${total} scan${total !== 1 ? 's' : ''} total`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={load}
              className="w-8 h-8 flex items-center justify-center rounded-[8px] transition-all"
              style={{ border: '1px solid rgba(255,255,255,0.07)', color: 'rgba(255,255,255,0.35)' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.7)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.35)')}
              title="Refresh"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
            <Link href="/dashboard/websites/new">
              <button
                className="flex items-center gap-1.5 px-3 py-[7px] rounded-[8px] text-[12px] font-semibold transition-all"
                style={{ background: 'rgba(139,255,62,0.1)', border: '1px solid rgba(139,255,62,0.3)', color: '#8BFF3E' }}
                onMouseEnter={e => { const el = e.currentTarget; el.style.background = 'rgba(139,255,62,0.16)'; el.style.borderColor = 'rgba(139,255,62,0.5)' }}
                onMouseLeave={e => { const el = e.currentTarget; el.style.background = 'rgba(139,255,62,0.1)'; el.style.borderColor = 'rgba(139,255,62,0.3)' }}
              >
                <Plus className="w-3.5 h-3.5" />
                New Scan
              </button>
            </Link>
          </div>
        </motion.div>

        {/* Filter pills */}
        <motion.div
          className="flex items-center gap-2 flex-wrap"
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.05 }}
        >
          {(['all', 'running', 'completed', 'failed', 'queued', 'cancelled'] as const).map(s => {
            const active = filter === s
            const cfg = s !== 'all' ? STATUS[s] : null
            const count = s === 'all' ? items.length : (counts[s] ?? 0)
            return (
              <button
                key={s}
                onClick={() => setFilter(s)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold transition-all duration-150"
                style={{
                  background:   active ? (cfg?.bg ?? 'rgba(255,255,255,0.08)') : 'rgba(255,255,255,0.03)',
                  border:       active ? `1px solid ${cfg?.border ?? 'rgba(255,255,255,0.15)'}` : '1px solid rgba(255,255,255,0.06)',
                  color:        active ? (cfg?.color ?? '#ffffff') : 'rgba(255,255,255,0.35)',
                }}
              >
                {s === 'all' ? 'All' : STATUS[s].label}
                {count > 0 && (
                  <span
                    className="px-1 rounded-full text-[9px] font-black"
                    style={{ background: active ? 'rgba(255,255,255,0.15)' : 'rgba(255,255,255,0.06)' }}
                  >
                    {count}
                  </span>
                )}
              </button>
            )
          })}
        </motion.div>

        {/* List */}
        {loading ? (
          <LoadingState />
        ) : error ? (
          <ErrorState message={error} onRetry={load} />
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-4">
            <div className="w-12 h-12 rounded-[12px] flex items-center justify-center" style={{ background: 'rgba(139,255,62,0.06)', border: '1px solid rgba(139,255,62,0.12)' }}>
              <ScanLine className="w-5 h-5" style={{ color: '#8BFF3E' }} />
            </div>
            <p className="text-[14px] font-semibold text-white">{filter === 'all' ? 'No scans yet' : `No ${filter} scans`}</p>
            <Link href="/dashboard/websites/new">
              <button className="px-4 py-2 rounded-[8px] text-[12px] font-semibold" style={{ background: 'rgba(139,255,62,0.1)', border: '1px solid rgba(139,255,62,0.3)', color: '#8BFF3E' }}>
                Start a scan
              </button>
            </Link>
          </div>
        ) : (
          <motion.div
            className="rounded-[12px] overflow-hidden"
            style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.1 }}
          >
            {filtered.map((job, i) => {
              const s = STATUS[job.status] ?? STATUS.queued
              const Icon = s.icon
              const dur = formatDuration(job.started_at, job.completed_at)
              const profileColor = PROFILE_COLOR[job.profile] ?? '#9ca3af'
              return (
                <Link
                  key={job.id}
                  href={`/dashboard/scans/${job.id}`}
                  className="flex items-center gap-3 sm:gap-4 px-3 sm:px-5 py-3.5 group transition-colors"
                  style={{
                    borderBottom: i < filtered.length - 1 ? '1px solid rgba(255,255,255,0.04)' : undefined,
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.02)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  {/* Status icon */}
                  <div className="w-8 h-8 rounded-[8px] flex items-center justify-center flex-shrink-0" style={{ background: s.bg }}>
                    <Icon
                      className={cn('w-3.5 h-3.5', job.status === 'running' && 'animate-spin')}
                      style={{ color: s.color }}
                    />
                  </div>

                  {/* URL + meta */}
                  <div className="flex-1 min-w-0">
                    <span className="text-[13px] font-mono font-medium text-white block truncate">
                      {job.requested_url}
                    </span>
                    <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.28)' }}>
                      {timeAgo(job.created_at)}
                      {dur && <> · {dur}</>}
                      {job.error_message && <span className="ml-1.5 text-[#ef4444]">— {job.error_message}</span>}
                    </span>
                  </div>

                  {/* Badges — profile hidden on mobile to keep the row from wrapping */}
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span
                      className="hidden sm:inline-block px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wide"
                      style={{ background: `${profileColor}18`, color: profileColor, border: `1px solid ${profileColor}35` }}
                    >
                      {job.profile}
                    </span>
                    <span
                      className="px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wide"
                      style={{ background: s.bg, color: s.color, border: `1px solid ${s.border}` }}
                    >
                      {s.label}
                    </span>
                    <ChevronRight className="hidden sm:block w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: 'rgba(255,255,255,0.3)' }} />
                  </div>
                </Link>
              )
            })}
          </motion.div>
        )}
      </div>
    </div>
  )
}
