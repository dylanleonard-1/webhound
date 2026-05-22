'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import { motion } from 'framer-motion'
import {
  ArrowLeft, ScanLine, Clock, CheckCircle, XCircle,
  Loader2, AlertTriangle, Globe, BarChart2, ChevronRight,
} from 'lucide-react'
import { api, type ScanJobResponse, type ScanResultSummary } from '@/lib/api'
import { LoadingState } from '@/components/loading-state'
import { ErrorState } from '@/components/error-state'
import { cn } from '@/lib/utils'

const STATUS: Record<string, { label: string; color: string; bg: string; border: string; icon: React.FC<{ className?: string; style?: React.CSSProperties }> }> = {
  queued:    { label: 'Queued',    color: '#9ca3af', bg: 'rgba(107,114,128,0.08)', border: 'rgba(107,114,128,0.2)',  icon: Clock       },
  running:   { label: 'Running',   color: '#4F9CF9', bg: 'rgba(79,156,249,0.1)',   border: 'rgba(79,156,249,0.25)',  icon: Loader2     },
  completed: { label: 'Completed', color: '#8BFF3E', bg: 'rgba(139,255,62,0.08)',  border: 'rgba(139,255,62,0.22)', icon: CheckCircle },
  failed:    { label: 'Failed',    color: '#ef4444', bg: 'rgba(239,68,68,0.1)',    border: 'rgba(239,68,68,0.25)',  icon: XCircle     },
  cancelled: { label: 'Cancelled', color: '#6b7280', bg: 'rgba(107,114,128,0.06)', border: 'rgba(107,114,128,0.15)', icon: XCircle   },
}

const PROFILE_COLOR: Record<string, string> = {
  quick:    '#22d3ee',
  standard: '#8BFF3E',
  deep:     '#a78bfa',
  monitor:  '#f97316',
}

const POLL_INTERVAL = 3000

function formatTs(s: string | null): string | null {
  if (!s) return null
  return new Date(s).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function formatDuration(start: string | null, end: string | null): string | null {
  if (!start || !end) return null
  const ms = new Date(end).getTime() - new Date(start).getTime()
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
}

const RISK_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#8BFF3E',
  info:     '#4F9CF9',
}

interface PipelineStage {
  label: string
  sublabel?: string
  ts: string | null
  state: 'done' | 'active' | 'pending' | 'error'
}

function buildPipeline(job: ScanJobResponse): PipelineStage[] {
  const isDone = ['completed', 'failed', 'cancelled'].includes(job.status)
  const isRunning = job.status === 'running'
  return [
    {
      label: 'Queued',
      sublabel: 'Job accepted',
      ts: formatTs(job.created_at),
      state: 'done',
    },
    {
      label: 'Running',
      sublabel: isRunning ? 'Scanning in progress…' : job.started_at ? 'Scan executed' : undefined,
      ts: formatTs(job.started_at),
      state: isRunning ? 'active' : isDone ? 'done' : 'pending',
    },
    {
      label: job.status === 'failed' ? 'Failed' : job.status === 'cancelled' ? 'Cancelled' : 'Completed',
      sublabel: job.status === 'failed' ? 'Error encountered' : job.status === 'cancelled' ? 'Scan cancelled' : isDone ? 'Results ready' : undefined,
      ts: formatTs(job.completed_at),
      state: job.status === 'failed' ? 'error' : isDone ? 'done' : 'pending',
    },
  ]
}

function PipelineDot({ state }: { state: PipelineStage['state'] }) {
  if (state === 'active') {
    return (
      <div className="relative w-3 h-3">
        <div className="absolute inset-0 rounded-full animate-ping" style={{ background: 'rgba(79,156,249,0.4)' }} />
        <div className="relative w-3 h-3 rounded-full border-2" style={{ borderColor: '#4F9CF9', background: '#4F9CF9' }} />
      </div>
    )
  }
  const colorMap = { done: '#8BFF3E', error: '#ef4444', pending: 'rgba(255,255,255,0.1)' } as const
  const borderMap = { done: '#8BFF3E', error: '#ef4444', pending: 'rgba(255,255,255,0.18)' } as const
  return (
    <div
      className="w-3 h-3 rounded-full border-2 flex-shrink-0"
      style={{ background: colorMap[state], borderColor: borderMap[state] }}
    />
  )
}

export default function ScanDetailPage() {
  const params = useParams()
  const id = params.id as string

  const [job, setJob] = useState<ScanJobResponse | null>(null)
  const [result, setResult] = useState<ScanResultSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  function stopPolling() {
    if (intervalRef.current) { clearInterval(intervalRef.current); intervalRef.current = null }
  }

  async function fetchJob() {
    try {
      const j = await api.scanJobs.get(id)
      setJob(j)
      return j
    } catch {
      setError('Scan job not found.')
      return null
    }
  }

  useEffect(() => {
    fetchJob().then(j => {
      setLoading(false)
      if (!j) return
      if (j.status === 'completed') {
        api.scanResults.list({ scan_job_id: j.id })
          .then(res => { if (res.items.length > 0) setResult(res.items[0]) })
          .catch(() => {})
      } else if (j.status === 'queued' || j.status === 'running') {
        intervalRef.current = setInterval(async () => {
          const updated = await fetchJob()
          if (!updated || !['queued', 'running'].includes(updated.status)) stopPolling()
        }, POLL_INTERVAL)
      }
    })
    return () => stopPolling()
  }, [id]) // eslint-disable-line react-hooks/exhaustive-deps

  if (loading) return <div className="p-8"><LoadingState /></div>

  if (error || !job) {
    return (
      <div className="p-8 space-y-4">
        <ErrorState message={error ?? 'Scan job not found.'} />
        <div className="flex justify-center">
          <Link href="/dashboard/scans">
            <button className="flex items-center gap-1.5 text-[12px]" style={{ color: 'rgba(255,255,255,0.45)' }}>
              <ArrowLeft className="w-3.5 h-3.5" /> Back to Scans
            </button>
          </Link>
        </div>
      </div>
    )
  }

  const cfg = STATUS[job.status] ?? STATUS.queued
  const StatusIcon = cfg.icon
  const isActive = job.status === 'queued' || job.status === 'running'
  const pipeline = buildPipeline(job)
  const duration = formatDuration(job.started_at, job.completed_at)
  const profileColor = PROFILE_COLOR[job.profile] ?? '#9ca3af'

  return (
    <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
      <div className="max-w-[820px] mx-auto px-4 py-5 sm:px-6 sm:py-8 space-y-5">

        {/* Back nav */}
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
          <Link
            href="/dashboard/scans"
            className="inline-flex items-center gap-1.5 text-[12px] transition-colors"
            style={{ color: 'rgba(255,255,255,0.35)' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.65)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.35)')}
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Scans
          </Link>
        </motion.div>

        {/* Header card */}
        <motion.div
          className="rounded-[12px] p-5"
          style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.05 }}
        >
          <div className="flex items-start gap-4">
            {/* Status icon */}
            <div
              className="w-10 h-10 rounded-[10px] flex items-center justify-center flex-shrink-0"
              style={{ background: cfg.bg, border: `1px solid ${cfg.border}` }}
            >
              <StatusIcon
                className={cn('w-5 h-5', isActive && job.status === 'running' && 'animate-spin')}
                style={{ color: cfg.color }}
              />
            </div>

            <div className="flex-1 min-w-0">
              {/* Badges */}
              <div className="flex items-center gap-2 flex-wrap mb-2">
                <span
                  className="px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wide"
                  style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}` }}
                >
                  {cfg.label}
                </span>
                <span
                  className="px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wide"
                  style={{ background: `${profileColor}18`, color: profileColor, border: `1px solid ${profileColor}35` }}
                >
                  {job.profile}
                </span>
                {duration && (
                  <span
                    className="px-2 py-0.5 rounded-full text-[9px] font-mono font-semibold"
                    style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.45)', border: '1px solid rgba(255,255,255,0.08)' }}
                  >
                    {duration}
                  </span>
                )}
                {isActive && (
                  <span className="flex items-center gap-1 text-[10px]" style={{ color: '#4F9CF9' }}>
                    <Loader2 className="w-3 h-3 animate-spin" />
                    Live
                  </span>
                )}
              </div>

              {/* URL */}
              <Link
                href={`/dashboard/websites/${job.website_id}`}
                className="flex items-center gap-1.5 group"
                onMouseEnter={e => e.currentTarget.style.opacity = '0.8'}
                onMouseLeave={e => e.currentTarget.style.opacity = '1'}
              >
                <Globe className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'rgba(255,255,255,0.3)' }} />
                <span className="text-[13px] font-mono text-white truncate">{job.requested_url}</span>
                <ChevronRight className="w-3 h-3 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: 'rgba(255,255,255,0.3)' }} />
              </Link>
              <p className="text-[10px] font-mono mt-1" style={{ color: 'rgba(255,255,255,0.2)' }}>
                {job.id}
              </p>
            </div>
          </div>
        </motion.div>

        {/* Pipeline visualization */}
        <motion.div
          className="rounded-[12px] p-5"
          style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.1 }}
        >
          <div className="flex items-center gap-2 mb-5">
            <ScanLine className="w-3.5 h-3.5" style={{ color: 'rgba(255,255,255,0.4)' }} />
            <span className="text-[13px] font-semibold text-white">Pipeline</span>
          </div>

          {/* Horizontal pipeline for wide screens, vertical for narrow */}
          <div className="hidden sm:flex items-start gap-0">
            {pipeline.map((stage, i) => {
              const isLast = i === pipeline.length - 1
              return (
                <div key={i} className="flex items-center flex-1 min-w-0">
                  <div className="flex flex-col items-center gap-1.5 flex-shrink-0">
                    <PipelineDot state={stage.state} />
                    <span
                      className="text-[11px] font-semibold whitespace-nowrap"
                      style={{
                        color: stage.state === 'done' ? '#8BFF3E'
                          : stage.state === 'active' ? '#4F9CF9'
                          : stage.state === 'error' ? '#ef4444'
                          : 'rgba(255,255,255,0.2)',
                      }}
                    >
                      {stage.label}
                    </span>
                    {stage.sublabel && (
                      <span className="text-[9px] whitespace-nowrap" style={{ color: 'rgba(255,255,255,0.28)' }}>
                        {stage.sublabel}
                      </span>
                    )}
                    {stage.ts ? (
                      <span className="text-[9px] font-mono whitespace-nowrap" style={{ color: 'rgba(255,255,255,0.2)' }}>
                        {stage.ts}
                      </span>
                    ) : (
                      <span className="text-[9px]" style={{ color: 'rgba(255,255,255,0.1)' }}>—</span>
                    )}
                  </div>
                  {!isLast && (
                    <div
                      className="flex-1 h-px mx-3 mb-10"
                      style={{
                        background: pipeline[i + 1].state !== 'pending'
                          ? 'rgba(139,255,62,0.3)'
                          : 'rgba(255,255,255,0.07)',
                      }}
                    />
                  )}
                </div>
              )
            })}
          </div>

          {/* Vertical fallback for mobile */}
          <ol className="sm:hidden space-y-4">
            {pipeline.map((stage, i) => (
              <li key={i} className="flex gap-4">
                <div className="flex flex-col items-center">
                  <PipelineDot state={stage.state} />
                  {i < pipeline.length - 1 && (
                    <div
                      className="w-px flex-1 mt-1"
                      style={{
                        minHeight: 24,
                        background: pipeline[i + 1].state !== 'pending' ? 'rgba(139,255,62,0.3)' : 'rgba(255,255,255,0.07)',
                      }}
                    />
                  )}
                </div>
                <div className="pb-4">
                  <p
                    className="text-[12px] font-semibold"
                    style={{
                      color: stage.state === 'done' ? '#8BFF3E'
                        : stage.state === 'active' ? '#4F9CF9'
                        : stage.state === 'error' ? '#ef4444'
                        : 'rgba(255,255,255,0.2)',
                    }}
                  >
                    {stage.label}
                    {stage.state === 'active' && (
                      <span className="ml-2 text-[10px] font-normal" style={{ color: '#4F9CF9' }}>
                        <Loader2 className="w-2.5 h-2.5 animate-spin inline mr-0.5" />
                        in progress
                      </span>
                    )}
                  </p>
                  {stage.ts ? (
                    <p className="text-[10px] font-mono mt-0.5" style={{ color: 'rgba(255,255,255,0.28)' }}>{stage.ts}</p>
                  ) : (
                    <p className="text-[10px] mt-0.5" style={{ color: 'rgba(255,255,255,0.15)' }}>—</p>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </motion.div>

        {/* Error details */}
        {job.status === 'failed' && job.error_message && (
          <motion.div
            className="rounded-[12px] p-5"
            style={{ background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.2)' }}
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.15 }}
          >
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-3.5 h-3.5" style={{ color: '#ef4444' }} />
              <span className="text-[13px] font-semibold" style={{ color: '#ef4444' }}>Error Details</span>
            </div>
            <p className="text-[12px] font-mono leading-relaxed p-3 rounded-[8px]" style={{ color: '#fca5a5', background: 'rgba(239,68,68,0.06)' }}>
              {job.error_message}
            </p>
          </motion.div>
        )}

        {/* Results */}
        {job.status === 'completed' && (
          <motion.div
            className="rounded-[12px] p-5"
            style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(139,255,62,0.18)' }}
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.15 }}
          >
            <div className="flex items-center gap-2 mb-4">
              <BarChart2 className="w-3.5 h-3.5" style={{ color: '#8BFF3E' }} />
              <span className="text-[13px] font-semibold text-white">Scan Results</span>
            </div>

            {result ? (
              <div className="flex items-center justify-between gap-4">
                <div className="space-y-3">
                  {/* Risk score */}
                  <div className="flex items-center gap-3">
                    <div>
                      <p className="text-[10px] uppercase tracking-wide mb-0.5" style={{ color: 'rgba(255,255,255,0.3)' }}>Risk Score</p>
                      <div className="flex items-baseline gap-2">
                        <span
                          className="text-[28px] font-bold font-mono leading-none"
                          style={{ color: RISK_COLOR[result.risk_level] ?? '#8BFF3E' }}
                        >
                          {result.risk_score}
                        </span>
                        <span
                          className="text-[11px] font-semibold uppercase"
                          style={{ color: RISK_COLOR[result.risk_level] ?? '#8BFF3E' }}
                        >
                          {result.risk_level}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Finding counts */}
                  <div className="flex items-center gap-4">
                    <div>
                      <p className="text-[10px] uppercase tracking-wide" style={{ color: 'rgba(255,255,255,0.3)' }}>Total</p>
                      <p className="text-[16px] font-bold text-white font-mono">{result.total_findings}</p>
                    </div>
                    <div style={{ width: 1, height: 30, background: 'rgba(255,255,255,0.06)' }} />
                    <div>
                      <p className="text-[10px] uppercase tracking-wide" style={{ color: 'rgba(255,255,255,0.3)' }}>Actionable</p>
                      <p className="text-[16px] font-bold font-mono" style={{ color: result.actionable_findings > 0 ? '#f97316' : '#8BFF3E' }}>
                        {result.actionable_findings}
                      </p>
                    </div>
                    {result.pages_crawled > 0 && (
                      <>
                        <div style={{ width: 1, height: 30, background: 'rgba(255,255,255,0.06)' }} />
                        <div>
                          <p className="text-[10px] uppercase tracking-wide" style={{ color: 'rgba(255,255,255,0.3)' }}>Pages</p>
                          <p className="text-[16px] font-bold text-white font-mono">{result.pages_crawled}</p>
                        </div>
                      </>
                    )}
                  </div>
                </div>

                <Link href={`/dashboard/results/${result.id}`}>
                  <button
                    className="flex items-center gap-1.5 px-4 py-2.5 rounded-[8px] text-[12px] font-semibold transition-all"
                    style={{ background: 'rgba(139,255,62,0.1)', border: '1px solid rgba(139,255,62,0.3)', color: '#8BFF3E' }}
                    onMouseEnter={e => { const el = e.currentTarget; el.style.background = 'rgba(139,255,62,0.16)'; el.style.borderColor = 'rgba(139,255,62,0.5)' }}
                    onMouseLeave={e => { const el = e.currentTarget; el.style.background = 'rgba(139,255,62,0.1)'; el.style.borderColor = 'rgba(139,255,62,0.3)' }}
                  >
                    View Results
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </Link>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" style={{ color: 'rgba(255,255,255,0.3)' }} />
                <span className="text-[12px]" style={{ color: 'rgba(255,255,255,0.35)' }}>Loading result data…</span>
              </div>
            )}
          </motion.div>
        )}
      </div>
    </div>
  )
}
