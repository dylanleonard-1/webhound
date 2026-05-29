'use client'

// WebHound — apps/web/src/app/scan/[token]/status/page.tsx
// Slice 4.A — polling status page.
//
// The visitor arrives here from /scan after the URL-entry form
// posted to POST /public/scan. We poll GET /public/scan/{token}
// every 2 seconds (per H3) until the scan reaches a terminal
// status. Polling will be replaced by SSE in Slice 4.B without
// changing this page's UX.
//
// Status copy is plain-English ("We're checking your website now")
// — never "Loading..." per the ADDITIONAL REQUIREMENTS for 4.A.
// The page must feel ALIVE and helpful, not technical.

import { use, useEffect, useState } from 'react'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import {
  CheckCircle2, AlertCircle, Globe, ArrowRight, Loader2,
} from 'lucide-react'

const API_BASE =
  (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_API_URL) ||
  'https://api.webhoundsecurity.com'

interface ScanStatusResponse {
  scan_id: string
  guest_token: string
  status: string
  target_url: string
  profile: string
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  result: {
    risk_score: number | null
    risk_level: string | null
    total_findings: number | null
    actionable_findings: number | null
    severity_breakdown: Record<string, number> | null
    duration_seconds: number | null
  } | null
}

// Plain-English status rotation while the scan is running. Matches
// the rewritten STATUSES copy from Slice 3 so the visitor sees the
// same vocabulary on the Landing Page and during their real scan.
const RUNNING_STATUS_COPY = [
  'Looking at every page on your site…',
  'Checking the tools your site uses…',
  'Finding security weaknesses…',
  'Ranking what to fix first…',
  'Comparing against known threats…',
  'Building your report…',
]

const POLL_INTERVAL_MS = 2000
const QUEUED_REASSURE_MS = 6000   // soften messaging after ~3 polls

export default function ScanStatusPage(props: {
  params: Promise<{ token: string }>
}) {
  // Next 16 requires unwrapping params via use().
  const { token } = use(props.params)
  const [data, setData] = useState<ScanStatusResponse | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [pollCount, setPollCount] = useState(0)
  const [statusIdx, setStatusIdx] = useState(0)

  // Live updates. Slice 4.B — prefer SSE; fall back to polling
  // if EventSource fails or the browser doesn't support it. Either
  // path lands the same payload shape into setData(), so the rest
  // of the page is unaware which transport is in use.
  useEffect(() => {
    let cancelled = false
    let es: EventSource | null = null
    let pollTimer: ReturnType<typeof setTimeout> | null = null

    async function startPolling() {
      async function poll() {
        if (cancelled) return
        try {
          const res = await fetch(`${API_BASE}/public/scan/${token}`)
          const body: ScanStatusResponse | { detail?: string } =
            await res.json().catch(() => ({}))
          if (cancelled) return
          if (!res.ok) {
            const detail = (body as { detail?: string }).detail ||
              'We couldn’t find that scan.'
            setErrorMessage(detail)
            return
          }
          const ok = body as ScanStatusResponse
          setData(ok)
          setPollCount((p) => p + 1)
          if (ok.status !== 'completed' && ok.status !== 'failed' && ok.status !== 'cancelled') {
            pollTimer = setTimeout(poll, POLL_INTERVAL_MS)
          }
        } catch {
          if (cancelled) return
          pollTimer = setTimeout(poll, POLL_INTERVAL_MS)
        }
      }
      poll()
    }

    function tryEventSource() {
      if (typeof window === 'undefined' || typeof EventSource === 'undefined') {
        startPolling()
        return
      }
      try {
        es = new EventSource(`${API_BASE}/public/scan/${token}/events`)
        es.addEventListener('snapshot', (ev) => {
          try {
            const parsed = JSON.parse((ev as MessageEvent).data) as ScanStatusResponse
            if (!cancelled) {
              setData(parsed)
              setPollCount((p) => p + 1)
            }
          } catch { /* ignore malformed snapshot */ }
        })
        // Lifecycle frames — refetch the current state so the
        // status card always reflects the latest server-side
        // truth (no need to merge partial events client-side).
        es.onmessage = async () => {
          if (cancelled) return
          try {
            const res = await fetch(`${API_BASE}/public/scan/${token}`)
            const body = await res.json().catch(() => null)
            if (!cancelled && res.ok && body) {
              setData(body as ScanStatusResponse)
              setPollCount((p) => p + 1)
            }
          } catch { /* ignore — keep stream open */ }
        }
        es.onerror = () => {
          if (es) { es.close(); es = null }
          if (!cancelled) startPolling()
        }
      } catch {
        startPolling()
      }
    }

    tryEventSource()
    return () => {
      cancelled = true
      if (es) { es.close(); es = null }
      if (pollTimer) clearTimeout(pollTimer)
    }
  }, [token])

  // Rotate the running-status copy locally so the page feels
  // alive even between polls. ~3s cadence keeps it gentle.
  useEffect(() => {
    if (!data || data.status === 'completed' || data.status === 'failed') return
    const id = setInterval(
      () => setStatusIdx((i) => (i + 1) % RUNNING_STATUS_COPY.length),
      3000,
    )
    return () => clearInterval(id)
  }, [data])

  // -------------------------------------------------------------
  // Error state — only when the API returned a terminal error
  // (typically the 404 'unknown token' path).
  // -------------------------------------------------------------
  if (errorMessage) {
    return (
      <PageShell>
        <div
          className="flex flex-col items-start gap-4 p-6 rounded-[14px]"
          style={{
            background: 'rgba(239,68,68,0.06)',
            border: '1px solid rgba(239,68,68,0.28)',
          }}
        >
          <AlertCircle className="w-6 h-6" style={{ color: '#ef4444' }} />
          <h1 className="text-[22px] font-bold text-white">We couldn’t find that scan.</h1>
          <p className="text-[14px] leading-[1.6]" style={{ color: 'rgba(255,255,255,0.6)' }}>
            {errorMessage} Guest scan links expire after 24 hours.
          </p>
          <Link
            href="/scan"
            className="inline-flex items-center gap-1.5 mt-2 text-[14px] font-semibold"
            style={{ color: '#7CFF00' }}
          >
            Start a new scan
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </PageShell>
    )
  }

  // -------------------------------------------------------------
  // Initial state — request just submitted, first poll pending.
  // Never show "Loading..." per the brief; show a real first
  // status copy line.
  // -------------------------------------------------------------
  if (!data) {
    return (
      <PageShell>
        <RunningView statusCopy={RUNNING_STATUS_COPY[0]} targetUrl="" pollCount={0} />
      </PageShell>
    )
  }

  // -------------------------------------------------------------
  // Completed
  // -------------------------------------------------------------
  if (data.status === 'completed') {
    return (
      <PageShell>
        <CompletedView data={data} />
      </PageShell>
    )
  }

  // -------------------------------------------------------------
  // Failed / Cancelled
  // -------------------------------------------------------------
  if (data.status === 'failed' || data.status === 'cancelled') {
    return (
      <PageShell>
        <FailedView data={data} />
      </PageShell>
    )
  }

  // -------------------------------------------------------------
  // Running — the normal path.
  // -------------------------------------------------------------
  // First few polls: extra reassurance copy. After QUEUED_REASSURE_MS
  // the visitor sees the rotating running statuses.
  const inQueueWindow =
    data.status === 'queued' && pollCount * POLL_INTERVAL_MS < QUEUED_REASSURE_MS

  return (
    <PageShell>
      <RunningView
        statusCopy={
          inQueueWindow
            ? 'We’re checking your website now…'
            : RUNNING_STATUS_COPY[statusIdx]
        }
        targetUrl={data.target_url}
        pollCount={pollCount}
      />
    </PageShell>
  )
}


// ─────────────────────────────────────────────────────────────────
// Page chrome
// ─────────────────────────────────────────────────────────────────


function PageShell({ children }: { children: React.ReactNode }) {
  return (
    <section
      className="relative min-h-screen flex items-center justify-center px-6 py-16"
      style={{ background: '#020617' }}
    >
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.012]"
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='300' height='300'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='300' height='300' filter='url(%23n)'/%3E%3C/svg%3E\")",
        }}
      />
      <div className="relative max-w-[640px] w-full">{children}</div>
    </section>
  )
}


// ─────────────────────────────────────────────────────────────────
// Running view — visible while the scan is queued or running.
// ─────────────────────────────────────────────────────────────────


function RunningView({
  statusCopy, targetUrl, pollCount,
}: { statusCopy: string; targetUrl: string; pollCount: number }) {
  return (
    <div className="flex flex-col">
      {/* Eyebrow + URL */}
      <div className="inline-flex items-center gap-2 mb-5 w-fit">
        <motion.span
          className="w-1.5 h-1.5 rounded-full"
          style={{ background: '#7CFF00', boxShadow: '0 0 8px rgba(124,255,0,0.9)' }}
          animate={{ opacity: [1, 0.3, 1] }}
          transition={{ duration: 1.4, repeat: Infinity }}
        />
        <span className="text-[10px] font-bold tracking-[0.28em] uppercase" style={{ color: 'rgba(139,255,62,0.75)' }}>
          Scan in progress
        </span>
      </div>

      {targetUrl && (
        <div className="flex items-center gap-2 mb-6">
          <Globe className="w-3.5 h-3.5" style={{ color: 'rgba(255,255,255,0.42)' }} />
          <span className="text-[13px] font-medium" style={{ color: 'rgba(255,255,255,0.75)' }}>
            {targetUrl}
          </span>
        </div>
      )}

      <h1
        className="font-bold leading-[1.1] tracking-[-0.02em] mb-4 text-white"
        style={{ fontSize: 'clamp(1.6rem, 3.2vw, 2.4rem)' }}
      >
        Checking your website now.
      </h1>

      <p className="text-[15px] mb-9 max-w-[520px] leading-[1.6]" style={{ color: 'rgba(255,255,255,0.6)' }}>
        Most scans finish in under two minutes. We’ll show you what
        we found in plain English when it’s done — there’s nothing
        you need to do.
      </p>

      {/* Live status line — rotates plain-English copy */}
      <div className="relative h-7 overflow-hidden mb-4">
        <AnimatePresence mode="wait">
          <motion.div
            key={statusCopy}
            className="absolute inset-0 flex items-center gap-2"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.3 }}
          >
            <Loader2 className="w-4 h-4 animate-spin" style={{ color: '#7CFF00' }} />
            <span className="text-[14px]" style={{ color: 'rgba(255,255,255,0.85)' }}>
              {statusCopy}
            </span>
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Indeterminate progress bar — non-deterministic but
          reassuring. Real progress arrives in Slice 4.B with SSE. */}
      <div className="relative h-1 rounded-full overflow-hidden mb-8" style={{ background: 'rgba(139,255,62,0.08)' }}>
        <motion.div
          className="absolute inset-y-0 rounded-full"
          style={{ background: '#7CFF00', width: '35%' }}
          animate={{ x: ['-110%', '300%'] }}
          transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}
        />
      </div>

      <p className="text-[11.5px]" style={{ color: 'rgba(255,255,255,0.32)' }}>
        You can leave this page open — we’ll keep checking. Polled{' '}
        {pollCount} {pollCount === 1 ? 'time' : 'times'}.
      </p>
    </div>
  )
}


// ─────────────────────────────────────────────────────────────────
// Completed view — basic summary; richer rendering arrives in 4.B/4.C.
// ─────────────────────────────────────────────────────────────────


function CompletedView({ data }: { data: ScanStatusResponse }) {
  const r = data.result
  const score = r?.risk_score ?? null
  const level = (r?.risk_level ?? 'unknown').toUpperCase()
  const total = r?.total_findings ?? 0
  const actionable = r?.actionable_findings ?? 0
  const sev = (r?.severity_breakdown ?? {}) as Record<string, number>

  return (
    <div className="flex flex-col">
      <div className="inline-flex items-center gap-2 mb-5 w-fit">
        <CheckCircle2 className="w-4 h-4" style={{ color: '#7CFF00' }} />
        <span className="text-[10px] font-bold tracking-[0.28em] uppercase" style={{ color: 'rgba(139,255,62,0.75)' }}>
          Scan complete
        </span>
      </div>

      <div className="flex items-center gap-2 mb-6">
        <Globe className="w-3.5 h-3.5" style={{ color: 'rgba(255,255,255,0.42)' }} />
        <span className="text-[13px] font-medium" style={{ color: 'rgba(255,255,255,0.75)' }}>
          {data.target_url}
        </span>
      </div>

      <h1
        className="font-bold leading-[1.1] tracking-[-0.02em] mb-5 text-white"
        style={{ fontSize: 'clamp(1.8rem, 3.4vw, 2.6rem)' }}
      >
        We found {total} {total === 1 ? 'issue' : 'issues'} on your website.
      </h1>

      <div className="grid grid-cols-2 gap-4 mb-8">
        <SummaryCard
          label="Security score"
          value={score === null ? '—' : `${score}/100`}
          sub={level !== 'UNKNOWN' ? `Risk: ${level}` : ''}
        />
        <SummaryCard
          label="Needs attention"
          value={String(actionable)}
          sub={`${total} total`}
        />
      </div>

      <div className="flex flex-col gap-2 mb-9">
        {(['critical', 'high', 'medium', 'low'] as const).map((s) => {
          const n = sev[s] ?? 0
          if (n === 0) return null
          return (
            <SeverityRow key={s} severity={s} count={n} />
          )
        })}
      </div>

      <div
        className="p-5 rounded-[12px] mb-5"
        style={{
          background: 'rgba(139,255,62,0.04)',
          border: '1px solid rgba(139,255,62,0.18)',
        }}
      >
        <p className="text-[14px] leading-[1.6] mb-3" style={{ color: 'rgba(255,255,255,0.78)' }}>
          Want to keep this report, see the details for each finding, and
          schedule a daily re-scan?
        </p>
        <Link
          href={`/register?save=${data.guest_token}`}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[8px] text-[13.5px] font-semibold text-[#020617]"
          style={{ background: '#7CFF00' }}
        >
          Save my report
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
        <p className="text-[11.5px] mt-3" style={{ color: 'rgba(255,255,255,0.42)' }}>
          Guest reports expire after 24 hours. Saving keeps it.
        </p>
      </div>

      <Link
        href="/scan"
        className="text-[12.5px] underline"
        style={{ color: 'rgba(255,255,255,0.5)' }}
      >
        Scan a different website
      </Link>
    </div>
  )
}


function SummaryCard({
  label, value, sub,
}: { label: string; value: string; sub: string }) {
  return (
    <div
      className="rounded-[12px] p-4"
      style={{
        background: 'rgba(8,12,22,0.85)',
        border: '1px solid rgba(255,255,255,0.06)',
      }}
    >
      <div className="text-[10px] font-bold tracking-[0.2em] uppercase mb-2" style={{ color: 'rgba(255,255,255,0.4)' }}>
        {label}
      </div>
      <div className="text-[26px] font-bold text-white leading-none mb-1">{value}</div>
      {sub && <div className="text-[11px]" style={{ color: 'rgba(255,255,255,0.4)' }}>{sub}</div>}
    </div>
  )
}


function SeverityRow({
  severity, count,
}: { severity: 'critical' | 'high' | 'medium' | 'low'; count: number }) {
  const theme: Record<typeof severity, { label: string; color: string; bg: string; border: string }> = {
    critical: { label: 'Critical', color: '#ef4444', bg: 'rgba(239,68,68,0.07)', border: 'rgba(239,68,68,0.28)' },
    high:     { label: 'High',     color: '#f97316', bg: 'rgba(249,115,22,0.07)', border: 'rgba(249,115,22,0.28)' },
    medium:   { label: 'Medium',   color: '#eab308', bg: 'rgba(234,179,8,0.07)', border: 'rgba(234,179,8,0.28)' },
    low:      { label: 'Low',      color: '#22d3ee', bg: 'rgba(34,211,238,0.07)', border: 'rgba(34,211,238,0.28)' },
  }
  const s = theme[severity]
  return (
    <div className="flex items-center justify-between px-4 py-3 rounded-[10px]" style={{ background: 'rgba(8,12,22,0.55)', border: '1px solid rgba(255,255,255,0.05)' }}>
      <span
        className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
        style={{ background: s.bg, color: s.color, border: `1px solid ${s.border}` }}
      >
        {s.label}
      </span>
      <span className="text-[13px] font-medium text-white">{count} {count === 1 ? 'finding' : 'findings'}</span>
    </div>
  )
}


// ─────────────────────────────────────────────────────────────────
// Failed view
// ─────────────────────────────────────────────────────────────────


function FailedView({ data }: { data: ScanStatusResponse }) {
  return (
    <div className="flex flex-col">
      <div className="inline-flex items-center gap-2 mb-5 w-fit">
        <AlertCircle className="w-4 h-4" style={{ color: '#ef4444' }} />
        <span className="text-[10px] font-bold tracking-[0.28em] uppercase" style={{ color: 'rgba(239,68,68,0.8)' }}>
          Scan didn’t finish
        </span>
      </div>
      <h1 className="text-[24px] font-bold text-white leading-[1.1] mb-4">
        We couldn’t scan {data.target_url}.
      </h1>
      <p className="text-[14px] mb-7 leading-[1.6]" style={{ color: 'rgba(255,255,255,0.6)' }}>
        {data.error_message ||
          'The scan couldn’t complete this time. It could be the site blocked us, or there was a temporary network problem. Try again in a few minutes.'}
      </p>
      <Link
        href="/scan"
        className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[8px] text-[13.5px] font-semibold w-fit"
        style={{
          background: 'rgba(8,12,22,0.85)',
          border: '1px solid rgba(255,255,255,0.10)',
          color: 'rgba(255,255,255,0.85)',
        }}
      >
        Try a different URL
      </Link>
    </div>
  )
}
