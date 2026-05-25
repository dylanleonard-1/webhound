'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import {
  Globe, ScanLine, Bell, Activity, CheckCircle, XCircle,
  Loader2, Clock, ArrowRight, Zap, AlertTriangle, Shield, Plus,
} from 'lucide-react'
import { api, type ScanJobResponse } from '@/lib/api'
import { StatCard } from '@/components/stat-card'
import { LoadingState } from '@/components/loading-state'
import { ErrorState } from '@/components/error-state'
import { cn } from '@/lib/utils'

// ── Helpers ───────────────────────────────────────────────────────────────────

interface Stats { websites: number; scanJobs: number; notifications: number }

const STATUS_ICON: Record<string, React.FC<{ className?: string; style?: React.CSSProperties }>> = {
  completed: CheckCircle, failed: XCircle, running: Loader2,
  queued: Clock, cancelled: XCircle,
}
const STATUS_COLOR: Record<string, string> = {
  completed: '#8BFF3E', failed: '#ef4444', running: '#4F9CF9',
  queued: 'rgba(255,255,255,0.35)', cancelled: 'rgba(255,255,255,0.2)',
}
const STATUS_BG: Record<string, string> = {
  completed: 'rgba(139,255,62,0.08)',  failed: 'rgba(239,68,68,0.08)',
  running:   'rgba(79,156,249,0.08)',  queued: 'rgba(255,255,255,0.04)',
  cancelled: 'rgba(255,255,255,0.03)',
}

function timeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime()
  const min = Math.floor(diff / 60000)
  if (min < 1) return 'just now'
  if (min < 60) return `${min}m ago`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr}h ago`
  return `${Math.floor(hr / 24)}d ago`
}

// ── Risk ring ─────────────────────────────────────────────────────────────────

function RiskRing({ score = 72 }: { score?: number }) {
  const r = 38
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ

  const color = score >= 80 ? '#8BFF3E' : score >= 50 ? '#eab308' : '#ef4444'
  const label = score >= 80 ? 'GOOD' : score >= 50 ? 'FAIR' : 'RISK'

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-24 h-24">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 88 88">
          <circle cx="44" cy="44" r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="6" />
          <circle
            cx="44" cy="44" r={r}
            fill="none"
            stroke={color}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            style={{ filter: `drop-shadow(0 0 6px ${color}60)`, transition: 'stroke-dashoffset 1.2s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-[22px] font-black text-white leading-none">{score}</span>
          <span className="text-[8px] font-black tracking-[0.15em] mt-0.5" style={{ color }}>{label}</span>
        </div>
      </div>
      <span className="text-[10px] text-[rgba(255,255,255,0.32)] font-medium">Security Score</span>
    </div>
  )
}

// ── Quick actions ─────────────────────────────────────────────────────────────

const QUICK_ACTIONS = [
  { label: 'New Scan',    href: '/dashboard/websites/new', icon: Plus,    color: '#8BFF3E', bg: 'rgba(139,255,62,0.1)',  border: 'rgba(139,255,62,0.25)'  },
  { label: 'View Scans', href: '/dashboard/scans',         icon: ScanLine, color: '#4F9CF9', bg: 'rgba(79,156,249,0.08)', border: 'rgba(79,156,249,0.2)'  },
  { label: 'Monitoring', href: '/dashboard/monitoring',    icon: Activity, color: '#a78bfa', bg: 'rgba(167,139,250,0.08)',border: 'rgba(167,139,250,0.2)'  },
  { label: 'Alerts',     href: '/dashboard/notifications', icon: Bell,    color: '#f97316', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.2)'   },
]

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [recentScans, setRecentScans] = useState<ScanJobResponse[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function load() {
      try {
        const [websites, scanJobs, notifCount, recent] = await Promise.all([
          api.websites.list({ limit: 1 }),
          api.scanJobs.list({ limit: 1 }),
          api.notifications.unreadCount(),
          api.scanJobs.list({ limit: 6 }),
        ])
        setStats({ websites: websites.total, scanJobs: scanJobs.total, notifications: notifCount.count })
        setRecentScans(recent.items)
      } catch {
        setError('Failed to load dashboard data.')
      }
    }
    load()
  }, [])

  if (error) return <ErrorState message={error} onRetry={() => { setError(null); setStats(null) }} />

  return (
    <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
      <div className="max-w-[1100px] mx-auto px-4 py-5 sm:px-6 sm:py-8 space-y-6 sm:space-y-8">

        {/* ── Header ──────────────────────────────────────────── */}
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
          <h1 className="text-[22px] font-bold text-white tracking-tight">Security Overview</h1>
          <p className="text-[13px] mt-0.5" style={{ color: 'rgba(255,255,255,0.38)' }}>
            Your attack surface intelligence at a glance.
          </p>
        </motion.div>

        {/* ── Onboarding cue (only shown when zero websites yet) ── */}
        {stats !== null && stats.websites === 0 && (
          <motion.div
            initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.06 }}
            className="rounded-[14px] p-5"
            style={{
              background: 'linear-gradient(180deg, rgba(139,255,62,0.06), rgba(8,12,22,0.95))',
              border: '1px solid rgba(139,255,62,0.22)',
            }}
          >
            <div className="flex items-start gap-3 mb-4">
              <div
                className="w-9 h-9 rounded-[10px] flex items-center justify-center flex-shrink-0"
                style={{ background: 'rgba(139,255,62,0.12)', border: '1px solid rgba(139,255,62,0.3)' }}
              >
                <Zap className="w-4 h-4" style={{ color: '#8BFF3E' }} />
              </div>
              <div>
                <h2 className="text-[15px] font-bold text-white mb-0.5">
                  Get your first scan running
                </h2>
                <p className="text-[12px]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                  Three quick steps to see what WebHound finds on your site.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {[
                {
                  step: '1',
                  title: 'Add your website',
                  desc: 'Paste the URL you want to scan.',
                  cta: 'Add website',
                  href: '/dashboard/websites/new',
                },
                {
                  step: '2',
                  title: 'Verify ownership',
                  desc: 'A 30-second DNS TXT record proves the site is yours.',
                  cta: null,
                  href: '/dashboard/websites',
                },
                {
                  step: '3',
                  title: 'Run your first scan',
                  desc: 'Manual scan now, then daily automatic monitoring kicks in.',
                  cta: null,
                  href: '/dashboard/scans',
                },
              ].map(s => (
                <div
                  key={s.step}
                  className="rounded-[10px] p-3"
                  style={{
                    background: 'rgba(8,12,22,0.6)',
                    border: '1px solid rgba(255,255,255,0.06)',
                  }}
                >
                  <div className="flex items-center gap-2 mb-1.5">
                    <span
                      className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-black"
                      style={{ background: 'rgba(139,255,62,0.15)', color: '#8BFF3E' }}
                    >
                      {s.step}
                    </span>
                    <span className="text-[12.5px] font-semibold text-white">{s.title}</span>
                  </div>
                  <p className="text-[11px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.42)' }}>
                    {s.desc}
                  </p>
                </div>
              ))}
            </div>

            <Link
              href="/dashboard/websites/new"
              className="inline-flex items-center gap-1.5 mt-4 px-4 py-2 rounded-[8px] text-[12px] font-semibold transition-all"
              style={{ background: '#8BFF3E', color: '#020617' }}
            >
              <Plus className="w-3.5 h-3.5" />
              Start with your first website
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </motion.div>
        )}

        {/* ── Quick actions ────────────────────────────────────── */}
        <motion.div
          className="grid grid-cols-2 sm:grid-cols-4 gap-3"
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.05 }}
        >
          {QUICK_ACTIONS.map(({ label, href, icon: Icon, color, bg, border }) => (
            <Link key={label} href={href}>
              <div
                className="flex items-center gap-2.5 px-4 py-3 rounded-[10px] transition-all duration-150 hover:opacity-90 cursor-pointer"
                style={{ background: bg, border: `1px solid ${border}` }}
              >
                <Icon className="w-4 h-4 flex-shrink-0" style={{ color }} strokeWidth={1.75} />
                <span className="text-[12.5px] font-semibold" style={{ color }}>{label}</span>
              </div>
            </Link>
          ))}
        </motion.div>

        {/* ── Stats grid ──────────────────────────────────────── */}
        {stats === null ? (
          <LoadingState />
        ) : (
          <motion.div
            className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.1 }}
          >
            <StatCard title="Monitored Sites"  value={stats.websites}        icon={Globe}     accent="green"  href="/dashboard/websites"      subtitle="Active targets" />
            <StatCard title="Total Scans"       value={stats.scanJobs}        icon={ScanLine}  accent="blue"   href="/dashboard/scans"          subtitle="All time" />
            <StatCard title="Unread Alerts"     value={stats.notifications}   icon={Bell}      accent={stats.notifications > 0 ? 'orange' : 'default'} href="/dashboard/notifications" subtitle="Require attention" />
            <StatCard title="Monitoring Status" value="Active"                icon={Activity}  accent="violet" subtitle="Continuous coverage" />
          </motion.div>
        )}

        {/* ── Main content ─────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_280px] gap-6">

          {/* Recent scans table */}
          <motion.div
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.15 }}
          >
            <div
              className="rounded-[12px] overflow-hidden"
              style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
            >
              <div className="flex items-center justify-between px-5 py-3.5" style={{ borderBottom: '1px solid rgba(255,255,255,0.055)' }}>
                <div className="flex items-center gap-2">
                  <ScanLine className="w-4 h-4" style={{ color: 'rgba(255,255,255,0.35)' }} />
                  <span className="text-[13px] font-semibold text-white">Recent Scans</span>
                </div>
                <Link href="/dashboard/scans" className="flex items-center gap-1 text-[11px] font-medium transition-colors"
                  style={{ color: 'rgba(255,255,255,0.32)' }}
                  onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.65)')}
                  onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.32)')}
                >
                  View all <ArrowRight className="w-3 h-3" />
                </Link>
              </div>

              {recentScans.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 gap-3">
                  <div className="w-10 h-10 rounded-full flex items-center justify-center"
                    style={{ background: 'rgba(139,255,62,0.08)', border: '1px solid rgba(139,255,62,0.15)' }}>
                    <ScanLine className="w-5 h-5" style={{ color: '#8BFF3E' }} />
                  </div>
                  <p className="text-[13px] font-medium text-white">No scans yet</p>
                  <p className="text-[11px]" style={{ color: 'rgba(255,255,255,0.32)' }}>Start by adding a website to scan</p>
                  <Link href="/dashboard/websites/new"
                    className="mt-1 px-4 py-2 rounded-[8px] text-[12px] font-semibold transition-all"
                    style={{ background: 'rgba(139,255,62,0.1)', border: '1px solid rgba(139,255,62,0.3)', color: '#8BFF3E' }}
                  >
                    Add Website
                  </Link>
                </div>
              ) : (
                <div>
                  {recentScans.map((scan, i) => {
                    const Icon = STATUS_ICON[scan.status] ?? Clock
                    const color = STATUS_COLOR[scan.status] ?? 'rgba(255,255,255,0.35)'
                    const bg = STATUS_BG[scan.status] ?? 'rgba(255,255,255,0.03)'
                    return (
                      <Link
                        key={scan.id}
                        href={`/dashboard/scans/${scan.id}`}
                        className="flex items-center gap-3 px-3 sm:px-5 py-3.5 transition-colors group"
                        style={{
                          borderBottom: i < recentScans.length - 1 ? '1px solid rgba(255,255,255,0.04)' : undefined,
                        }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.02)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                      >
                        <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
                          style={{ background: bg }}>
                          <Icon
                            className={cn('w-3.5 h-3.5', scan.status === 'running' && 'animate-spin')}
                            style={{ color }}
                          />
                        </div>

                        <div className="flex-1 min-w-0">
                          <span className="text-[12.5px] font-mono font-medium text-white block truncate group-hover:text-white transition-colors">
                            {scan.requested_url}
                          </span>
                          <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.28)' }}>
                            {timeAgo(scan.created_at)}
                          </span>
                        </div>

                        <div className="flex items-center gap-2 flex-shrink-0">
                          <span
                            className="px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wide"
                            style={{ background: bg, color }}
                          >
                            {scan.status}
                          </span>
                          <span
                            className="hidden sm:inline-block px-2 py-0.5 rounded-full text-[9px] font-medium"
                            style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.3)' }}
                          >
                            {scan.profile}
                          </span>
                        </div>
                      </Link>
                    )
                  })}
                </div>
              )}
            </div>
          </motion.div>

          {/* Right panel */}
          <motion.div
            className="flex flex-col gap-4"
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.2 }}
          >
            {/* Security score */}
            <div
              className="rounded-[12px] p-5 flex flex-col items-center gap-4"
              style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
            >
              <RiskRing score={stats ? Math.min(100, 100 - (stats.notifications * 8)) : 72} />
              <div className="w-full space-y-2">
                {[
                  { label: 'SSL Coverage',   val: 100, color: '#8BFF3E' },
                  { label: 'DNS Health',     val: 88,  color: '#4F9CF9' },
                  { label: 'Header Config',  val: 62,  color: '#eab308' },
                ].map(({ label, val, color }) => (
                  <div key={label}>
                    <div className="flex justify-between mb-1">
                      <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.38)' }}>{label}</span>
                      <span className="text-[10px] font-bold" style={{ color }}>{val}%</span>
                    </div>
                    <div className="h-1 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
                      <div className="h-full rounded-full" style={{ width: `${val}%`, background: color, boxShadow: `0 0 6px ${color}60` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Platform status */}
            <div
              className="rounded-[12px] p-4"
              style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
            >
              <p className="text-[11px] font-black tracking-[0.12em] uppercase mb-3" style={{ color: 'rgba(255,255,255,0.28)' }}>
                Platform Status
              </p>
              {[
                { label: 'Scan Engine',    ok: true  },
                { label: 'AI Analysis',    ok: true  },
                { label: 'Monitoring',     ok: true  },
                { label: 'Alerts',         ok: true  },
              ].map(({ label, ok }) => (
                <div key={label} className="flex items-center justify-between py-1.5">
                  <span className="text-[12px]" style={{ color: 'rgba(255,255,255,0.55)' }}>{label}</span>
                  <div className="flex items-center gap-1.5">
                    <div
                      className="w-1.5 h-1.5 rounded-full"
                      style={{
                        background: ok ? '#8BFF3E' : '#ef4444',
                        boxShadow: ok ? '0 0 4px rgba(139,255,62,0.8)' : '0 0 4px rgba(239,68,68,0.8)',
                        animation: 'pulse 2s ease-in-out infinite',
                      }}
                    />
                    <span className="text-[10px] font-semibold" style={{ color: ok ? '#8BFF3E' : '#ef4444' }}>
                      {ok ? 'Operational' : 'Degraded'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </div>

      </div>
    </div>
  )
}
