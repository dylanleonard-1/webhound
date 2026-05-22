'use client'

import { useCallback, useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Bell, CheckCheck, ExternalLink, Trash2, RefreshCw } from 'lucide-react'
import Link from 'next/link'
import { api, type NotificationResponse, type NotificationSeverity, type NotificationType } from '@/lib/api'
import { LoadingState } from '@/components/loading-state'
import { ErrorState } from '@/components/error-state'

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#4F9CF9',
  info:     '#9ca3af',
}

const TYPE_LABEL: Record<string, string> = {
  scan_completed:    'Scan Completed',
  scan_failed:       'Scan Failed',
  high_risk_finding: 'High Risk',
  critical_finding:  'Critical Finding',
  wade_anomaly:      'WADE Anomaly',
  schedule_failed:   'Schedule Failed',
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
const TYPES: { value: NotificationType; label: string }[] = [
  { value: 'scan_completed',    label: 'Scan Completed' },
  { value: 'scan_failed',       label: 'Scan Failed' },
  { value: 'high_risk_finding', label: 'High Risk' },
  { value: 'critical_finding',  label: 'Critical' },
  { value: 'wade_anomaly',      label: 'WADE Anomaly' },
  { value: 'schedule_failed',   label: 'Schedule Failed' },
]

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

const LIMIT = 25

export default function NotificationsPage() {
  const [notifications, setNotifications] = useState<NotificationResponse[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState(false)
  const [hasMore, setHasMore] = useState(false)

  const [filterSeverity, setFilterSeverity] = useState<NotificationSeverity | ''>('')
  const [filterType, setFilterType] = useState<NotificationType | ''>('')
  const [filterRead, setFilterRead] = useState<'' | 'unread' | 'read'>('')
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [markingAll, setMarkingAll] = useState(false)

  function buildParams(offset: number): Parameters<typeof api.notifications.list>[0] {
    const p: Parameters<typeof api.notifications.list>[0] = { limit: LIMIT, offset }
    if (filterSeverity) p.severity = filterSeverity
    if (filterType) p.type = filterType
    if (filterRead === 'unread') p.is_read = false
    if (filterRead === 'read') p.is_read = true
    return p
  }

  const load = useCallback(async () => {
    setLoading(true)
    setError(false)
    try {
      const res = await api.notifications.list(buildParams(0))
      setNotifications(res.items)
      setTotal(res.total)
      setHasMore(res.has_more)
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterSeverity, filterType, filterRead])

  useEffect(() => { load() }, [load])

  async function loadMore() {
    setLoadingMore(true)
    try {
      const res = await api.notifications.list(buildParams(notifications.length))
      setNotifications(prev => [...prev, ...res.items])
      setTotal(res.total)
      setHasMore(res.has_more)
    } catch { /* ignore */ } finally { setLoadingMore(false) }
  }

  async function handleMarkRead(id: string) {
    try {
      const updated = await api.notifications.markRead(id)
      setNotifications(prev => prev.map(n => n.id === id ? updated : n))
    } catch { /* ignore */ }
  }

  async function handleDelete(id: string) {
    setDeletingId(id)
    try {
      await api.notifications.delete(id)
      setNotifications(prev => prev.filter(n => n.id !== id))
      setTotal(t => t - 1)
    } catch { /* ignore */ } finally { setDeletingId(null) }
  }

  async function handleMarkAllRead() {
    setMarkingAll(true)
    try {
      await api.notifications.markAllRead()
      setNotifications(prev => prev.map(n => ({ ...n, is_read: true })))
    } catch { /* ignore */ } finally { setMarkingAll(false) }
  }

  const unreadCount = notifications.filter(n => !n.is_read).length
  const noFilters = !filterSeverity && !filterType && !filterRead

  return (
    <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
      <div className="max-w-[860px] mx-auto px-4 py-5 sm:px-6 sm:py-8 space-y-6">

        {/* Header */}
        <motion.div
          className="flex items-start justify-between"
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}
        >
          <div>
            <h1 className="text-[22px] font-bold text-white tracking-tight">Alerts</h1>
            <p className="text-[13px] mt-0.5" style={{ color: 'rgba(255,255,255,0.35)' }}>
              {loading ? '—' : `${total} notification${total !== 1 ? 's' : ''}`}
              {unreadCount > 0 && ` · ${unreadCount} unread`}
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
            {unreadCount > 0 && (
              <button
                onClick={handleMarkAllRead}
                disabled={markingAll}
                className="flex items-center gap-1.5 px-3 py-[7px] rounded-[8px] text-[12px] font-semibold transition-all disabled:opacity-50"
                style={{ border: '1px solid rgba(255,255,255,0.08)', color: 'rgba(255,255,255,0.55)' }}
                onMouseEnter={e => { const el = e.currentTarget; el.style.color = 'rgba(255,255,255,0.85)'; el.style.borderColor = 'rgba(255,255,255,0.15)' }}
                onMouseLeave={e => { const el = e.currentTarget; el.style.color = 'rgba(255,255,255,0.55)'; el.style.borderColor = 'rgba(255,255,255,0.08)' }}
              >
                <CheckCheck className="w-3.5 h-3.5" />
                Mark all read
              </button>
            )}
          </div>
        </motion.div>

        {/* Filter pills */}
        <motion.div
          className="space-y-2"
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.05 }}
        >
          {/* Severity pills */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] font-semibold uppercase tracking-wide mr-1" style={{ color: 'rgba(255,255,255,0.25)' }}>Severity</span>
            {(['', ...SEVERITIES] as const).map(s => {
              const active = filterSeverity === s
              const color = s ? SEV_COLOR[s] : undefined
              return (
                <button
                  key={s || 'all-sev'}
                  onClick={() => setFilterSeverity(s as NotificationSeverity | '')}
                  className="px-2.5 py-1 rounded-full text-[10px] font-semibold transition-all duration-150"
                  style={{
                    background:   active ? (color ? `${color}18` : 'rgba(255,255,255,0.08)') : 'rgba(255,255,255,0.02)',
                    border:       active ? `1px solid ${color ?? 'rgba(255,255,255,0.15)'}` : '1px solid rgba(255,255,255,0.05)',
                    color:        active ? (color ?? '#ffffff') : 'rgba(255,255,255,0.32)',
                  }}
                >
                  {s ? s.charAt(0).toUpperCase() + s.slice(1) : 'All'}
                </button>
              )
            })}
          </div>
          {/* Type + Read pills */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] font-semibold uppercase tracking-wide mr-1" style={{ color: 'rgba(255,255,255,0.25)' }}>Type</span>
            {(['', ...TYPES.map(t => t.value)] as const).map(t => {
              const label = t ? TYPES.find(x => x.value === t)?.label ?? t : 'All'
              const active = filterType === t
              return (
                <button
                  key={t || 'all-type'}
                  onClick={() => setFilterType(t as NotificationType | '')}
                  className="px-2.5 py-1 rounded-full text-[10px] font-semibold transition-all duration-150"
                  style={{
                    background:   active ? 'rgba(167,139,250,0.12)' : 'rgba(255,255,255,0.02)',
                    border:       active ? '1px solid rgba(167,139,250,0.35)' : '1px solid rgba(255,255,255,0.05)',
                    color:        active ? '#a78bfa' : 'rgba(255,255,255,0.32)',
                  }}
                >
                  {label}
                </button>
              )
            })}
            <span className="text-[10px] font-semibold uppercase tracking-wide mx-1" style={{ color: 'rgba(255,255,255,0.25)' }}>Read</span>
            {(['', 'unread', 'read'] as const).map(r => {
              const active = filterRead === r
              return (
                <button
                  key={r || 'all-read'}
                  onClick={() => setFilterRead(r)}
                  className="px-2.5 py-1 rounded-full text-[10px] font-semibold transition-all duration-150"
                  style={{
                    background:   active ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.02)',
                    border:       active ? '1px solid rgba(255,255,255,0.15)' : '1px solid rgba(255,255,255,0.05)',
                    color:        active ? '#ffffff' : 'rgba(255,255,255,0.32)',
                  }}
                >
                  {r === '' ? 'All' : r.charAt(0).toUpperCase() + r.slice(1)}
                </button>
              )
            })}
            {!noFilters && (
              <button
                onClick={() => { setFilterSeverity(''); setFilterType(''); setFilterRead('') }}
                className="px-2.5 py-1 rounded-full text-[10px] transition-colors ml-1"
                style={{ color: 'rgba(255,255,255,0.3)' }}
                onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.6)')}
                onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.3)')}
              >
                Clear filters
              </button>
            )}
          </div>
        </motion.div>

        {/* List */}
        {loading ? (
          <LoadingState />
        ) : error ? (
          <ErrorState message="Failed to load notifications." onRetry={load} />
        ) : notifications.length === 0 ? (
          <motion.div
            className="flex flex-col items-center justify-center py-20 gap-4"
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
          >
            <div className="w-12 h-12 rounded-[12px] flex items-center justify-center" style={{ background: 'rgba(139,255,62,0.06)', border: '1px solid rgba(139,255,62,0.12)' }}>
              <Bell className="w-5 h-5" style={{ color: '#8BFF3E' }} />
            </div>
            <p className="text-[14px] font-semibold text-white">
              {noFilters ? "You're all caught up" : 'No matching notifications'}
            </p>
          </motion.div>
        ) : (
          <motion.div
            className="rounded-[12px] overflow-hidden"
            style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.1 }}
          >
            {notifications.map((n, i) => {
              const sevColor = SEV_COLOR[n.severity] ?? '#9ca3af'
              return (
                <div
                  key={n.id}
                  className="flex items-start gap-3 px-5 py-3.5 group"
                  style={{
                    borderBottom: i < notifications.length - 1 ? '1px solid rgba(255,255,255,0.04)' : undefined,
                    background: n.is_read ? 'transparent' : 'rgba(255,255,255,0.01)',
                    opacity: n.is_read ? 0.65 : 1,
                    transition: 'opacity 0.15s',
                  }}
                >
                  {/* Unread indicator */}
                  <button
                    onClick={() => !n.is_read && handleMarkRead(n.id)}
                    className="mt-1.5 flex-shrink-0 w-2 h-2 rounded-full transition-all"
                    style={{
                      background: n.is_read ? 'rgba(255,255,255,0.1)' : sevColor,
                      boxShadow: n.is_read ? 'none' : `0 0 6px ${sevColor}60`,
                    }}
                    title={n.is_read ? undefined : 'Mark as read'}
                  />

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-0.5">
                      <span
                        className="px-1.5 py-0.5 rounded-full text-[9px] font-bold uppercase"
                        style={{ background: `${sevColor}18`, color: sevColor, border: `1px solid ${sevColor}35` }}
                      >
                        {n.severity}
                      </span>
                      <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.32)' }}>
                        {TYPE_LABEL[n.type] ?? n.type}
                      </span>
                    </div>
                    <p className="text-[13px] text-white truncate">{n.title}</p>
                    <p className="text-[11px] mt-0.5 line-clamp-2" style={{ color: 'rgba(255,255,255,0.38)' }}>{n.message}</p>
                    <p className="text-[10px] mt-1" style={{ color: 'rgba(255,255,255,0.22)' }}>{timeAgo(n.created_at)}</p>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                    {n.scan_result_id && (
                      <Link
                        href={`/dashboard/results/${n.scan_result_id}`}
                        className="w-7 h-7 flex items-center justify-center rounded-[6px] transition-colors"
                        style={{ color: 'rgba(255,255,255,0.3)' }}
                        onMouseEnter={e => (e.currentTarget.style.color = '#4F9CF9')}
                        onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.3)')}
                        title="View result"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </Link>
                    )}
                    <button
                      onClick={() => handleDelete(n.id)}
                      disabled={deletingId === n.id}
                      className="w-7 h-7 flex items-center justify-center rounded-[6px] transition-colors disabled:opacity-40"
                      style={{ color: 'rgba(255,255,255,0.3)' }}
                      onMouseEnter={e => (e.currentTarget.style.color = '#ef4444')}
                      onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.3)')}
                      title="Delete"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              )
            })}

            {/* Load more */}
            {hasMore && (
              <div style={{ borderTop: '1px solid rgba(255,255,255,0.04)', padding: '12px 20px' }}>
                <button
                  onClick={loadMore}
                  disabled={loadingMore}
                  className="w-full py-2 rounded-[8px] text-[12px] font-semibold transition-all disabled:opacity-50"
                  style={{ border: '1px solid rgba(255,255,255,0.07)', color: 'rgba(255,255,255,0.45)' }}
                  onMouseEnter={e => { const el = e.currentTarget; el.style.color = 'rgba(255,255,255,0.75)'; el.style.borderColor = 'rgba(255,255,255,0.12)' }}
                  onMouseLeave={e => { const el = e.currentTarget; el.style.color = 'rgba(255,255,255,0.45)'; el.style.borderColor = 'rgba(255,255,255,0.07)' }}
                >
                  {loadingMore ? 'Loading…' : `Load more (${total - notifications.length} remaining)`}
                </button>
              </div>
            )}
          </motion.div>
        )}
      </div>
    </div>
  )
}
