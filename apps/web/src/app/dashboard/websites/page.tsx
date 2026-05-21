'use client'

import { useEffect, useState, useCallback } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { Globe, Plus, RefreshCw, ExternalLink, ChevronRight, ShieldCheck, ShieldAlert, Clock, Shield } from 'lucide-react'
import { api, type WebsiteResponse } from '@/lib/api'
import { LoadingState } from '@/components/loading-state'
import { ErrorState } from '@/components/error-state'

const VERIFICATION: Record<string, { label: string; color: string; bg: string; border: string; icon: React.FC<{ className?: string; style?: React.CSSProperties }> }> = {
  verified:   { label: 'Verified',   color: '#8BFF3E', bg: 'rgba(139,255,62,0.08)',  border: 'rgba(139,255,62,0.22)',  icon: ShieldCheck  },
  pending:    { label: 'Pending',    color: '#4F9CF9', bg: 'rgba(79,156,249,0.1)',   border: 'rgba(79,156,249,0.25)',  icon: Clock        },
  failed:     { label: 'Failed',     color: '#ef4444', bg: 'rgba(239,68,68,0.1)',    border: 'rgba(239,68,68,0.25)',   icon: ShieldAlert  },
  unverified: { label: 'Unverified', color: '#9ca3af', bg: 'rgba(107,114,128,0.08)', border: 'rgba(107,114,128,0.2)', icon: Shield       },
}

function timeAgo(ts: string) {
  const diff = Date.now() - new Date(ts).getTime()
  const d = Math.floor(diff / 86400000)
  if (d === 0) return 'today'
  if (d === 1) return 'yesterday'
  if (d < 30) return `${d}d ago`
  const mo = Math.floor(d / 30)
  return `${mo}mo ago`
}

export default function WebsitesPage() {
  const [items, setItems] = useState<WebsiteResponse[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.websites.list({ limit: 100 })
      setItems(res.items)
      setTotal(res.total)
    } catch {
      setError('Failed to load websites.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
      <div className="max-w-[1100px] mx-auto px-6 py-8 space-y-6">

        {/* Header */}
        <motion.div
          className="flex items-start justify-between"
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}
        >
          <div>
            <h1 className="text-[22px] font-bold text-white tracking-tight">Websites</h1>
            <p className="text-[13px] mt-0.5" style={{ color: 'rgba(255,255,255,0.35)' }}>
              {loading ? '—' : `${total} site${total !== 1 ? 's' : ''} monitored`}
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
                Add Website
              </button>
            </Link>
          </div>
        </motion.div>

        {/* Content */}
        {loading ? (
          <LoadingState />
        ) : error ? (
          <ErrorState message={error} onRetry={load} />
        ) : items.length === 0 ? (
          <motion.div
            className="flex flex-col items-center justify-center py-20 gap-4"
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}
          >
            <div className="w-12 h-12 rounded-[12px] flex items-center justify-center" style={{ background: 'rgba(139,255,62,0.06)', border: '1px solid rgba(139,255,62,0.12)' }}>
              <Globe className="w-5 h-5" style={{ color: '#8BFF3E' }} />
            </div>
            <p className="text-[14px] font-semibold text-white">No websites yet</p>
            <p className="text-[12px]" style={{ color: 'rgba(255,255,255,0.35)' }}>
              Add a website to start monitoring for security issues
            </p>
            <Link href="/dashboard/websites/new">
              <button
                className="px-4 py-2 rounded-[8px] text-[12px] font-semibold"
                style={{ background: 'rgba(139,255,62,0.1)', border: '1px solid rgba(139,255,62,0.3)', color: '#8BFF3E' }}
              >
                Add your first website
              </button>
            </Link>
          </motion.div>
        ) : (
          <motion.div
            className="rounded-[12px] overflow-hidden"
            style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.05 }}
          >
            {items.map((site, i) => {
              const v = VERIFICATION[site.verification_status] ?? VERIFICATION.unverified
              const VIcon = v.icon
              return (
                <Link
                  key={site.id}
                  href={`/dashboard/websites/${site.id}`}
                  className="flex items-center gap-4 px-5 py-3.5 group transition-colors"
                  style={{ borderBottom: i < items.length - 1 ? '1px solid rgba(255,255,255,0.04)' : undefined }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.02)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  {/* Icon */}
                  <div className="w-8 h-8 rounded-[8px] flex items-center justify-center flex-shrink-0" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}>
                    <Globe className="w-3.5 h-3.5" style={{ color: 'rgba(255,255,255,0.4)' }} />
                  </div>

                  {/* URL + meta */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-[13px] font-mono font-medium text-white truncate">
                        {site.hostname}
                      </span>
                      {site.display_name && (
                        <span className="text-[11px] px-1.5 py-0.5 rounded-full flex-shrink-0" style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.35)' }}>
                          {site.display_name}
                        </span>
                      )}
                    </div>
                    <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.28)' }}>
                      {site.url} · Added {timeAgo(site.created_at)}
                    </span>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span
                      className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wide"
                      style={{ background: v.bg, color: v.color, border: `1px solid ${v.border}` }}
                    >
                      <VIcon className="w-2.5 h-2.5" />
                      {v.label}
                    </span>
                    <a
                      href={site.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={e => e.stopPropagation()}
                      className="w-6 h-6 flex items-center justify-center rounded-[6px] opacity-0 group-hover:opacity-100 transition-opacity"
                      style={{ color: 'rgba(255,255,255,0.35)' }}
                      title="Open site"
                    >
                      <ExternalLink className="w-3 h-3" />
                    </a>
                    <ChevronRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: 'rgba(255,255,255,0.3)' }} />
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
