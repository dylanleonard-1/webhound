'use client'

import { usePathname } from 'next/navigation'
import Link from 'next/link'
import { Bell, Plus, Search, ChevronRight, Menu } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api } from '@/lib/api'

interface Crumb { label: string; href?: string }

function buildCrumbs(pathname: string): Crumb[] {
  const exact: Record<string, string> = {
    '/dashboard':                    'Overview',
    '/dashboard/websites':           'Websites',
    '/dashboard/websites/new':       'New Website',
    '/dashboard/scans':              'Scans',
    '/dashboard/monitoring':         'Monitoring',
    '/dashboard/notifications':      'Alerts',
    '/dashboard/settings':           'Settings',
  }
  if (exact[pathname]) return [{ label: exact[pathname] }]
  if (/^\/dashboard\/websites\/[^/]+\/monitoring$/.test(pathname))
    return [{ label: 'Websites', href: '/dashboard/websites' }, { label: 'Monitoring' }]
  if (/^\/dashboard\/websites\/[^/]+$/.test(pathname))
    return [{ label: 'Websites', href: '/dashboard/websites' }, { label: 'Detail' }]
  if (/^\/dashboard\/scans\/[^/]+$/.test(pathname))
    return [{ label: 'Scans', href: '/dashboard/scans' }, { label: 'Scan Job' }]
  if (/^\/dashboard\/results\/[^/]+$/.test(pathname))
    return [{ label: 'Scans', href: '/dashboard/scans' }, { label: 'Results' }]
  return [{ label: 'Dashboard' }]
}

interface TopbarProps {
  onMenuClick?: () => void
}

export function Topbar({ onMenuClick }: TopbarProps) {
  const pathname = usePathname()
  const crumbs = buildCrumbs(pathname)
  const [unread, setUnread] = useState(0)

  useEffect(() => {
    api.notifications.unreadCount().then(r => setUnread(r.count)).catch(() => {})
  }, [pathname])

  // On mobile we only show the last crumb so the title doesn't wrap or overflow.
  const mobileCrumb = crumbs[crumbs.length - 1]

  return (
    <header
      className="h-[57px] flex items-center justify-between px-3 sm:px-6 flex-shrink-0 gap-2 sm:gap-4"
      style={{
        background: 'rgba(5,8,16,0.95)',
        borderBottom: '1px solid rgba(255,255,255,0.055)',
        backdropFilter: 'blur(12px)',
      }}
    >
      {/* ── Left: mobile menu + breadcrumb ──────────────────────── */}
      <div className="flex items-center gap-2 min-w-0 flex-1">
        <button
          type="button"
          onClick={onMenuClick}
          className="md:hidden flex items-center justify-center w-9 h-9 rounded-[8px] flex-shrink-0"
          style={{ color: 'rgba(255,255,255,0.7)', border: '1px solid rgba(255,255,255,0.07)' }}
          aria-label="Open menu"
        >
          <Menu className="w-4 h-4" />
        </button>

        {/* Mobile: just the current page label */}
        <div className="md:hidden min-w-0 flex-1">
          <span className="text-[14px] font-semibold text-white truncate block">
            {mobileCrumb.label}
          </span>
        </div>

        {/* Desktop: full breadcrumb */}
        <div className="hidden md:flex items-center gap-1.5 min-w-0">
          {crumbs.map((c, i) => (
            <div key={i} className="flex items-center gap-1.5 min-w-0">
              {i > 0 && (
                <ChevronRight className="w-3 h-3 flex-shrink-0" style={{ color: 'rgba(255,255,255,0.2)' }} />
              )}
              {c.href ? (
                <Link
                  href={c.href}
                  className="text-[13px] font-medium transition-colors truncate"
                  style={{ color: 'rgba(255,255,255,0.38)' }}
                  onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.7)')}
                  onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.38)')}
                >
                  {c.label}
                </Link>
              ) : (
                <span className="text-[13px] font-semibold text-white truncate">{c.label}</span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* ── Right: actions ────────────────────────────────────── */}
      <div className="flex items-center gap-2 flex-shrink-0">
        <button
          className="hidden md:flex items-center gap-2 px-3 py-[6px] rounded-[8px] text-[11px] transition-all duration-150"
          style={{
            background: 'rgba(255,255,255,0.03)',
            border: '1px solid rgba(255,255,255,0.06)',
            color: 'rgba(255,255,255,0.28)',
          }}
          onClick={() => {
            const e = new KeyboardEvent('keydown', { key: 'k', metaKey: true, bubbles: true })
            document.dispatchEvent(e)
          }}
        >
          <Search className="w-3 h-3" />
          <span>Search…</span>
          <div className="flex items-center gap-0.5 ml-1">
            <kbd className="px-1 py-0.5 rounded text-[9px] font-mono" style={{ background: 'rgba(255,255,255,0.05)' }}>⌘</kbd>
            <kbd className="px-1 py-0.5 rounded text-[9px] font-mono" style={{ background: 'rgba(255,255,255,0.05)' }}>K</kbd>
          </div>
        </button>

        {/* New Scan CTA — icon-only on small screens */}
        <Link href="/dashboard/websites/new">
          <button
            className="flex items-center gap-1.5 px-2.5 sm:px-3 py-[6px] rounded-[8px] text-[12px] font-semibold transition-all duration-200"
            style={{
              background: 'rgba(139,255,62,0.1)',
              border: '1px solid rgba(139,255,62,0.3)',
              color: '#8BFF3E',
            }}
            onMouseEnter={e => {
              const el = e.currentTarget
              el.style.background = 'rgba(139,255,62,0.16)'
              el.style.borderColor = 'rgba(139,255,62,0.5)'
            }}
            onMouseLeave={e => {
              const el = e.currentTarget
              el.style.background = 'rgba(139,255,62,0.1)'
              el.style.borderColor = 'rgba(139,255,62,0.3)'
            }}
            aria-label="New Scan"
          >
            <Plus className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">New Scan</span>
          </button>
        </Link>

        {/* Notifications */}
        <Link
          href="/dashboard/notifications"
          className="relative w-8 h-8 flex items-center justify-center rounded-[8px] transition-all duration-150"
          style={{ color: 'rgba(255,255,255,0.38)', border: '1px solid rgba(255,255,255,0.07)' }}
          onMouseEnter={e => {
            const el = e.currentTarget as HTMLElement
            el.style.color = 'rgba(255,255,255,0.75)'
            el.style.background = 'rgba(255,255,255,0.05)'
          }}
          onMouseLeave={e => {
            const el = e.currentTarget as HTMLElement
            el.style.color = 'rgba(255,255,255,0.38)'
            el.style.background = 'transparent'
          }}
          title="Notifications"
        >
          <Bell className="w-4 h-4" />
          {unread > 0 && (
            <span
              className="absolute -top-1 -right-1 min-w-[16px] h-4 rounded-full flex items-center justify-center text-[9px] font-black px-0.5"
              style={{ background: '#8BFF3E', color: '#020617' }}
            >
              {unread > 9 ? '9+' : unread}
            </span>
          )}
        </Link>
      </div>
    </header>
  )
}
