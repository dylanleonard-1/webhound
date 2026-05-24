'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useEffect } from 'react'
import Image from 'next/image'
import {
  LayoutDashboard, Globe, ScanLine, Activity, Bell,
  Settings, LogOut, X,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useAuth } from '@/contexts/auth'

const NAV = [
  {
    section: 'Platform',
    items: [
      { href: '/dashboard',          label: 'Overview',      icon: LayoutDashboard, exact: true  },
      { href: '/dashboard/websites', label: 'Websites',      icon: Globe,           exact: false },
      { href: '/dashboard/scans',    label: 'Scans',         icon: ScanLine,        exact: false },
    ],
  },
  {
    section: 'Intelligence',
    items: [
      { href: '/dashboard/monitoring',    label: 'Monitoring', icon: Activity, exact: false },
      { href: '/dashboard/notifications', label: 'Alerts',     icon: Bell,     exact: false },
    ],
  },
  {
    section: 'Account',
    items: [
      { href: '/dashboard/settings', label: 'Settings', icon: Settings, exact: false },
    ],
  },
]

function activeLink(pathname: string, href: string, exact: boolean) {
  return exact ? pathname === href : pathname.startsWith(href)
}

interface SidebarProps {
  mobileOpen?: boolean
  onClose?: () => void
}

export function Sidebar({ mobileOpen = false, onClose }: SidebarProps) {
  const pathname = usePathname()
  const { user, logout } = useAuth()

  // Auto-close the drawer when the route changes on mobile.
  useEffect(() => {
    if (mobileOpen && onClose) onClose()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathname])

  // Lock body scroll while drawer is open on mobile.
  useEffect(() => {
    if (typeof document === 'undefined') return
    const prev = document.body.style.overflow
    if (mobileOpen) document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = prev
    }
  }, [mobileOpen])

  return (
    <>
      {/* Backdrop (mobile only) */}
      {mobileOpen && (
        <button
          type="button"
          aria-label="Close menu"
          onClick={onClose}
          className="md:hidden fixed inset-0 z-30"
          style={{ background: 'rgba(0,0,0,0.55)', backdropFilter: 'blur(2px)' }}
        />
      )}

      <aside
        className={cn(
          'w-[260px] md:w-[216px] flex-shrink-0 flex flex-col h-full',
          // mobile: off-canvas drawer
          'fixed md:static inset-y-0 left-0 z-40 transition-transform duration-200 ease-out md:transition-none',
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
        )}
        style={{
          background: 'linear-gradient(180deg, #05080f 0%, #060a14 100%)',
          borderRight: '1px solid rgba(255,255,255,0.055)',
        }}
      >
        {/* ── Logo + close button (mobile) ────────────────────── */}
        <div
          className="flex items-center justify-between gap-2.5 px-4 h-[57px] flex-shrink-0"
          style={{ borderBottom: '1px solid rgba(255,255,255,0.055)' }}
        >
          <Link href="/dashboard" className="flex items-center gap-2.5">
            <Image
              src="/logo.png"
              alt="WebHound"
              width={32}
              height={32}
              priority
              className="flex-shrink-0 select-none"
              style={{ width: 32, height: 32, objectFit: 'contain' }}
            />
            <span className="font-bold text-white text-[13.5px] tracking-[-0.01em]">WebHound</span>
          </Link>
          <button
            type="button"
            onClick={onClose}
            className="md:hidden p-1 rounded-md"
            style={{ color: 'rgba(255,255,255,0.45)' }}
            aria-label="Close menu"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* ── Navigation ────────────────────────────────────────── */}
        <nav className="flex-1 overflow-y-auto py-3" style={{ scrollbarWidth: 'none' }}>
          {NAV.map(({ section, items }) => (
            <div key={section} className="mb-4">
              <div className="px-4 pb-1.5 pt-1">
                <span
                  className="text-[9px] font-black tracking-[0.20em] uppercase"
                  style={{ color: 'rgba(255,255,255,0.22)' }}
                >
                  {section}
                </span>
              </div>

              <div className="px-2 flex flex-col gap-0.5">
                {items.map(({ href, label, icon: Icon, exact }) => {
                  const active = activeLink(pathname, href, exact)
                  return (
                    <Link
                      key={href}
                      href={href}
                      className={cn(
                        'relative flex items-center gap-2.5 px-3 py-[10px] md:py-[8px] rounded-[9px] text-[14px] md:text-[13px] font-medium transition-all duration-150',
                        active
                          ? 'text-white'
                          : 'text-[rgba(255,255,255,0.4)] hover:text-[rgba(255,255,255,0.72)] hover:bg-[rgba(255,255,255,0.035)]',
                      )}
                      style={active ? { background: 'rgba(139,255,62,0.09)' } : {}}
                    >
                      {active && (
                        <div
                          className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-4 rounded-r-full"
                          style={{ background: '#8BFF3E', boxShadow: '0 0 8px rgba(139,255,62,0.7)' }}
                        />
                      )}

                      <Icon
                        className={cn(
                          'w-[15px] h-[15px] flex-shrink-0 transition-colors',
                          active ? 'text-[#8BFF3E]' : 'text-current',
                        )}
                        strokeWidth={active ? 2.25 : 1.75}
                      />
                      {label}
                    </Link>
                  )
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* ── User footer ───────────────────────────────────────── */}
        <div
          className="flex-shrink-0 p-3"
          style={{ borderTop: '1px solid rgba(255,255,255,0.055)' }}
        >
          <div
            className="flex items-center gap-2.5 px-2.5 py-2 rounded-[9px]"
            style={{ background: 'rgba(255,255,255,0.025)' }}
          >
            <div
              className="w-[26px] h-[26px] rounded-full flex items-center justify-center flex-shrink-0 text-[10px] font-black"
              style={{ background: 'rgba(139,255,62,0.12)', color: '#8BFF3E' }}
            >
              {user?.email?.[0]?.toUpperCase() ?? '?'}
            </div>
            <div className="flex-1 min-w-0">
              <p
                className="text-[11px] font-medium truncate"
                style={{ color: 'rgba(255,255,255,0.55)' }}
              >
                {user?.email}
              </p>
            </div>
            <button
              onClick={logout}
              title="Sign out"
              className="p-[5px] rounded-md transition-colors"
              style={{ color: 'rgba(255,255,255,0.22)' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'rgba(239,68,68,0.8)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.22)')}
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </aside>
    </>
  )
}
