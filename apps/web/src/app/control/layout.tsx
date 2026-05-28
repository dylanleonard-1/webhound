'use client'

// Internal /control command center — RBAC gate.
// The API (/internal/*) is the real security boundary (403 for non-staff);
// this layout hides the surface and redirects unauthorized users so the
// command center never renders for customers.
//
// It also owns the single SOC SSE connection: it polls the alert summary for
// the nav badge and fans live events out to pages via ControlEventsContext.

import { useEffect, useRef, useState, createContext, useContext, useCallback } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import Link from 'next/link'
import {
  ShieldHalf, ArrowLeft, Loader2, LayoutDashboard, ScanLine, Cpu, BellRing, Users, CreditCard, ShieldAlert, Ticket, UserCog, Rocket, FileSearch, Radar,
} from 'lucide-react'
import {
  api, getStoredToken, streamInternalEvents,
  type InternalMe, type AlertSummary, type AbuseSummary, type TicketSummary,
} from '@/lib/api'

const MeContext = createContext<InternalMe | null>(null)
export const useInternalMe = () => useContext(MeContext)

type ControlEvents = {
  summary: AlertSummary | null
  abuse: AbuseSummary | null
  tickets: TicketSummary | null
  live: boolean
  subscribe: (cb: (data: Record<string, unknown>) => void) => () => void
}
const EventsContext = createContext<ControlEvents>({ summary: null, abuse: null, tickets: null, live: false, subscribe: () => () => {} })
export const useControlEvents = () => useContext(EventsContext)

const ROLE_LABEL: Record<string, string> = {
  super_admin: 'Super Admin', admin: 'Admin', analyst: 'Analyst',
  support: 'Support', developer: 'Developer', billing: 'Billing', read_only: 'Read Only',
}

const NAV = [
  { href: '/control', label: 'Command Center', icon: LayoutDashboard, badgeKey: null },
  { href: '/control/scans', label: 'Scan Ops', icon: ScanLine, badgeKey: null },
  { href: '/control/engines', label: 'Engines', icon: Cpu, badgeKey: null },
  { href: '/control/alerts', label: 'Alerts', icon: BellRing, badgeKey: 'alerts' as const },
  { href: '/control/abuse', label: 'Abuse', icon: ShieldAlert, badgeKey: 'abuse' as const },
  { href: '/control/tickets', label: 'Tickets', icon: Ticket, badgeKey: 'tickets' as const },
  { href: '/control/customers', label: 'Customers', icon: Users, badgeKey: null },
  { href: '/control/billing', label: 'Billing', icon: CreditCard, badgeKey: null },
  { href: '/control/team', label: 'Team', icon: UserCog, badgeKey: null },
  { href: '/control/deploys', label: 'Deploys', icon: Rocket, badgeKey: null },
  { href: '/control/logs', label: 'Logs', icon: FileSearch, badgeKey: null },
  { href: '/control/threat-intel', label: 'Threat Intel', icon: Radar, badgeKey: null },
]

function ControlNav({
  openAlerts, pendingAbuse, openTickets, breachedTickets,
}: { openAlerts: number; pendingAbuse: number; openTickets: number; breachedTickets: number }) {
  const pathname = usePathname()
  return (
    <nav className="flex items-center gap-1">
      {NAV.map(({ href, label, icon: Icon, badgeKey }) => {
        const active = href === '/control' ? pathname === '/control' : pathname.startsWith(href)
        const badgeCount = badgeKey === 'alerts' ? openAlerts
          : badgeKey === 'abuse' ? pendingAbuse
          : badgeKey === 'tickets' ? openTickets
          : 0
        const isBreach = badgeKey === 'tickets' && breachedTickets > 0
        return (
          <Link key={href} href={href}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-medium transition-colors"
                style={active
                  ? { background: 'rgba(139,255,62,0.1)', color: '#8BFF3E', border: '1px solid rgba(139,255,62,0.2)' }
                  : { color: 'rgba(255,255,255,0.5)', border: '1px solid transparent' }}>
            <Icon className="w-3.5 h-3.5" /> {label}
            {badgeCount > 0 && (
              <span className="ml-0.5 text-[10px] font-bold px-1.5 py-0.5 rounded-full"
                    style={{ background: isBreach ? '#ef4444' : '#f59e0b', color: '#fff' }}>{badgeCount}</span>
            )}
          </Link>
        )
      })}
    </nav>
  )
}

export default function ControlLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const [state, setState] = useState<'checking' | 'ok'>('checking')
  const [me, setMe] = useState<InternalMe | null>(null)
  const [summary, setSummary] = useState<AlertSummary | null>(null)
  const [abuse, setAbuse] = useState<AbuseSummary | null>(null)
  const [tickets, setTickets] = useState<TicketSummary | null>(null)
  const [live, setLive] = useState(false)
  const listeners = useRef(new Set<(d: Record<string, unknown>) => void>())

  const subscribe = useCallback((cb: (d: Record<string, unknown>) => void) => {
    listeners.current.add(cb)
    return () => { listeners.current.delete(cb) }
  }, [])

  useEffect(() => {
    if (!getStoredToken()) { router.replace('/login?next=/control'); return }
    let cancelled = false
    api.internal.me()
      .then(m => { if (!cancelled) { setMe(m); setState('ok') } })
      .catch(() => { if (!cancelled) router.replace('/') })  // 401/403 → bounce, no trace
    return () => { cancelled = true }
  }, [router])

  // Once authenticated: poll the alert summary + open one shared SSE stream.
  useEffect(() => {
    if (state !== 'ok') return
    let cancelled = false
    const loadAll = () => {
      api.internal.alertsSummary().then(s => { if (!cancelled) setSummary(s) }).catch(() => {})
      api.internal.abuseSummary().then(s => { if (!cancelled) setAbuse(s) }).catch(() => {})
      api.internal.ticketsSummary().then(s => { if (!cancelled) setTickets(s) }).catch(() => {})
    }
    loadAll()
    const poll = setInterval(loadAll, 30000)
    const stop = streamInternalEvents(
      (data) => {
        setLive(true)
        loadAll()
        listeners.current.forEach(cb => cb(data))
      },
      () => setLive(false),
    )
    return () => { cancelled = true; clearInterval(poll); stop() }
  }, [state])

  if (state === 'checking') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#05070d]">
        <Loader2 className="w-5 h-5 animate-spin" style={{ color: '#8BFF3E' }} />
      </div>
    )
  }

  return (
    <MeContext.Provider value={me}>
      <EventsContext.Provider value={{ summary, abuse, tickets, live, subscribe }}>
        <div className="min-h-screen bg-[#05070d] text-gray-100"
             style={{ backgroundImage: 'radial-gradient(900px 500px at 80% -10%, rgba(139,255,62,0.05), transparent)' }}>
          <header className="sticky top-0 z-30 border-b border-white/[0.06] bg-[#05070d]/85 backdrop-blur">
            <div className="max-w-[1400px] mx-auto px-5 h-14 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <ShieldHalf className="w-5 h-5" style={{ color: '#8BFF3E' }} />
                <span className="font-bold tracking-tight text-[15px]">WebHound</span>
                <span className="text-[10px] font-black tracking-[0.22em] uppercase px-1.5 py-0.5 rounded"
                      style={{ background: 'rgba(139,255,62,0.1)', color: '#8BFF3E', border: '1px solid rgba(139,255,62,0.2)' }}>
                  Control
                </span>
                <span className="flex items-center gap-1 text-[10px]" title={live ? 'Realtime connected' : 'Realtime offline'}>
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: live ? '#8BFF3E' : 'rgba(255,255,255,0.25)', boxShadow: live ? '0 0 6px #8BFF3E' : 'none' }} />
                  <span style={{ color: 'rgba(255,255,255,0.35)' }}>{live ? 'LIVE' : 'offline'}</span>
                </span>
              </div>
              <div className="flex items-center gap-4 text-[12px]">
                {me && (
                  <span style={{ color: 'rgba(255,255,255,0.55)' }}>
                    {me.email} · <span style={{ color: '#8BFF3E' }}>{ROLE_LABEL[me.role] ?? me.role}</span>
                  </span>
                )}
                <Link href="/dashboard" className="flex items-center gap-1 hover:text-white transition-colors"
                      style={{ color: 'rgba(255,255,255,0.45)' }}>
                  <ArrowLeft className="w-3.5 h-3.5" /> App
                </Link>
              </div>
            </div>
            <div className="max-w-[1400px] mx-auto px-5 pb-2.5">
              <ControlNav
                openAlerts={summary?.open ?? 0}
                pendingAbuse={abuse?.pending ?? 0}
                openTickets={tickets?.open ?? 0}
                breachedTickets={tickets?.breached ?? 0}
              />
            </div>
          </header>
          <main className="max-w-[1400px] mx-auto px-5 py-6">{children}</main>
        </div>
      </EventsContext.Provider>
    </MeContext.Provider>
  )
}
