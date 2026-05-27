'use client'

// Internal /control command center — RBAC gate.
// The API (/internal/*) is the real security boundary (403 for non-staff);
// this layout hides the surface and redirects unauthorized users so the
// command center never renders for customers.

import { useEffect, useState, createContext, useContext } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import Link from 'next/link'
import { ShieldHalf, ArrowLeft, Loader2, LayoutDashboard, ScanLine, Cpu } from 'lucide-react'
import { api, getStoredToken, type InternalMe } from '@/lib/api'

const MeContext = createContext<InternalMe | null>(null)
export const useInternalMe = () => useContext(MeContext)

const ROLE_LABEL: Record<string, string> = {
  super_admin: 'Super Admin', admin: 'Admin', analyst: 'Analyst',
  support: 'Support', developer: 'Developer', billing: 'Billing', read_only: 'Read Only',
}

const NAV = [
  { href: '/control', label: 'Command Center', icon: LayoutDashboard },
  { href: '/control/scans', label: 'Scan Ops', icon: ScanLine },
  { href: '/control/engines', label: 'Engines', icon: Cpu },
]

function ControlNav() {
  const pathname = usePathname()
  return (
    <nav className="flex items-center gap-1">
      {NAV.map(({ href, label, icon: Icon }) => {
        const active = href === '/control' ? pathname === '/control' : pathname.startsWith(href)
        return (
          <Link key={href} href={href}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-medium transition-colors"
                style={active
                  ? { background: 'rgba(139,255,62,0.1)', color: '#8BFF3E', border: '1px solid rgba(139,255,62,0.2)' }
                  : { color: 'rgba(255,255,255,0.5)', border: '1px solid transparent' }}>
            <Icon className="w-3.5 h-3.5" /> {label}
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

  useEffect(() => {
    if (!getStoredToken()) { router.replace('/login?next=/control'); return }
    let cancelled = false
    api.internal.me()
      .then(m => { if (!cancelled) { setMe(m); setState('ok') } })
      .catch(() => { if (!cancelled) router.replace('/') })  // 401/403 → bounce, no trace
    return () => { cancelled = true }
  }, [router])

  if (state === 'checking') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#05070d]">
        <Loader2 className="w-5 h-5 animate-spin" style={{ color: '#8BFF3E' }} />
      </div>
    )
  }

  return (
    <MeContext.Provider value={me}>
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
            <ControlNav />
          </div>
        </header>
        <main className="max-w-[1400px] mx-auto px-5 py-6">{children}</main>
      </div>
    </MeContext.Provider>
  )
}
