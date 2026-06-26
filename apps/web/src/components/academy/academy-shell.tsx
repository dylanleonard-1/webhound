'use client'

import { useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { GraduationCap, Menu, X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { ACADEMY_NAV, ACADEMY_BASE } from '@/lib/academy/pca-risk'

function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname()
  return (
    <nav className="space-y-1">
      {ACADEMY_NAV.map((item) => {
        const active = pathname === item.href ||
          (item.href !== ACADEMY_BASE && pathname.startsWith(item.href))
        return (
          <div key={item.label}>
            <Link
              href={item.href}
              onClick={onNavigate}
              className={cn(
                'block rounded-lg px-3 py-2 text-sm transition-colors',
                active ? 'bg-accent-green/10 text-accent-green'
                       : 'text-slate-400 hover:bg-white/5 hover:text-white',
              )}
            >
              {item.label}
            </Link>
            {item.children ? (
              <div className="ml-3 mt-1 space-y-0.5 border-l border-app-border pl-3">
                {item.children.map((c) => {
                  const cActive = pathname === c.href
                  return (
                    <Link
                      key={c.href}
                      href={c.href}
                      onClick={onNavigate}
                      className={cn(
                        'block rounded-md px-2 py-1.5 text-xs transition-colors',
                        cActive ? 'text-accent-green' : 'text-slate-500 hover:text-slate-200',
                      )}
                    >
                      {c.label}
                    </Link>
                  )
                })}
              </div>
            ) : null}
          </div>
        )
      })}
    </nav>
  )
}

export function AcademyShell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="min-h-screen bg-app-bg text-white">
      {/* Top bar (mobile + brand) */}
      <header className="sticky top-0 z-30 flex items-center justify-between border-b border-app-border bg-app-bg/90 px-4 py-3 backdrop-blur md:px-6">
        <Link href={ACADEMY_BASE} className="flex items-center gap-2">
          <GraduationCap className="h-5 w-5 text-accent-green" />
          <span className="text-sm font-bold tracking-tight">PCA Risk Academy</span>
          <span className="hidden text-xs text-slate-500 sm:inline">· private study</span>
        </Link>
        <button
          type="button"
          aria-label="Toggle menu"
          onClick={() => setOpen((v) => !v)}
          className="rounded-lg p-2 text-slate-300 hover:bg-white/5 md:hidden"
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </header>

      <div className="mx-auto flex max-w-6xl gap-6 px-4 py-6 md:px-6">
        {/* Desktop sidebar */}
        <aside className="hidden w-56 shrink-0 md:block">
          <div className="sticky top-20">
            <NavLinks />
          </div>
        </aside>

        {/* Mobile drawer */}
        {open ? (
          <div className="fixed inset-0 z-40 md:hidden">
            <div className="absolute inset-0 bg-black/60" onClick={() => setOpen(false)} />
            <div className="absolute left-0 top-0 h-full w-64 overflow-y-auto border-r border-app-border bg-app-surface p-4">
              <NavLinks onNavigate={() => setOpen(false)} />
            </div>
          </div>
        ) : null}

        <main className="min-w-0 flex-1">{children}</main>
      </div>
    </div>
  )
}
