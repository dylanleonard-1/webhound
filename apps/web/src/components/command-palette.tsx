'use client'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { Command } from 'cmdk'
import {
  LayoutDashboard, Globe, ScanLine, Activity, Bell, Settings,
  FileText, Search, Zap, LogOut, Plus, ArrowRight, Shield,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth'

interface CommandItem {
  id: string
  label: string
  description?: string
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  action: () => void
  group: string
  keywords?: string
}

// ── Palette ───────────────────────────────────────────────────────────────────

export function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const router = useRouter()
  const { logout } = useAuth()

  const go = useCallback((href: string) => {
    setOpen(false)
    router.push(href)
  }, [router])

  const ITEMS: CommandItem[] = [
    { id: 'overview',     group: 'Navigate', label: 'Overview',         description: 'Dashboard home',        icon: LayoutDashboard, action: () => go('/dashboard') },
    { id: 'websites',     group: 'Navigate', label: 'Websites',          description: 'Monitored targets',     icon: Globe,           action: () => go('/dashboard/websites') },
    { id: 'scans',        group: 'Navigate', label: 'Scans',             description: 'Scan history',          icon: ScanLine,        action: () => go('/dashboard/scans') },
    { id: 'monitoring',   group: 'Navigate', label: 'Monitoring',        description: 'Schedules & anomalies', icon: Activity,        action: () => go('/dashboard/monitoring') },
    { id: 'alerts',       group: 'Navigate', label: 'Alerts',            description: 'Notifications center', icon: Bell,            action: () => go('/dashboard/notifications') },
    { id: 'settings',     group: 'Navigate', label: 'Settings',          description: 'Account & API keys',   icon: Settings,        action: () => go('/dashboard/settings') },
    { id: 'new-scan',     group: 'Actions',  label: 'New Scan',          description: 'Start a new scan',     icon: Plus,            action: () => go('/dashboard/websites/new'), keywords: 'add create scan' },
    { id: 'docs',         group: 'Resources',label: 'Documentation',     description: 'WebHound docs',        icon: FileText,        action: () => go('/docs') },
    { id: 'logout',       group: 'Account',  label: 'Sign Out',          description: 'Log out of WebHound',  icon: LogOut,          action: () => { setOpen(false); logout() } },
  ]

  const GROUPS = ['Navigate', 'Actions', 'Resources', 'Account'] as const

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if ((e.key === 'k' && (e.metaKey || e.ctrlKey)) || e.key === '/') {
        e.preventDefault()
        setOpen(v => !v)
      }
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('keydown', down)
    return () => document.removeEventListener('keydown', down)
  }, [])

  if (!open) return null

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-[10000]"
        style={{ background: 'rgba(2,6,23,0.7)', backdropFilter: 'blur(8px)', WebkitBackdropFilter: 'blur(8px)' }}
        onClick={() => setOpen(false)}
      />

      {/* Panel */}
      <div
        className="fixed top-[20vh] left-1/2 -translate-x-1/2 z-[10001] w-full max-w-[540px] px-4"
      >
        <Command
          label="Command menu"
          shouldFilter={true}
          className="rounded-[16px] overflow-hidden shadow-2xl"
          style={{
            background: 'rgba(6,9,18,0.98)',
            border: '1px solid rgba(255,255,255,0.09)',
            boxShadow: '0 24px 80px rgba(0,0,0,0.8), 0 0 0 1px rgba(255,255,255,0.04)',
          }}
        >
          {/* Search input */}
          <div className="flex items-center gap-3 px-4 py-3.5" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <Search className="w-4 h-4 flex-shrink-0" style={{ color: 'rgba(255,255,255,0.3)' }} />
            <Command.Input
              value={search}
              onValueChange={setSearch}
              placeholder="Search commands, pages, actions…"
              className="flex-1 bg-transparent text-[14px] text-white placeholder-[rgba(255,255,255,0.28)] outline-none"
            />
            <kbd
              className="flex-shrink-0 px-1.5 py-0.5 rounded text-[10px] font-mono"
              style={{ background: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.35)', border: '1px solid rgba(255,255,255,0.08)' }}
            >
              ESC
            </kbd>
          </div>

          {/* Results */}
          <Command.List className="max-h-[360px] overflow-y-auto py-2" style={{ scrollbarWidth: 'none' }}>
            <Command.Empty className="py-10 text-center text-[13px]" style={{ color: 'rgba(255,255,255,0.3)' }}>
              No results for &ldquo;{search}&rdquo;
            </Command.Empty>

            {GROUPS.map(group => {
              const groupItems = ITEMS.filter(i => i.group === group)
              return (
                <Command.Group
                  key={group}
                  heading={group}
                  className="[&_[cmdk-group-heading]]:text-[9px] [&_[cmdk-group-heading]]:font-black [&_[cmdk-group-heading]]:tracking-[0.18em] [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:px-4 [&_[cmdk-group-heading]]:py-2"
                  style={{ '--cmdk-group-heading-color': 'rgba(255,255,255,0.25)' } as React.CSSProperties}
                >
                  {groupItems.map(item => (
                    <Command.Item
                      key={item.id}
                      value={`${item.label} ${item.description ?? ''} ${item.keywords ?? ''}`}
                      onSelect={item.action}
                      className="flex items-center gap-3 px-4 py-2.5 mx-2 rounded-[9px] cursor-pointer transition-all duration-100 data-[selected=true]:bg-[rgba(139,255,62,0.08)]"
                    >
                      <div
                        className="w-7 h-7 rounded-[8px] flex items-center justify-center flex-shrink-0"
                        style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}
                      >
                        <item.icon className="w-3.5 h-3.5" style={{ color: 'rgba(255,255,255,0.55)' }} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-[13px] font-medium text-white">{item.label}</p>
                        {item.description && (
                          <p className="text-[11px] truncate" style={{ color: 'rgba(255,255,255,0.32)' }}>
                            {item.description}
                          </p>
                        )}
                      </div>
                      <ArrowRight className="w-3.5 h-3.5 opacity-0 data-[selected=true]:opacity-100 flex-shrink-0" style={{ color: 'rgba(139,255,62,0.6)' }} />
                    </Command.Item>
                  ))}
                </Command.Group>
              )
            })}
          </Command.List>

          {/* Footer */}
          <div
            className="flex items-center justify-between px-4 py-2.5"
            style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}
          >
            <div className="flex items-center gap-1.5">
              <div className="w-4 h-4 rounded-[4px] flex items-center justify-center" style={{ background: '#8BFF3E' }}>
                <Shield className="w-2.5 h-2.5 text-[#020617]" strokeWidth={2.5} />
              </div>
              <span className="text-[10px] font-bold tracking-wide" style={{ color: 'rgba(255,255,255,0.28)' }}>
                WebHound
              </span>
            </div>
            <div className="flex items-center gap-3">
              {[
                { keys: ['↑', '↓'], label: 'Navigate' },
                { keys: ['↵'], label: 'Select' },
                { keys: ['⌘', 'K'], label: 'Toggle' },
              ].map(({ keys, label }) => (
                <div key={label} className="flex items-center gap-1">
                  <div className="flex gap-0.5">
                    {keys.map(k => (
                      <kbd
                        key={k}
                        className="px-1 py-0.5 rounded text-[9px] font-mono"
                        style={{ background: 'rgba(255,255,255,0.05)', color: 'rgba(255,255,255,0.3)', border: '1px solid rgba(255,255,255,0.07)' }}
                      >
                        {k}
                      </kbd>
                    ))}
                  </div>
                  <span className="text-[9px]" style={{ color: 'rgba(255,255,255,0.22)' }}>{label}</span>
                </div>
              ))}
            </div>
          </div>
        </Command>
      </div>
    </>
  )
}
