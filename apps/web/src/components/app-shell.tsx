'use client'

import { useState, type ReactNode } from 'react'
import { Sidebar } from './sidebar'
import { Topbar } from './topbar'
import { CommandPalette } from './command-palette'

export function AppShell({ children }: { children: ReactNode }) {
  // Mobile-only: tracks whether the off-canvas sidebar drawer is open.
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const closeMobileNav = () => setMobileNavOpen(false)

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#05080f' }}>
      <Sidebar mobileOpen={mobileNavOpen} onClose={closeMobileNav} />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Topbar onMenuClick={() => setMobileNavOpen(true)} />
        <main className="flex-1 overflow-y-auto flex flex-col">{children}</main>
      </div>
      <CommandPalette />
    </div>
  )
}
