'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import { X, Menu, ChevronDown } from 'lucide-react'
import { Logo } from './logo'

// ── Nav data ──────────────────────────────────────────────────────────────────

type DropdownItem = { label: string; href: string; desc: string }
type NavLeaf      = { label: string; href: string }
type NavGroup     = { label: string; children: DropdownItem[] }
type NavItem      = NavLeaf | NavGroup

function isGroup(item: NavItem): item is NavGroup {
  return 'children' in item
}

// Slice 3 D6 — engine name 'WADE' removed from marketing-visible
// nav (still the route slug). 'AI baseline + anomaly detection'
// was a feature description; 'Catches what other scanners miss'
// is the outcome an SBO recognises.
const NAV_ITEMS: NavItem[] = [
  {
    label: 'Product',
    children: [
      { label: 'Security scan',          href: '/scanner',    desc: 'A plain-English checkup of your website'   },
      { label: 'Continuous monitoring',  href: '/monitoring', desc: 'We watch for changes after the scan'        },
      { label: 'Smart change detection', href: '/wade',       desc: 'Catches what other scanners miss'           },
      { label: 'Reports',                href: '/reports',    desc: 'What you get in writing after every scan'   },
    ],
  },
  { label: 'Pricing', href: '/pricing' },
]

// ── Desktop dropdown ──────────────────────────────────────────────────────────

function DesktopDropdown({ item }: { item: NavGroup }) {
  const [open, setOpen]   = useState(false)
  const timerRef          = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  const enter = () => { clearTimeout(timerRef.current); setOpen(true) }
  const leave = () => { timerRef.current = setTimeout(() => setOpen(false), 120) }

  return (
    <div onMouseEnter={enter} onMouseLeave={leave} className="relative">
      <button
        className="relative px-3.5 py-2 text-[13px] font-medium text-gray-400 hover:text-white rounded-full hover:bg-white/[0.05] transition-all duration-200 flex items-center gap-1"
        aria-expanded={open}
      >
        {item.label}
        <ChevronDown
          className="w-3 h-3 transition-transform duration-200"
          style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}
        />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 6, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 4, scale: 0.97 }}
            transition={{ duration: 0.16, ease: [0.25, 0.46, 0.45, 0.94] }}
            className="absolute top-full left-1/2 -translate-x-1/2 mt-2 min-w-[230px] rounded-xl border overflow-hidden"
            style={{
              background:           'rgba(8,12,22,0.98)',
              borderColor:          'rgba(255,255,255,0.08)',
              backdropFilter:       'blur(24px)',
              WebkitBackdropFilter: 'blur(24px)',
              boxShadow:            '0 16px 48px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.04)',
            }}
          >
            <div className="p-1.5">
              {item.children.map(child => (
                <Link
                  key={child.href}
                  href={child.href}
                  className="flex flex-col px-3.5 py-2.5 rounded-lg hover:bg-white/[0.06] transition-colors group"
                >
                  <span className="text-[13px] font-medium text-white/75 group-hover:text-white transition-colors">
                    {child.label}
                  </span>
                  <span className="text-[11px] mt-0.5" style={{ color: 'rgba(255,255,255,0.30)' }}>
                    {child.desc}
                  </span>
                </Link>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ── Public nav ────────────────────────────────────────────────────────────────

export function PublicNav() {
  const [scrolled,            setScrolled]            = useState(false)
  const [mobileOpen,          setMobileOpen]          = useState(false)
  const [mobileExpandedGroup, setMobileExpandedGroup] = useState<string | null>(null)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 10)
    window.addEventListener('scroll', onScroll, { passive: true })
    onScroll()
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    if (!mobileOpen) return
    const check = () => { if (window.innerWidth >= 768) setMobileOpen(false) }
    window.addEventListener('resize', check)
    return () => window.removeEventListener('resize', check)
  }, [mobileOpen])

  useEffect(() => {
    document.body.style.overflow = mobileOpen ? 'hidden' : ''
    return () => { document.body.style.overflow = '' }
  }, [mobileOpen])

  const closeMobile = useCallback(() => {
    setMobileOpen(false)
    setMobileExpandedGroup(null)
  }, [])

  return (
    <>
      <motion.header
        className="fixed top-0 inset-x-0 z-[9999]"
        style={{ transform: 'translateZ(0)', WebkitTransform: 'translateZ(0)' }}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.35, ease: 'easeOut' }}
      >
        <div
          className="border-b transition-all duration-500"
          style={{
            background:           scrolled ? 'rgba(11,15,25,0.97)' : 'rgba(16,20,32,0.92)',
            borderColor:          scrolled ? 'rgba(139,255,62,0.12)' : 'rgba(255,255,255,0.10)',
            backdropFilter:       'blur(24px)',
            WebkitBackdropFilter: 'blur(24px)',
            boxShadow:            scrolled
              ? '0 1px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(139,255,62,0.04)'
              : '0 1px 0 rgba(255,255,255,0.06), 0 4px 24px rgba(0,0,0,0.2)',
          }}
        >
          <div className="max-w-6xl mx-auto px-5 h-16 flex items-center justify-between gap-4">
            {/* Logo */}
            <Link href="/" className="flex-shrink-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-green rounded">
              <Logo size="sm" />
            </Link>

            {/* Desktop nav */}
            <nav className="hidden md:flex items-center gap-0.5">
              {NAV_ITEMS.map(item =>
                isGroup(item) ? (
                  <DesktopDropdown key={item.label} item={item} />
                ) : (
                  <Link
                    key={item.href}
                    href={item.href}
                    className="relative px-3.5 py-2 text-[13px] font-medium text-gray-400 hover:text-white rounded-full hover:bg-white/[0.05] transition-all duration-200"
                  >
                    {item.label}
                  </Link>
                )
              )}
            </nav>

            {/* Desktop CTAs */}
            <div className="hidden md:flex items-center gap-4 flex-shrink-0">
              <Link
                href="/login"
                className="text-[13px] font-medium text-gray-400 hover:text-white transition-colors duration-200 px-3 py-2"
              >
                Sign in
              </Link>
              <Link
                href="/dashboard"
                className="text-[13px] font-semibold px-5 py-2 rounded-full bg-[#8BFF3E] text-[#020617] hover:shadow-[0_0_24px_rgba(139,255,62,0.45)] transition-all duration-300 hover:scale-[1.03]"
                style={{ boxShadow: '0 0 14px rgba(139,255,62,0.22)' }}
              >
                Start Free Scan
              </Link>
            </div>

            {/* Mobile toggle */}
            <button
              onClick={() => setMobileOpen(v => !v)}
              className="md:hidden p-2 text-gray-400 hover:text-white transition-colors rounded-lg hover:bg-white/[0.06]"
              aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={mobileOpen}
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </motion.header>

      {/* ── Mobile panel ──────────────────────────────────────────────────────── */}
      <AnimatePresence>
        {mobileOpen && (
          <>
            <motion.div
              key="pub-backdrop"
              className="fixed inset-0 z-[56] md:hidden"
              style={{ background: 'rgba(2,6,23,0.6)', backdropFilter: 'blur(4px)', WebkitBackdropFilter: 'blur(4px)' }}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.25 }}
              onClick={closeMobile}
            />

            <motion.aside
              key="pub-panel"
              role="dialog"
              aria-modal="true"
              aria-label="Navigation menu"
              className="fixed inset-y-0 right-0 z-[58] w-full max-w-[320px] flex flex-col md:hidden"
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ duration: 0.4, ease: [0.25, 0.46, 0.45, 0.94] }}
              style={{
                background:           'rgba(8,12,22,0.98)',
                backdropFilter:       'blur(40px)',
                WebkitBackdropFilter: 'blur(40px)',
                borderLeft:           '1px solid rgba(139,255,62,0.08)',
                boxShadow:            '-16px 0 60px rgba(0,0,0,0.5)',
              }}
            >
              {/* Header */}
              <div className="flex items-center justify-between px-5 pt-5 pb-5 flex-shrink-0">
                <Link href="/" onClick={closeMobile}>
                  <Logo size="sm" />
                </Link>
                <button
                  onClick={closeMobile}
                  aria-label="Close menu"
                  className="w-9 h-9 flex items-center justify-center rounded-full border border-white/10 text-white/40 hover:text-white hover:border-white/20 transition-all"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="mx-5 h-px bg-white/[0.06] flex-shrink-0" />

              {/* Links */}
              <nav className="flex-1 px-3 py-3 flex flex-col gap-0.5 overflow-y-auto">
                {NAV_ITEMS.map((item, i) => {
                  if (isGroup(item)) {
                    const expanded = mobileExpandedGroup === item.label
                    return (
                      <motion.div
                        key={item.label}
                        initial={{ opacity: 0, x: 16 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3, delay: 0.04 + i * 0.055 }}
                      >
                        <button
                          onClick={() => setMobileExpandedGroup(g => g === item.label ? null : item.label)}
                          className="flex items-center justify-between w-full px-4 py-3.5 rounded-xl text-gray-400 hover:text-white hover:bg-white/[0.05] transition-all"
                        >
                          <span className="text-[15px] font-medium">{item.label}</span>
                          <ChevronDown
                            className="w-4 h-4 transition-transform duration-200"
                            style={{ transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)' }}
                          />
                        </button>

                        <AnimatePresence initial={false}>
                          {expanded && (
                            <motion.div
                              initial={{ height: 0, opacity: 0 }}
                              animate={{ height: 'auto', opacity: 1 }}
                              exit={{ height: 0, opacity: 0 }}
                              transition={{ duration: 0.22 }}
                              className="overflow-hidden pl-3"
                            >
                              {item.children.map(child => (
                                <Link
                                  key={child.href}
                                  href={child.href}
                                  onClick={closeMobile}
                                  className="flex flex-col px-4 py-2.5 rounded-xl hover:bg-white/[0.05] transition-colors"
                                >
                                  <span className="text-[14px] font-medium text-gray-400 hover:text-white">{child.label}</span>
                                  <span className="text-[11px] mt-0.5" style={{ color: 'rgba(255,255,255,0.25)' }}>{child.desc}</span>
                                </Link>
                              ))}
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </motion.div>
                    )
                  }

                  return (
                    <motion.div
                      key={item.href}
                      initial={{ opacity: 0, x: 16 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.3, delay: 0.04 + i * 0.055 }}
                    >
                      <Link
                        href={item.href}
                        onClick={closeMobile}
                        className="flex items-center justify-between px-4 py-3.5 rounded-xl text-gray-400 hover:text-white hover:bg-white/[0.05] transition-all group"
                      >
                        <span className="text-[15px] font-medium">{item.label}</span>
                        <span className="text-transparent group-hover:text-[rgba(139,255,62,0.5)] transition-colors text-sm">→</span>
                      </Link>
                    </motion.div>
                  )
                })}
              </nav>

              {/* Bottom CTAs */}
              <div className="px-5 pb-8 pt-3 flex-shrink-0">
                <div className="h-px bg-white/[0.06] mb-4" />
                <div className="flex flex-col gap-2.5">
                  <Link
                    href="/login"
                    onClick={closeMobile}
                    className="flex items-center justify-center h-11 rounded-full border border-white/10 text-gray-400 hover:text-white hover:border-white/20 text-sm font-medium transition-all"
                  >
                    Sign in
                  </Link>
                  <Link
                    href="/dashboard"
                    onClick={closeMobile}
                    className="flex items-center justify-center h-11 rounded-full bg-[#8BFF3E] text-[#020617] text-sm font-bold transition-all hover:shadow-[0_0_24px_rgba(139,255,62,0.45)]"
                    style={{ boxShadow: '0 0 14px rgba(139,255,62,0.22)' }}
                  >
                    Start Free Scan
                  </Link>
                </div>
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  )
}
