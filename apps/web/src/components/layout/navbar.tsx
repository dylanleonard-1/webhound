'use client'

import { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import Image from 'next/image'
import { motion, AnimatePresence } from 'framer-motion'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'

const NAV_LINKS = [
  { label: 'Features',    href: '/features'    },
  { label: 'How It Works',href: '/how-it-works' },
  { label: 'Scanner',     href: '/scanner'     },
  { label: 'Reports',     href: '/reports'     },
  { label: 'Monitoring',  href: '/monitoring'  },
  { label: 'Pricing',     href: '/pricing'     },
  { label: 'Docs',        href: '/docs'        },
] as const

function Logo() {
  return (
    <div className="flex items-center gap-2.5 group">
      <Image
        src="/logo.png"
        alt="WebHound"
        width={36}
        height={36}
        priority
        className="flex-shrink-0 select-none transition-transform duration-300 group-hover:scale-110"
        style={{ width: 36, height: 36, objectFit: 'contain' }}
      />
      <span className="hidden sm:block text-white font-bold text-[13px] tracking-[0.18em] uppercase select-none">
        WebHound
      </span>
    </div>
  )
}

export function Navbar() {
  const [scrolled,   setScrolled]   = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => {
    const check = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', check, { passive: true })
    check()
    return () => window.removeEventListener('scroll', check)
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

  const closeMobile = useCallback(() => setMobileOpen(false), [])

  return (
    <>
      {/* ── Fixed navbar ─────────────────────────────────────── */}
      <motion.header
        aria-label="Site navigation"
        className="fixed top-0 left-0 right-0 z-[9999]"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.5, ease: [0.25, 0.46, 0.45, 0.94] }}
      >
        <div
          className="transition-all duration-500"
          style={{
            background:           scrolled ? 'rgba(2,6,23,0.95)' : 'rgba(2,6,23,0.75)',
            backdropFilter:       'blur(20px)',
            WebkitBackdropFilter: 'blur(20px)',
            borderBottom:         scrolled
              ? '1px solid rgba(255,255,255,0.07)'
              : '1px solid rgba(255,255,255,0.04)',
            boxShadow: scrolled ? '0 1px 40px rgba(0,0,0,0.5)' : 'none',
          }}
        >
          <div className="max-w-[1340px] mx-auto px-5 sm:px-8 xl:px-12 h-16 flex items-center justify-between gap-4">

            {/* Logo */}
            <Link href="/" className="flex-shrink-0">
              <Logo />
            </Link>

            {/* Center nav — desktop */}
            <ul className="hidden lg:flex items-center gap-0.5 flex-1 justify-center" role="list">
              {NAV_LINKS.map(({ label, href }) => (
                <li key={label}>
                  <Link
                    href={href}
                    className="flex items-center gap-1 px-3 py-2 text-[12.5px] font-medium rounded-lg transition-all duration-200"
                    style={{ color: 'rgba(255,255,255,0.45)' }}
                    onMouseEnter={e => {
                      e.currentTarget.style.color = 'rgba(255,255,255,0.9)'
                      e.currentTarget.style.background = 'rgba(255,255,255,0.05)'
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.color = 'rgba(255,255,255,0.45)'
                      e.currentTarget.style.background = 'transparent'
                    }}
                  >
                    {label}
                  </Link>
                </li>
              ))}
            </ul>

            {/* Right CTAs */}
            <div className="hidden lg:flex items-center gap-3 flex-shrink-0">
              <Link
                href="/login"
                className="text-[12.5px] font-medium px-3 py-2 transition-colors duration-200"
                style={{ color: 'rgba(255,255,255,0.42)' }}
                onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.9)')}
                onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.42)')}
              >
                Log in
              </Link>
              <Link href="/dashboard">
                <span
                  className="inline-flex items-center px-4 py-[8px] rounded-[8px] text-[12.5px] font-semibold transition-all duration-200"
                  style={{
                    background:  'rgba(139,255,62,0.08)',
                    border:      '1px solid rgba(139,255,62,0.35)',
                    color:       'rgba(139,255,62,0.9)',
                  }}
                  onMouseEnter={e => {
                    const el = e.currentTarget as HTMLSpanElement
                    el.style.background = 'rgba(139,255,62,0.14)'
                    el.style.borderColor = 'rgba(139,255,62,0.6)'
                    el.style.color = '#ffffff'
                    el.style.boxShadow = '0 0 20px rgba(139,255,62,0.2)'
                  }}
                  onMouseLeave={e => {
                    const el = e.currentTarget as HTMLSpanElement
                    el.style.background = 'rgba(139,255,62,0.08)'
                    el.style.borderColor = 'rgba(139,255,62,0.35)'
                    el.style.color = 'rgba(139,255,62,0.9)'
                    el.style.boxShadow = 'none'
                  }}
                >
                  Get Started
                </span>
              </Link>
            </div>

            {/* Mobile hamburger */}
            <button
              type="button"
              aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={mobileOpen}
              aria-controls="mobile-nav-panel"
              className="lg:hidden w-9 h-9 flex flex-col items-center justify-center gap-[5px] rounded-lg transition-colors duration-200"
              style={{ background: mobileOpen ? 'rgba(255,255,255,0.07)' : 'transparent' }}
              onClick={() => setMobileOpen(v => !v)}
            >
              <span className={cn('block w-[18px] h-[1.5px] bg-white/60 transition-all duration-300 origin-center', mobileOpen && 'rotate-45 translate-y-[6.5px]')} />
              <span className={cn('block w-[18px] h-[1.5px] bg-white/60 transition-all duration-300', mobileOpen && 'opacity-0 scale-x-0')} />
              <span className={cn('block w-[18px] h-[1.5px] bg-white/60 transition-all duration-300 origin-center', mobileOpen && '-rotate-45 -translate-y-[6.5px]')} />
            </button>
          </div>
        </div>
      </motion.header>

      {/* ── Mobile panel ─────────────────────────────────────── */}
      <AnimatePresence>
        {mobileOpen && (
          <>
            <motion.div
              key="nav-backdrop"
              className="fixed inset-0 z-[9998] lg:hidden"
              style={{ background: 'rgba(2,6,23,0.7)', backdropFilter: 'blur(4px)', WebkitBackdropFilter: 'blur(4px)' }}
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              transition={{ duration: 0.25 }}
              onClick={closeMobile}
            />

            <motion.aside
              key="nav-panel"
              id="mobile-nav-panel"
              role="dialog"
              aria-modal="true"
              aria-label="Navigation menu"
              className="fixed inset-y-0 right-0 z-[9999] w-full max-w-[300px] flex flex-col lg:hidden"
              initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
              transition={{ duration: 0.38, ease: [0.25, 0.46, 0.45, 0.94] }}
              style={{
                background:   'rgba(4,8,18,0.99)',
                backdropFilter: 'blur(40px)',
                borderLeft:   '1px solid rgba(255,255,255,0.06)',
                boxShadow:    '-12px 0 60px rgba(0,0,0,0.6)',
              }}
            >
              {/* Header */}
              <div className="flex items-center justify-between px-5 py-5" style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                <Link href="/" onClick={closeMobile}><Logo /></Link>
                <button onClick={closeMobile} aria-label="Close menu"
                  className="w-8 h-8 flex items-center justify-center rounded-lg transition-all"
                  style={{ border: '1px solid rgba(255,255,255,0.08)', color: 'rgba(255,255,255,0.4)' }}
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Links */}
              <nav className="flex-1 px-3 py-4 flex flex-col gap-0.5 overflow-y-auto">
                {NAV_LINKS.map(({ label, href }, i) => (
                  <motion.div
                    key={label}
                    initial={{ opacity: 0, x: 14 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.28, delay: 0.04 + i * 0.04 }}
                  >
                    <Link
                      href={href}
                      onClick={closeMobile}
                      className="flex items-center px-4 py-3 rounded-xl text-[14px] font-medium transition-all"
                      style={{ color: 'rgba(255,255,255,0.5)' }}
                      onMouseEnter={e => {
                        e.currentTarget.style.color = 'rgba(255,255,255,0.9)'
                        e.currentTarget.style.background = 'rgba(255,255,255,0.05)'
                      }}
                      onMouseLeave={e => {
                        e.currentTarget.style.color = 'rgba(255,255,255,0.5)'
                        e.currentTarget.style.background = 'transparent'
                      }}
                    >
                      {label}
                    </Link>
                  </motion.div>
                ))}
              </nav>

              {/* CTAs */}
              <div className="px-5 pb-8 pt-3" style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                <div className="flex flex-col gap-2.5 pt-4">
                  <Link href="/login" onClick={closeMobile}
                    className="flex items-center justify-center h-11 rounded-lg text-sm font-medium transition-all"
                    style={{ border: '1px solid rgba(255,255,255,0.08)', color: 'rgba(255,255,255,0.5)' }}
                  >
                    Log in
                  </Link>
                  <Link href="/dashboard" onClick={closeMobile}
                    className="flex items-center justify-center h-11 rounded-lg text-sm font-semibold transition-all"
                    style={{ background: 'rgba(139,255,62,0.08)', border: '1px solid rgba(139,255,62,0.35)', color: 'rgba(139,255,62,0.9)' }}
                  >
                    Get Started
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
