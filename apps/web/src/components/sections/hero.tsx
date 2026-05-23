'use client'

import dynamic from 'next/dynamic'
import Link from 'next/link'
import { ArrowRight } from 'lucide-react'
import { motion } from 'framer-motion'

const CyberGlobe = dynamic(() => import('./cyber-globe'), {
  ssr: false,
  loading: () => <GlobeShell />,
})

function GlobeShell() {
  return (
    <div className="w-full h-full flex items-center justify-center">
      <div
        className="w-[75%] aspect-square rounded-full"
        style={{
          background: 'radial-gradient(circle at 40% 50%, rgba(124,255,0,0.04) 0%, rgba(2,6,23,0.6) 65%)',
          boxShadow:  '0 0 100px rgba(124,255,0,0.04)',
          border:     '1px solid rgba(124,255,0,0.05)',
        }}
      />
    </div>
  )
}

// ── Animated counter ──────────────────────────────────────────────────────────

function StatPill({ value, label }: { value: string; label: string }) {
  return (
    <motion.div
      className="flex flex-col items-center gap-0.5"
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.6 }}
    >
      <span className="text-[15px] font-black text-white font-mono">{value}</span>
      <span className="text-[9px] font-medium tracking-wide" style={{ color: 'rgba(255,255,255,0.32)' }}>{label}</span>
    </motion.div>
  )
}

// ── Hero ──────────────────────────────────────────────────────────────────────

export function Hero() {
  return (
    <section className="relative overflow-hidden pt-16 lg:pt-20" style={{ background: '#020617' }}>

      {/* ── Atmospheric layers ──────────────────────────────── */}
      <div aria-hidden className="pointer-events-none absolute inset-0"
        style={{
          background: [
            'radial-gradient(ellipse 80% 100% at 78% 48%, rgba(124,255,0,0.03) 0%, transparent 55%)',
            'radial-gradient(ellipse 50% 60% at 10% 50%, rgba(2,6,23,0.8) 0%, transparent 70%)',
          ].join(','),
        }}
      />

      {/* Noise texture */}
      <div aria-hidden className="pointer-events-none absolute inset-0 opacity-[0.012]"
        style={{
          backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='300' height='300'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='300' height='300' filter='url(%23n)'/%3E%3C/svg%3E\")",
        }}
      />

      {/* Subtle grid */}
      <div aria-hidden className="pointer-events-none absolute inset-0 opacity-[0.018]"
        style={{
          backgroundImage: `linear-gradient(rgba(139,255,62,1) 1px, transparent 1px), linear-gradient(90deg, rgba(139,255,62,1) 1px, transparent 1px)`,
          backgroundSize: '60px 60px',
        }}
      />

      {/* ── Main layout ──────────────────────────────────────── */}
      <div className="relative z-10 lg:min-h-[calc(100vh-5rem)] flex flex-col lg:flex-row">

        {/* ── Left: hero content ───────────────────────────── */}
        <div className="flex flex-col justify-center w-full lg:w-[48%] xl:w-[44%] px-6 sm:px-12 xl:px-20 pt-8 pb-10 lg:pt-0 lg:pb-0">

          {/* Eyebrow */}
          <motion.div
            className="inline-flex items-center gap-2 mb-5 w-fit"
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.05 }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full flex-shrink-0"
              style={{ background: '#7CFF00', boxShadow: '0 0 8px rgba(124,255,0,0.9)', animation: 'pulse 2s ease-in-out infinite' }}
            />
            <span className="text-[10px] font-bold tracking-[0.28em] uppercase" style={{ color: 'rgba(139,255,62,0.75)' }}>
              AI-Powered Security · webhoundsecurity.com
            </span>
          </motion.div>

          {/* Headline */}
          <motion.h1
            className="font-bold leading-[0.95] tracking-[-0.03em] mb-5"
            style={{ fontSize: 'clamp(2.5rem, 5.2vw, 4.8rem)' }}
            initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.12 }}
          >
            <span className="text-white block">Find your</span>
            <span className="text-white block">vulnerabilities.</span>
            <span className="block" style={{ color: '#7CFF00', textShadow: '0 0 60px rgba(124,255,0,0.28)' }}>
              Before attackers do.
            </span>
          </motion.h1>

          {/* Subtext */}
          <motion.p
            className="leading-[1.65] max-w-[420px] mb-5 text-[14px]"
            style={{ color: 'rgba(255,255,255,0.40)' }}
            initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.22 }}
          >
            WebHound runs 42,000+ passive checks across your website, APIs, and
            infrastructure — delivering CVSS-scored findings with actionable
            remediation in under 2 minutes.
          </motion.p>

          {/* Social proof pill */}
          <motion.div
            className="hidden sm:flex items-center gap-3 px-4 py-2.5 rounded-xl mb-5 w-fit"
            style={{
              background: 'rgba(5,10,22,0.7)',
              border: '1px solid rgba(139,255,62,0.12)',
              backdropFilter: 'blur(16px)',
            }}
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.30 }}
          >
            <div className="flex gap-0.5">
              {Array.from({ length: 5 }, (_, i) => (
                <span key={i} style={{ color: '#fbbf24', fontSize: 11 }}>★</span>
              ))}
            </div>
            <span className="text-[11px] font-medium" style={{ color: 'rgba(255,255,255,0.50)' }}>
              Trusted by 200+ security teams
            </span>
          </motion.div>

          {/* CTA buttons */}
          <motion.div
            className="flex flex-col sm:flex-row items-start sm:items-center gap-3 mb-6"
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.38 }}
          >
            <Link href="/dashboard" tabIndex={-1}>
              <button
                className="inline-flex items-center gap-2 px-6 py-3 rounded-[9px] text-[13.5px] font-semibold text-[#020617] transition-all duration-300 hover:shadow-[0_0_30px_rgba(124,255,0,0.35)] hover:scale-[1.02]"
                style={{ background: '#7CFF00', boxShadow: '0 0 18px rgba(124,255,0,0.2)' }}
              >
                Start Free Scan
                <ArrowRight className="w-4 h-4" />
              </button>
            </Link>

            <Link href="/how-it-works" tabIndex={-1}>
              <button
                className="inline-flex items-center gap-2 px-6 py-3 rounded-[9px] text-[13.5px] font-medium transition-all duration-300 hover:bg-[rgba(255,255,255,0.05)]"
                style={{ border: '1px solid rgba(255,255,255,0.10)', color: 'rgba(255,255,255,0.6)' }}
                onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.9)')}
                onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.6)')}
              >
                How It Works
              </button>
            </Link>
          </motion.div>

          {/* Stats row */}
          <motion.div
            className="flex items-center gap-6"
            initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.46 }}
          >
            <div className="h-8 w-px" style={{ background: 'rgba(255,255,255,0.08)' }} />
            <StatPill value="42K+"  label="Security checks" />
            <div className="h-8 w-px" style={{ background: 'rgba(255,255,255,0.08)' }} />
            <StatPill value="<2min" label="Avg scan time" />
            <div className="h-8 w-px" style={{ background: 'rgba(255,255,255,0.08)' }} />
            <StatPill value="100%"  label="Passive only" />
          </motion.div>
        </div>

      </div>

      {/* ── Globe ─────────────────────────────────────────────── */}
      {/* Mobile: compact strip below the CTAs. */}
      {/* Desktop: absolute-positioned background on the right half. */}
      <div className="relative h-[30vw] sm:h-[26vw] w-full lg:absolute lg:top-0 lg:h-full lg:w-[60vw] lg:[right:-6vw] pointer-events-none">
        <CyberGlobe className="absolute inset-0" />
      </div>

    </section>
  )
}
