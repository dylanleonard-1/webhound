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

// ── Hero ──────────────────────────────────────────────────────────────────────

export function Hero() {
  return (
    <section className="relative overflow-hidden pt-16 lg:pt-20" style={{ background: '#020617' }}>

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

          {/* Eyebrow — positioning copy (replaces the prior
              "webhoundsecurity.com" decorative-domain badge, which
              told visitors the URL they were already on). */}
          <motion.div
            className="inline-flex items-center gap-2 mb-5 w-fit"
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.05 }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full flex-shrink-0"
              style={{ background: '#7CFF00', boxShadow: '0 0 8px rgba(124,255,0,0.9)' }}
            />
            <span className="text-[10px] font-bold tracking-[0.28em] uppercase" style={{ color: 'rgba(139,255,62,0.75)' }}>
              Continuous website security
            </span>
          </motion.div>

          {/* Headline */}
          <motion.h1
            className="font-bold leading-[0.98] tracking-[-0.03em] mb-5"
            style={{ fontSize: 'clamp(2.4rem, 4.8vw, 4.4rem)' }}
            initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.12 }}
          >
            <span className="text-white block">Hackers scan your</span>
            <span className="text-white block">website every day.</span>
            <span className="block mt-2" style={{ color: '#7CFF00', textShadow: '0 0 60px rgba(124,255,0,0.28)' }}>
              You should too.
            </span>
          </motion.h1>

          {/* Subtext */}
          <motion.p
            className="leading-[1.65] max-w-[460px] mb-7 text-[15px]"
            style={{ color: 'rgba(255,255,255,0.55)' }}
            initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.22 }}
          >
            WebHound finds the security holes that put your customers,
            your data, and your reputation at risk — before anyone else can.
          </motion.p>

          {/* CTA buttons */}
          <motion.div
            className="flex flex-col sm:flex-row items-start sm:items-center gap-3"
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.32 }}
          >
            <Link href="/scan" tabIndex={-1}>
              <button
                className="inline-flex items-center gap-2 px-6 py-3 rounded-[9px] text-[14px] font-semibold text-[#020617] transition-all duration-300 hover:shadow-[0_0_30px_rgba(124,255,0,0.35)] hover:scale-[1.02]"
                style={{ background: '#7CFF00', boxShadow: '0 0 18px rgba(124,255,0,0.2)' }}
              >
                Start Free Scan
                <ArrowRight className="w-4 h-4" />
              </button>
            </Link>

            <a href="#live-scan" tabIndex={-1}>
              <button
                className="inline-flex items-center gap-2 px-6 py-3 rounded-[9px] text-[14px] font-medium transition-all duration-300 hover:bg-[rgba(255,255,255,0.05)]"
                style={{ border: '1px solid rgba(255,255,255,0.10)', color: 'rgba(255,255,255,0.6)' }}
                onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.9)')}
                onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.6)')}
              >
                See it run
              </button>
            </a>
          </motion.div>
        </div>

      </div>

      {/* ── Globe ─────────────────────────────────────────────── */}
      <div className="relative h-[30vw] sm:h-[26vw] w-full lg:absolute lg:top-0 lg:h-full lg:w-[60vw] lg:[right:-6vw] pointer-events-none">
        <CyberGlobe className="absolute inset-0" />
      </div>

    </section>
  )
}
