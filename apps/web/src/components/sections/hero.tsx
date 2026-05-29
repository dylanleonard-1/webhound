'use client'

// Slice 6 — CyberGlobe removed entirely (L5 audit verdict: trust
// neutral-to-negative, clarity negative, conversion negative —
// stock-art sphere occupying the slot where the strongest
// persuasive asset should live). The Hero now reads as a single
// full-width left-aligned text block on desktop; the LiveScan
// section immediately below carries the visual proof via the
// sample-finding composition. F3's product-screenshot composition
// remains queued for a future slice.

import Link from 'next/link'
import { ArrowRight } from 'lucide-react'
import { motion } from 'framer-motion'

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
      {/* Slice 6 — Hero is now single-column. Was a 2-column
          flex layout with globe on the right; the globe is gone
          and the text breathes full-width on desktop. The
          LiveScan section directly below carries the proof. */}
      <div className="relative z-10 lg:min-h-[calc(100vh-5rem)] flex flex-col items-start">

        <div className="flex flex-col justify-center w-full max-w-[820px] px-6 sm:px-12 xl:px-20 pt-12 pb-14 lg:pt-20 lg:pb-24">

          {/* Eyebrow — persona reveal (Slice 2: D1 approved
              Option 3). Explicit targeting so a 5-second visitor
              sees who the product is for before they decide whether
              to stay. */}
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
              Built for small business owners
            </span>
          </motion.div>

          {/* Headline — Slice 2 D1 approved. One sentence that says
              what WebHound does. The clarity is the hook; no glow,
              no fear-led framing. */}
          <motion.h1
            className="font-bold leading-[1.02] tracking-[-0.03em] mb-5 text-white"
            style={{ fontSize: 'clamp(2.4rem, 4.8vw, 4.4rem)' }}
            initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.12 }}
          >
            Website security without the security team.
          </motion.h1>

          {/* Sub-head — Slice 2 D1 approved. Spells out the three
              product capabilities (find / monitor / explain) and
              folds three risk-reversal signals (two minutes /
              no card / no jargon) into one rhythm so the 5-second
              visitor sees them in the Hero, not three sections
              deep. */}
          <motion.p
            className="leading-[1.65] max-w-[520px] mb-7 text-[15px]"
            style={{ color: 'rgba(255,255,255,0.62)' }}
            initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.22 }}
          >
            WebHound finds security issues, monitors your website
            for changes, and explains what we found in plain English
            so you know what to fix first.
            <span className="block mt-2" style={{ color: 'rgba(255,255,255,0.45)' }}>
              Two minutes to start. No credit card. No jargon.
            </span>
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

            {/* Secondary CTA — Slice 2 D1 approved.
                Anchors to ExampleFindings which IS the sample
                report (real findings rendered in plain English).
                Prior anchor (#live-scan) promised a live scan
                that the section couldn't fully deliver. */}
            <a href="#example-findings" tabIndex={-1}>
              <button
                className="inline-flex items-center gap-2 px-6 py-3 rounded-[9px] text-[14px] font-medium transition-all duration-300 hover:bg-[rgba(255,255,255,0.05)]"
                style={{ border: '1px solid rgba(255,255,255,0.10)', color: 'rgba(255,255,255,0.6)' }}
                onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.9)')}
                onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.6)')}
              >
                See Sample Report
              </button>
            </a>
          </motion.div>
        </div>

      </div>

    </section>
  )
}
