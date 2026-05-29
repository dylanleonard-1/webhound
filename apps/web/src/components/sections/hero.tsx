'use client'

// WebHound — components/sections/hero.tsx
// Hero rebuild (Section 1) — coded hologram + tablet visual.
//
// Layout follows hero-example-1.jpeg as the visual moodboard:
//   Desktop  — 2-column. Left: eyebrow → headline → subhead →
//              CTAs → trust row. Right: hero-background-1.png
//              (tablet/dashboard scene) with the coded
//              HeroHologram floating above the projector base
//              on the bottom-right of the image.
//   Tablet   — same 2-column, hologram size reduced.
//   Mobile   — stacked. Copy + CTAs at the top. Background
//              image below, dimmed; hologram present but
//              smaller so the layout stays readable.
//
// Background image is *not* baked with the hologram; the
// hologram is rendered by <HeroHologram /> in code so it can
// breathe, flicker, and respect prefers-reduced-motion.

import Link from 'next/link'
import Image from 'next/image'
import { ArrowRight } from 'lucide-react'
import { motion } from 'framer-motion'
import { HeroHologram } from './hero-hologram'

// Trust-row items — small clarifications under the CTAs that
// kill the most common "is it safe to let this scan my site?"
// objection on the first screen.
const TRUST_ITEMS = ['2 minutes', 'Read-only', 'No changes made', '100% safe']

export function Hero() {
  return (
    <section
      className="relative overflow-hidden pt-16 lg:pt-20"
      style={{ background: '#020617' }}
    >
      {/* Subtle noise + grid — kept from prior hero so this
          section reads as part of the same dark surface as the
          rest of the landing page. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.012]"
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='300' height='300'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='300' height='300' filter='url(%23n)'/%3E%3C/svg%3E\")",
        }}
      />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.018]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(139,255,62,1) 1px, transparent 1px), linear-gradient(90deg, rgba(139,255,62,1) 1px, transparent 1px)',
          backgroundSize: '60px 60px',
        }}
      />

      {/* Soft green ambient glow behind the visual side — same
          color family as the hologram, sells continuity. */}
      <div
        aria-hidden
        className="pointer-events-none absolute top-0 right-0 hidden lg:block"
        style={{
          width: '55%',
          height: '100%',
          background:
            'radial-gradient(ellipse at 70% 50%, rgba(124,255,0,0.08) 0%, transparent 55%)',
        }}
      />

      <div className="relative z-10 max-w-[1320px] mx-auto px-6 sm:px-10 xl:px-16 pt-10 pb-16 lg:pt-16 lg:pb-24">
        <div className="grid grid-cols-1 lg:grid-cols-[1.05fr_1fr] gap-10 lg:gap-12 items-center min-h-[calc(100vh-9rem)]">

          {/* ─────────── LEFT — copy + CTAs ─────────── */}
          <div className="flex flex-col justify-center max-w-[640px]">

            {/* Eyebrow pill — matches the example-1 green chip */}
            <motion.div
              className="inline-flex items-center gap-2 mb-6 w-fit px-3 py-1.5 rounded-full"
              style={{
                background: 'rgba(124,255,0,0.08)',
                border: '1px solid rgba(124,255,0,0.25)',
              }}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.05 }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                style={{
                  background: '#7CFF00',
                  boxShadow: '0 0 8px rgba(124,255,0,0.9)',
                }}
              />
              <span
                className="text-[10.5px] font-bold tracking-[0.22em] uppercase"
                style={{ color: '#8BFF3E' }}
              >
                AI-powered website security
              </span>
            </motion.div>

            {/* Headline — "See what hackers can see." (white)
                + "Protect what matters." (green). Two short
                sentences; the green clause is the promise. */}
            <motion.h1
              className="font-bold leading-[1.02] tracking-[-0.03em] mb-6"
              style={{ fontSize: 'clamp(2.4rem, 5.2vw, 4.6rem)' }}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.12 }}
            >
              <span className="block text-white">See what hackers can see.</span>
              <span className="block" style={{ color: '#7CFF00' }}>
                Protect what matters.
              </span>
            </motion.h1>

            {/* Subhead — verbatim from the spec. Mentions Wade
                AI explicitly per the brief. */}
            <motion.p
              className="leading-[1.65] max-w-[540px] mb-8 text-[15.5px]"
              style={{ color: 'rgba(255,255,255,0.68)' }}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.22 }}
            >
              WebHound scans your website in minutes, finds hidden
              vulnerabilities, explains them in plain English, and
              Wade AI watches your site 24/7.
            </motion.p>

            {/* CTA row */}
            <motion.div
              className="flex flex-col sm:flex-row items-start sm:items-center gap-3"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.32 }}
            >
              <div className="flex flex-col items-start">
                <Link href="/scan" tabIndex={-1}>
                  <button
                    className="inline-flex items-center gap-2 px-7 py-3.5 rounded-[10px] text-[14.5px] font-semibold text-[#020617] transition-all duration-200 motion-reduce:transition-none hover:shadow-[0_0_40px_rgba(124,255,0,0.45)] hover:-translate-y-px motion-reduce:hover:translate-y-0"
                    style={{
                      background: '#7CFF00',
                      boxShadow: '0 0 22px rgba(124,255,0,0.28)',
                    }}
                  >
                    Start Free Scan
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </Link>
                <span
                  className="text-[11px] mt-2 ml-1"
                  style={{ color: 'rgba(255,255,255,0.42)' }}
                >
                  No credit card required
                </span>
              </div>

              <a href="#example-findings" tabIndex={-1}>
                <button
                  className="inline-flex items-center gap-2 px-6 py-3.5 rounded-[10px] text-[14.5px] font-medium transition-all duration-200 motion-reduce:transition-none hover:bg-[rgba(255,255,255,0.05)]"
                  style={{
                    border: '1px solid rgba(255,255,255,0.14)',
                    color: 'rgba(255,255,255,0.78)',
                  }}
                  onMouseEnter={e => {
                    e.currentTarget.style.color = 'rgba(255,255,255,0.95)'
                    e.currentTarget.style.borderColor = 'rgba(255,255,255,0.28)'
                  }}
                  onMouseLeave={e => {
                    e.currentTarget.style.color = 'rgba(255,255,255,0.78)'
                    e.currentTarget.style.borderColor = 'rgba(255,255,255,0.14)'
                  }}
                >
                  See Sample Report
                </button>
              </a>
            </motion.div>

            {/* Trust row */}
            <motion.div
              className="flex flex-wrap items-center gap-x-5 gap-y-2 mt-8"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.42 }}
            >
              {TRUST_ITEMS.map((label, i) => (
                <div key={label} className="flex items-center gap-2.5">
                  {i > 0 && (
                    <span
                      aria-hidden
                      className="w-1 h-1 rounded-full"
                      style={{ background: 'rgba(255,255,255,0.22)' }}
                    />
                  )}
                  <span
                    className="inline-flex items-center gap-1.5 text-[12px] font-medium"
                    style={{ color: 'rgba(255,255,255,0.62)' }}
                  >
                    <span
                      className="w-1.5 h-1.5 rounded-full"
                      style={{
                        background: '#7CFF00',
                        boxShadow: '0 0 6px rgba(124,255,0,0.7)',
                      }}
                    />
                    {label}
                  </span>
                </div>
              ))}
            </motion.div>
          </div>

          {/* ─────────── RIGHT — tablet bg + coded hologram ─────────── */}
          <motion.div
            className="relative w-full"
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.7, delay: 0.18 }}
          >
            <div
              className="relative w-full mx-auto"
              style={{ aspectRatio: '16 / 10', maxWidth: 720 }}
            >
              {/* The hero background image. Slightly dimmed on
                  mobile so the copy stays the dominant element;
                  full brightness on desktop. */}
              <Image
                src="/images/hero-background-1.png"
                alt="WebHound dashboard on a tablet showing security score and recent findings"
                fill
                priority
                sizes="(max-width: 1024px) 100vw, 720px"
                className="object-contain opacity-80 lg:opacity-100"
                style={{
                  // Tasteful inner glow contact-shadow so the
                  // tablet sits on the dark surface instead of
                  // floating as a clipped rectangle.
                  filter: 'drop-shadow(0 30px 60px rgba(0,0,0,0.55))',
                }}
              />

              {/* Hologram — positioned over the projector base
                  on the bottom-right of the image. Coordinates
                  are percentages of the visual container so the
                  position stays correct as the image scales.
                  Sizes drop on smaller breakpoints. */}
              <div
                className="absolute pointer-events-none"
                style={{
                  // Empirically tuned against the source PNG so
                  // the shield sits centered above the projector
                  // base (the small puck on the bottom-right).
                  right: '6%',
                  bottom: '8%',
                }}
              >
                {/* Desktop hologram */}
                <div className="hidden lg:block">
                  <HeroHologram size={150} />
                </div>
                {/* Tablet hologram — smaller */}
                <div className="hidden sm:block lg:hidden">
                  <HeroHologram size={115} />
                </div>
                {/* Mobile hologram — smallest; still present but
                    out of the way of the headline. */}
                <div className="block sm:hidden">
                  <HeroHologram size={80} />
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  )
}
