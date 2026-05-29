'use client'

// WebHound — components/sections/hero.tsx
// Hero v3 — above-the-fold composition with the product as
// the star.
//
// Changes from v2 (this revision):
//   1. Tablet/dashboard +35%  → max-w 980 (was 720). Right
//      column also gets more grid weight (1.35fr vs 1fr left).
//   2. Right side feels integrated — image bleeds to the right
//      edge of the viewport on desktop instead of sitting in a
//      centered card; ambient green glow expands behind it.
//   3. Projector base enlarged — handled by HeroHologram which
//      now renders a 2x wider base puck on top of the in-image
//      projector.
//   4. Hologram is rebuilt — float + rotation + scanlines +
//      pulse glow + projection beam (see hero-hologram.tsx).
//   5. Above-the-fold on 1920x1080 — top + bottom padding cut
//      ~40%; min-h removed; section uses content-driven height.
//   6. Grid background opacity reduced ~70% (0.018 → 0.005).
//   7. Empty space tightened — eyebrow, headline, subhead, CTA
//      gaps reduced.
//   8. Right side is now visually dominant.
//   9. Performance: no canvas, all CSS + Framer Motion, every
//      animation respects prefers-reduced-motion.

import Link from 'next/link'
import Image from 'next/image'
import { ArrowRight } from 'lucide-react'
import { motion } from 'framer-motion'
import { HeroHologram } from './hero-hologram'

const TRUST_ITEMS = ['2 minutes', 'Read-only', 'No changes made', '100% safe']

export function Hero() {
  return (
    <section
      className="relative overflow-hidden pt-10 lg:pt-12"
      style={{ background: '#020617' }}
    >
      {/* Subtle noise — kept very faint */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.012]"
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='300' height='300'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='300' height='300' filter='url(%23n)'/%3E%3C/svg%3E\")",
        }}
      />

      {/* Brief item 6 — grid background reduced ~70%
          (0.018 → 0.005). It's still there for texture but you
          have to look for it instead of it competing with the
          product. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.005]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(139,255,62,1) 1px, transparent 1px), linear-gradient(90deg, rgba(139,255,62,1) 1px, transparent 1px)',
          backgroundSize: '60px 60px',
        }}
      />

      {/* Expanded ambient glow behind the visual side — wider
          and brighter than v2 so the right column "belongs" to
          the hero instead of looking pasted on. */}
      <div
        aria-hidden
        className="pointer-events-none absolute top-0 right-0 hidden lg:block"
        style={{
          width: '65%',
          height: '100%',
          background:
            'radial-gradient(ellipse at 65% 50%, rgba(124,255,0,0.14) 0%, rgba(124,255,0,0.04) 35%, transparent 65%)',
        }}
      />

      <div className="relative z-10 max-w-[1480px] mx-auto pl-6 sm:pl-10 xl:pl-16 pr-0 sm:pr-0 pt-2 pb-8 lg:pt-4 lg:pb-10">
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_1.35fr] gap-8 lg:gap-6 items-center">

          {/* ───────────────── LEFT — copy + CTAs ───────────────── */}
          <div className="flex flex-col justify-center max-w-[600px] pr-6 sm:pr-10 xl:pr-0">

            {/* Eyebrow pill */}
            <motion.div
              className="inline-flex items-center gap-2 mb-4 w-fit px-3 py-1.5 rounded-full"
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

            {/* Headline — slightly tightened size to help the
                whole hero stay above the fold on 1920x1080. */}
            <motion.h1
              className="font-bold leading-[1.02] tracking-[-0.03em] mb-5"
              style={{ fontSize: 'clamp(2.2rem, 4.6vw, 4.2rem)' }}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.12 }}
            >
              <span className="block text-white">See what hackers can see.</span>
              <span className="block" style={{ color: '#7CFF00' }}>
                Protect what matters.
              </span>
            </motion.h1>

            <motion.p
              className="leading-[1.6] max-w-[520px] mb-6 text-[15px]"
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

            {/* Trust row — tightened margin */}
            <motion.div
              className="flex flex-wrap items-center gap-x-5 gap-y-2 mt-6"
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

          {/* ───────────────── RIGHT — product as the star ───────────────── */}
          {/* The image is allowed to bleed off the right edge
              on desktop so it stops feeling like a card. On
              mobile/tablet it stays contained inside the
              padded container. */}
          <motion.div
            className="relative w-full"
            initial={{ opacity: 0, scale: 0.97 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.7, delay: 0.18 }}
          >
            <div
              className="relative w-full"
              style={{
                // 16/10 keeps the tablet readable. maxWidth bumped
                // 720 → 980 (+36%) per brief item 1.
                aspectRatio: '16 / 10',
                maxWidth: 980,
                marginLeft: 'auto',
              }}
            >
              {/* Background blur halo behind the tablet for
                  integration — sits behind the image and feels
                  like product light bleeding into the room. */}
              <div
                aria-hidden
                className="absolute inset-0 pointer-events-none"
                style={{
                  background:
                    'radial-gradient(ellipse at 50% 55%, rgba(124,255,0,0.16) 0%, rgba(124,255,0,0.04) 40%, transparent 70%)',
                  filter: 'blur(30px)',
                  transform: 'scale(1.1)',
                }}
              />

              <Image
                src="/images/hero-background-1.png"
                alt="WebHound dashboard on a tablet showing security score and recent findings"
                fill
                priority
                sizes="(max-width: 1024px) 100vw, 980px"
                className="object-contain opacity-85 lg:opacity-100"
                style={{
                  filter:
                    'drop-shadow(0 40px 80px rgba(0,0,0,0.6)) drop-shadow(0 0 60px rgba(124,255,0,0.15))',
                }}
              />

              {/* Hologram — anchored over the projector base on
                  the bottom-right of the image. Larger sizes on
                  all breakpoints to match the bigger product. */}
              <div
                className="absolute pointer-events-none"
                style={{
                  // Centered over the projector puck in the
                  // background image. Empirically tuned.
                  right: '4%',
                  bottom: '4%',
                }}
              >
                <div className="hidden lg:block">
                  <HeroHologram size={220} />
                </div>
                <div className="hidden sm:block lg:hidden">
                  <HeroHologram size={160} />
                </div>
                <div className="block sm:hidden">
                  <HeroHologram size={110} />
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  )
}
