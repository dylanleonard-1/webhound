'use client'

// WebHound — components/sections/hero.tsx
// Hero v4 — cinematic blended background, no card framing.
//
// Architecture change from v3:
//   v3 used a 2-column grid (text | image-card). The image
//   read as a rectangle "pasted onto" the hero.
//   v4 treats the right ~58% of the section as a CINEMATIC
//   BACKGROUND LAYER. The image is absolutely positioned,
//   mask-image fades all four edges into the page surface,
//   and a dark gradient veil keeps the text readable on the
//   left without any visible boundary between text and visual.
//
// Per the v3 review:
//   1. Hard rectangle gone — no border-radius, no card, no
//      drop-shadow box, no aspect-ratio wrapper.
//   2. Multi-edge mask blends image into the surrounding dark.
//   3. Image feels like the room the copy sits in.
//   4. Image width raised again (now covers the right 58% of
//      the section), but the mask crops it cinematically.
//   5. Hologram shrunk ~41% (see hero-hologram.tsx).
//   6. Hologram positioned closer to the projector base.
//   7. Beam thinner, glow halved (see hero-hologram.tsx).
//   8. Above-the-fold on 1920×1080 maintained.
//   9. Mobile: visual layer hidden — copy + CTA prioritized,
//      hologram dropped, no horizontal scroll.

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
      style={{
        // Section height is constrained so the entire hero
        // fits above the fold on 1920×1080 (after subtracting
        // a ~64–80px sticky header). 720px works at 1080p; on
        // taller viewports the section naturally grows.
        background: '#020617',
        minHeight: 'min(92vh, 760px)',
      }}
    >
      {/* Subtle noise */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.012]"
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='300' height='300'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='300' height='300' filter='url(%23n)'/%3E%3C/svg%3E\")",
        }}
      />

      {/* Faint grid — kept barely visible (~28% of v2) */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.005]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(139,255,62,1) 1px, transparent 1px), linear-gradient(90deg, rgba(139,255,62,1) 1px, transparent 1px)',
          backgroundSize: '60px 60px',
        }}
      />

      {/* ─────────────── CINEMATIC IMAGE LAYER ───────────────
          Desktop only. Absolutely positioned over the right
          ~58% of the section. The image fills that box with
          object-cover, then a four-edge mask softens every
          edge into transparency so it blends into the dark
          surface instead of sitting as a clipped rectangle.

          We use two stacked linear-gradient masks composited
          with `mask-composite: intersect` (modern spec) +
          `-webkit-mask-composite: source-in` (older WebKit) —
          one fades left/right, the other fades top/bottom.
          Together they produce a soft-edged vignette without
          turning the image into a circle.

          Hidden on <lg breakpoints so mobile/tablet prioritize
          the copy. */}
      <div
        aria-hidden
        className="hidden lg:block absolute top-0 right-0 h-full pointer-events-none"
        style={{ width: '58%' }}
      >
        <div
          className="relative w-full h-full"
          style={{
            // Four-edge soft vignette mask.
            maskImage:
              'linear-gradient(90deg, transparent 0%, black 22%, black 90%, transparent 100%), linear-gradient(180deg, transparent 0%, black 14%, black 86%, transparent 100%)',
            WebkitMaskImage:
              'linear-gradient(90deg, transparent 0%, black 22%, black 90%, transparent 100%), linear-gradient(180deg, transparent 0%, black 14%, black 86%, transparent 100%)',
            maskComposite: 'intersect',
            WebkitMaskComposite: 'source-in',
          }}
        >
          <Image
            src="/images/hero-background-1.png"
            alt=""
            fill
            priority
            sizes="58vw"
            className="object-cover"
            style={{ objectPosition: '40% 50%' }}
          />
        </div>
      </div>

      {/* Dark gradient veil between text and visual.
          Sits *over* the image, fading from full dark on the
          left to fully transparent on the right. This is what
          keeps the copy readable without ever introducing a
          visible boundary between text and image. */}
      <div
        aria-hidden
        className="hidden lg:block absolute inset-y-0 left-0 pointer-events-none"
        style={{
          width: '70%',
          background:
            'linear-gradient(90deg, #020617 0%, rgba(2,6,23,0.95) 25%, rgba(2,6,23,0.7) 55%, rgba(2,6,23,0.25) 80%, transparent 100%)',
        }}
      />

      {/* Soft ambient green wash — keeps the green brand color
          present even where the image fades out. */}
      <div
        aria-hidden
        className="pointer-events-none absolute top-0 right-0 hidden lg:block"
        style={{
          width: '60%',
          height: '100%',
          background:
            'radial-gradient(ellipse at 65% 50%, rgba(124,255,0,0.10) 0%, rgba(124,255,0,0.02) 40%, transparent 70%)',
        }}
      />

      {/* ─────────────── COPY LAYER ─────────────── */}
      <div className="relative z-10 max-w-[1480px] mx-auto px-6 sm:px-10 xl:px-16 pt-2 pb-6 lg:pt-4 lg:pb-8">
        <div className="max-w-[560px]">

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

          <motion.h1
            className="font-bold leading-[1.02] tracking-[-0.03em] mb-5"
            style={{ fontSize: 'clamp(2.2rem, 4.4vw, 4rem)' }}
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
            className="leading-[1.6] max-w-[500px] mb-6 text-[15px]"
            style={{ color: 'rgba(255,255,255,0.68)' }}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.22 }}
          >
            WebHound scans your website in minutes, finds hidden
            vulnerabilities, explains them in plain English, and
            Wade AI watches your site 24/7.
          </motion.p>

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
      </div>

      {/* ─────────────── HOLOGRAM LAYER ───────────────
          Anchored to the bottom-right of the section so it sits
          over the projector base in the background image. Sized
          per breakpoint; hidden on mobile (where the image
          itself is hidden so there's nothing to project from). */}
      <div
        className="hidden lg:block absolute pointer-events-none"
        style={{ right: '11%', bottom: '4%' }}
      >
        <HeroHologram size={130} />
      </div>
      <div
        className="hidden md:block lg:hidden absolute pointer-events-none"
        style={{ right: '8%', bottom: '4%' }}
      >
        <HeroHologram size={100} />
      </div>
    </section>
  )
}
