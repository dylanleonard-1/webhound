'use client'

// WebHound — components/sections/hero.tsx
// Hero v5 — zoomed-out cinematic visual, smaller hologram
// anchored to the projector base.
//
// v4 review fixes baked in here:
//   1. Image zoomed out (~20%) — switched from object-cover
//      ("40% 50%", which cropped top/right of the tablet) to
//      object-contain anchored bottom-right. Full tablet +
//      full projector are visible.
//   2. Image repositioned right + down — layer top inset to
//      6%, right inset to 2%, image anchored to 'right
//      bottom' inside the layer. Visible breathing room on
//      top + right edges.
//   3. Hologram lives INSIDE the image layer so it stays
//      glued to the projector base regardless of viewport.
//      Right/bottom offsets tuned over the in-image base.
//   4. Hero vertical height tightened — section minHeight
//      cap dropped 760 → 700px; container pb cut 8 → 6.
//      Whole hero (eyebrow → trust row) fits at 1920×1080.
//   5. Blend preserved — four-edge mask + dark gradient veil
//      kept; image is still a background, not a card.

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
        // v4 cap was 760; v5 drops to 700 so the entire hero
        // fits at 1920×1080 below a 64–80px header without
        // overlap of the next section.
        background: '#020617',
        minHeight: 'min(86vh, 700px)',
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

      {/* Faint grid — barely visible */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.005]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(139,255,62,1) 1px, transparent 1px), linear-gradient(90deg, rgba(139,255,62,1) 1px, transparent 1px)',
          backgroundSize: '60px 60px',
        }}
      />

      {/* ────────── CINEMATIC IMAGE + HOLOGRAM LAYER ──────────
          Layer wraps BOTH the masked image and the hologram so
          they move together. Hologram offsets are relative to
          this layer, which keeps the shield glued to the in-
          image projector base regardless of viewport size.

          Layer insets:
            top: 6%   — breathing room at top
            right: 2% — breathing room at right
            width: 56% — slightly narrower than v4 (was 58%)
                         so the image has room to breathe
                         without being shoved to the corner
            bottom: 0
       */}
      <div
        className="hidden lg:block absolute pointer-events-none"
        style={{
          top: '6%',
          right: '2%',
          bottom: 0,
          width: '56%',
        }}
      >
        {/* Masked image — four-edge soft vignette. */}
        <div
          aria-hidden
          className="absolute inset-0"
          style={{
            maskImage:
              'linear-gradient(90deg, transparent 0%, black 22%, black 92%, transparent 100%), linear-gradient(180deg, transparent 0%, black 12%, black 90%, transparent 100%)',
            WebkitMaskImage:
              'linear-gradient(90deg, transparent 0%, black 22%, black 92%, transparent 100%), linear-gradient(180deg, transparent 0%, black 12%, black 90%, transparent 100%)',
            maskComposite: 'intersect',
            WebkitMaskComposite: 'source-in',
          }}
        >
          <Image
            src="/images/hero-background-1.png"
            alt=""
            fill
            priority
            sizes="56vw"
            // v4 was object-cover (cropped top/right). v5
            // switches to object-contain so the full tablet
            // and projector are visible. objectPosition anchors
            // the contained image to the bottom-right corner
            // of the layer.
            className="object-contain"
            style={{ objectPosition: 'right bottom' }}
          />
        </div>

        {/* Hologram — positioned over the projector base.
            Offsets are empirically tuned for the image at
            object-contain 'right bottom' inside this layer.
            Inside the same wrapper so it follows the image
            as the viewport scales. */}
        <div
          className="absolute pointer-events-none"
          style={{
            right: '6%',
            bottom: '11%',
          }}
        >
          <HeroHologram size={95} />
        </div>
      </div>

      {/* Dark veil between text and visual. Image-side
          unchanged from v4; this is what keeps the headline
          readable without a visible card edge. */}
      <div
        aria-hidden
        className="hidden lg:block absolute inset-y-0 left-0 pointer-events-none"
        style={{
          width: '68%',
          background:
            'linear-gradient(90deg, #020617 0%, rgba(2,6,23,0.95) 25%, rgba(2,6,23,0.7) 55%, rgba(2,6,23,0.25) 80%, transparent 100%)',
        }}
      />

      {/* Ambient brand-green wash */}
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

      {/* ────────── COPY LAYER ────────── */}
      <div className="relative z-10 max-w-[1480px] mx-auto px-6 sm:px-10 xl:px-16 pt-2 pb-5 lg:pt-3 lg:pb-6">
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
            style={{ fontSize: 'clamp(2.1rem, 4.2vw, 3.8rem)' }}
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
            className="leading-[1.6] max-w-[500px] mb-5 text-[14.5px]"
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
            className="flex flex-wrap items-center gap-x-5 gap-y-2 mt-5"
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
    </section>
  )
}
