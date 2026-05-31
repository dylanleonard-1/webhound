'use client'

// WebHound — components/sections/hero.tsx
// Hero v11 — keep the cinematic tablet+projector background image,
// but the projector STAND now generates the new self-contained
// hologram projection (HologramPrototype) instead of the old flat
// 140px shield. The hologram box is anchored over the in-image puck
// so the stand visibly projects the shield.

import Link from 'next/link'
import Image from 'next/image'
import { ArrowRight } from 'lucide-react'
import { motion } from 'framer-motion'
import HologramPrototype from '@/components/experiments/HologramPrototype'
import { HeroTabletDashboard } from './hero-tablet-dashboard'

const TRUST_ITEMS = ['2 minutes', 'Read-only', 'No changes made', '100% safe']

export function Hero() {
  return (
    <section
      className="relative overflow-hidden pt-14 lg:pt-16"
      style={{
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
          Layer wraps BOTH the masked background image (tablet +
          standalone projector puck) AND the new hologram so they
          move together. The hologram box is positioned over the
          in-image puck so the stand appears to project the shield. */}
      <div
        className="hidden lg:block absolute pointer-events-none"
        style={{
          top: '6%',
          right: '2%',
          bottom: 0,
          width: '58%',
        }}
      >
        {/* Masked background image — four-edge soft vignette. */}
        <div
          aria-hidden
          className="absolute inset-0"
          style={{
            maskImage:
              'linear-gradient(90deg, transparent 0%, black 18%, black 94%, transparent 100%), linear-gradient(180deg, transparent 0%, black 10%, black 92%, transparent 100%)',
            WebkitMaskImage:
              'linear-gradient(90deg, transparent 0%, black 18%, black 94%, transparent 100%), linear-gradient(180deg, transparent 0%, black 10%, black 92%, transparent 100%)',
            maskComposite: 'intersect',
            WebkitMaskComposite: 'source-in',
          }}
        >
          <Image
            src="/images/hero-background-2.jpeg"
            alt=""
            fill
            priority
            sizes="60vw"
            className="object-contain"
            style={{ objectPosition: 'center bottom' }}
          />
        </div>

        {/* WebHound dashboard pinned inside the tablet screen-glass.
            Overlays the image box; matrix3d corner-pins the UI onto the
            measured perspective quad. pointer-events:none, hero-only. */}
        <HeroTabletDashboard />

        {/* NEW hologram — self-contained projection (base + beams +
            particles + floating shield) sitting ON the in-image
            projector puck.

            The image is object-contain/center-bottom, so its CONTENT box
            shrinks vertically as the viewport narrows while this layer's
            height stays fixed. Positioning the hologram against the layer
            made it drift off the puck on resize. Fix: this inner wrapper
            reproduces the image content box exactly (width = layer width,
            aspect-ratio 1672/941, bottom-anchored), so the hologram's %
            offsets track the puck at every size — same anchor the
            dashboard overlay uses. */}
        <div
          aria-hidden
          className="absolute inset-x-0 bottom-0 pointer-events-none"
          style={{
            aspectRatio: '1672 / 941',
            maxHeight: '100%',
          }}
        >
          <div
            aria-hidden
            className="absolute pointer-events-none"
            style={{
              left: '60.5%',
              top: '8.7%',
              width: '40%',
              height: '90.3%',
              // nudge: 1px right, 4px back (up)
              transform: 'translate(1px, -4px)',
            }}
          >
            <HologramPrototype embedded />
          </div>
        </div>
      </div>

      {/* Dark veil between text and visual. */}
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
