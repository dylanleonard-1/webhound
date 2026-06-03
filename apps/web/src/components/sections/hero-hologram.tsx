'use client'

// WebHound — components/sections/hero-hologram.tsx
//
// 🗄️ OBSOLETE / DEV ARCHIVE — NOT USED IN PRODUCTION OR ANYWHERE.
// Zero imports reference this file. It is an earlier hologram experiment
// (Hero v10) that was SUPERSEDED by the live path:
//   app/page.tsx → hero.tsx → <HologramPrototype embedded />.
// Kept for reference only. Do NOT wire this into the hero by mistake, and
// do not confuse it with the live hologram. (Safe to delete later, but the
// owner asked to keep it for now.)
//
// Hero v10 — "the shield IS the projected light".
//
// Rebuilt visual metaphor: v6–v9 treated the shield as an
// object lit from below by a stack of rays + cone. That read
// as "shield on a popsicle stick" because (a) the bunched
// rays formed a visible vertical pillar, (b) the shield had
// a hard solid bottom edge that contacted the pillar.
//
// v10 changes:
//   • Dropped the 5-ray fan entirely (the stick).
//   • Shield bottom is masked to transparent — its lower 28%
//     dissolves INTO the projection cone instead of touching
//     it as a hard edge. This is the single biggest fix.
//   • Cone is much wider (containerW × 0.85 vs 0.55) so it
//     envelops the shield, taller (containerH × 1.05 vs 0.92)
//     so its tip reaches the shield center, and brighter
//     (stops 0.42/0.30 vs 0.34/0.22).
//   • LED-emitter hotspot scaled up (size × 0.32 vs 0.18)
//     to clearly outshine the in-image puck LED.
//   • Shield image filter pushed: brightness 1.12 → 1.25,
//     saturate 1.08 → 1.18, plus opacity 0.92 so it reads as
//     emitted light, not a PNG sticker.
//   • Scanlines opacity 0.06 → 0.12 so the holographic
//     texture reads at normal viewing distance.
//
// Pure CSS + Framer Motion. All animations gated on
// prefers-reduced-motion.

import Image from 'next/image'
import { motion, useReducedMotion } from 'framer-motion'

interface HeroHologramProps {
  /** Width of the shield itself, in px. Pass per breakpoint. */
  size?: number
}

export function HeroHologram({ size = 140 }: HeroHologramProps) {
  const reduce = useReducedMotion()
  const containerW = size * 1.4
  const containerH = size * 1.6

  const flicker = reduce
    ? { opacity: 1 }
    : { opacity: [1, 0.97, 1, 0.99, 1, 1, 0.94, 1] }

  return (
    <div
      className="relative pointer-events-none select-none"
      style={{ width: containerW, height: containerH }}
      aria-hidden
    >
      {/* ─── 1. Projector base puck (background glow) ─────── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: 0,
          width: containerW * 0.75,
          height: size * 0.13,
          background:
            'radial-gradient(ellipse at center, rgba(140,255,235,0.55) 0%, rgba(124,255,0,0.22) 40%, transparent 80%)',
          filter: 'blur(4px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.9 }}
        animate={reduce ? { opacity: 0.9 } : { opacity: [0.78, 1, 0.78] }}
        transition={
          reduce
            ? undefined
            : { duration: 3.2, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 2. LED-emitter hotspot ────────────────────────
          v10: scaled up substantially (size × 0.32 × 0.08)
          so 'the projector is on' is unambiguous. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: -size * 0.005,
          width: size * 0.32,
          height: size * 0.08,
          background:
            'radial-gradient(ellipse at center, rgba(240,255,250,1) 0%, rgba(140,255,235,0.75) 45%, rgba(124,255,0,0.25) 75%, transparent 95%)',
          filter: 'blur(1.5px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 1 }}
        animate={reduce ? { opacity: 1 } : { opacity: [0.85, 1, 0.85] }}
        transition={
          reduce
            ? undefined
            : { duration: 1.8, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 3. Wide soft projection cone ───────────────────
          v10b: dropped conic-gradient (angles were placing
          the bright region off-canvas at the bottom edge —
          that's why prior versions looked like a thin
          pillar). Switched to radial-gradient at the bottom
          center, which naturally fans upward as a soft
          cone-shaped half-ellipse. Wider (0.95) and brighter. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          bottom: size * 0.02,
          // v10b polish: cone broadened so its tip at the
          // shield reads as a wider envelope.
          // width: 0.95 → 1.05
          // ellipse radii: 65/100 → 75/100
          width: containerW * 1.05,
          height: containerH * 1.05,
          background:
            'radial-gradient(ellipse 75% 100% at 50% 100%, rgba(124,255,0,0.55) 0%, rgba(124,255,0,0.30) 25%, rgba(140,255,235,0.18) 50%, transparent 80%)',
          filter: 'blur(16px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.95 }}
        animate={reduce ? { opacity: 0.95 } : { opacity: [0.82, 1, 0.82] }}
        transition={
          reduce
            ? undefined
            : { duration: 4.5, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 3b. Tighter cyan core inside the cone ──────────
          Narrower radial-gradient, cyan-leaning. Sells the
          temperature of holographic light. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          bottom: size * 0.04,
          width: containerW * 0.5,
          height: containerH * 0.95,
          background:
            'radial-gradient(ellipse 50% 100% at 50% 100%, rgba(140,255,235,0.55) 0%, rgba(140,255,235,0.22) 35%, transparent 75%)',
          filter: 'blur(10px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.9 }}
        animate={reduce ? { opacity: 0.9 } : { opacity: [0.75, 1, 0.75] }}
        transition={
          reduce
            ? undefined
            : { duration: 3.2, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 4. Shield-seat halo behind the shield ──────────
          Soft circular glow sitting where the shield will be.
          Gives the shield an aura that says 'this object
          emits light' rather than 'this object reflects light'. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          top: size * 0.05,
          width: size * 1.3,
          height: size * 1.3,
          background:
            'radial-gradient(circle at center, rgba(124,255,0,0.28) 0%, rgba(140,255,235,0.14) 35%, transparent 70%)',
          filter: 'blur(16px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.75 }}
        animate={reduce ? { opacity: 0.75 } : { opacity: [0.6, 0.9, 0.6] }}
        transition={
          reduce
            ? undefined
            : { duration: 3.6, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 5. The shield ──────────────────────────────────
          v10: bottom 28% masked to transparency so it
          DISSOLVES into the cone instead of touching it as
          a hard edge. Slightly translucent (opacity 0.92)
          and brighter saturation so it reads as emitted
          light. Subtle float kept. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          top: 0,
          width: size,
          height: size,
        }}
        animate={reduce ? undefined : { y: [0, -2, 0] }}
        transition={
          reduce
            ? undefined
            : { duration: 5.5, repeat: Infinity, ease: 'easeInOut' }
        }
      >
        <motion.div
          className="relative w-full h-full"
          animate={flicker}
          transition={
            reduce
              ? undefined
              : {
                  duration: 2.5,
                  repeat: Infinity,
                  ease: 'easeInOut',
                  times: [0, 0.08, 0.16, 0.32, 0.48, 0.6, 0.72, 1],
                }
          }
          style={{
            filter:
              'drop-shadow(0 0 10px rgba(124,255,0,0.55)) drop-shadow(0 0 26px rgba(124,255,0,0.30)) drop-shadow(0 0 50px rgba(140,255,235,0.18))',
            opacity: 0.92,
            // The single biggest fix in v10 — the shield's
            // bottom dissolves into the projection cone rather
            // than presenting a hard edge that contacts the
            // rays/cone.
            maskImage:
              'linear-gradient(180deg, black 0%, black 72%, transparent 100%)',
            WebkitMaskImage:
              'linear-gradient(180deg, black 0%, black 72%, transparent 100%)',
          }}
        >
          <Image
            src="/images/webhound-logo-1.png"
            alt=""
            fill
            sizes={`${size}px`}
            priority
            style={{
              objectFit: 'contain',
              filter: 'brightness(1.25) saturate(1.18) contrast(1.05)',
            }}
          />

          {/* ─── 6. Visible scanlines (clipped to shield) ──
              v10: opacity 0.06 → 0.12. The holographic texture
              should be visible at normal viewing distance, not
              just up close. */}
          {!reduce && (
            <motion.div
              className="absolute inset-0 pointer-events-none"
              style={{
                backgroundImage:
                  'repeating-linear-gradient(0deg, rgba(220,255,235,0.12) 0px, rgba(220,255,235,0.12) 1px, transparent 1px, transparent 4px)',
                backgroundSize: '100% 8px',
                mixBlendMode: 'overlay',
              }}
              animate={{ backgroundPositionY: ['0px', '16px'] }}
              // v10b polish: 2.8s → 2.0s so scanlines read as
              // alive instead of static at normal viewing.
              transition={{ duration: 2.0, repeat: Infinity, ease: 'linear' }}
            />
          )}
        </motion.div>
      </motion.div>
    </div>
  )
}
