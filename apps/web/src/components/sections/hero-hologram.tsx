'use client'

// WebHound — components/sections/hero-hologram.tsx
// Hero v4 — restrained, realistic, sitting close to the base.
//
// v3 review fixes baked in here:
//   • Shield ~41% smaller — composition dominated by product,
//     hologram reads as a detail, not a stage prop.
//   • Sits much closer to the projector base — top offset
//     ~5% of size instead of 15%.
//   • Projection beam is thin and tight — width dropped from
//     0.18*size to 0.05*size.
//   • Projector glow opacity halved across every layer
//     (puck, hotspot, cone, halos).
//   • Subtle scanlines + subtle flicker only. Removed the
//     aggressive horizontal scanner sweep.
//   • Rotating base ring kept, but dimmer.
//
// Everything still respects prefers-reduced-motion: every
// animated layer collapses to a static frame when reduce=true.

import Image from 'next/image'
import { motion, useReducedMotion } from 'framer-motion'

interface HeroHologramProps {
  /** Width of the shield itself, in px. Pass per breakpoint. */
  size?: number
}

export function HeroHologram({ size = 130 }: HeroHologramProps) {
  const reduce = useReducedMotion()

  // Container — slimmer than v3 because the hologram now hugs
  // its base rather than floating above it.
  const containerW = size * 1.25
  const containerH = size * 1.5

  const float = reduce
    ? { y: 0, rotateZ: 0 }
    : { y: [0, -4, 0], rotateZ: [-0.7, 0.7, -0.7] }

  const flicker = reduce
    ? { opacity: 1 }
    : { opacity: [1, 0.97, 1, 0.99, 1, 1, 0.95, 1] }

  return (
    <div
      className="relative pointer-events-none select-none"
      style={{ width: containerW, height: containerH }}
      aria-hidden
    >
      {/* ─── 1. Projector base puck ─────────────────────────
          Glow opacity halved from v3 (0.65/0.35/0.10 →
          0.32/0.18/0.05). */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: 0,
          width: containerW * 0.85,
          height: size * 0.22,
          background:
            'radial-gradient(ellipse at center, rgba(140,255,235,0.32) 0%, rgba(124,255,0,0.18) 30%, rgba(124,255,0,0.05) 60%, transparent 85%)',
          filter: 'blur(5px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.85 }}
        animate={reduce ? { opacity: 0.85 } : { opacity: [0.7, 1, 0.7] }}
        transition={
          reduce
            ? undefined
            : { duration: 3.2, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 1b. Inner base hotspot (dimmed) ───────────────── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: size * 0.06,
          width: size * 0.4,
          height: size * 0.1,
          background:
            'radial-gradient(ellipse at center, rgba(220,255,255,0.5) 0%, rgba(140,255,235,0.25) 40%, transparent 75%)',
          filter: 'blur(3px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 1 }}
        animate={reduce ? { opacity: 1 } : { opacity: [0.85, 1, 0.85] }}
        transition={
          reduce
            ? undefined
            : { duration: 2.4, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 2. Thin vertical projection beam ───────────────
          v3 width 0.18*size → v4 0.05*size. Tighter, more
          believable. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          bottom: size * 0.04,
          width: size * 0.05,
          height: containerH * 0.7,
          background:
            'linear-gradient(180deg, rgba(140,255,235,0) 0%, rgba(140,255,235,0.09) 30%, rgba(124,255,0,0.16) 60%, rgba(140,255,235,0.30) 95%, rgba(220,255,255,0.45) 100%)',
          filter: 'blur(2px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.7 }}
        animate={reduce ? { opacity: 0.7 } : { opacity: [0.55, 0.85, 0.55] }}
        transition={
          reduce
            ? undefined
            : { duration: 2.8, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 3. Conic projection cone (dimmer + narrower) ─── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          bottom: size * 0.06,
          width: containerW * 0.55,
          height: containerH * 0.65,
          background:
            'conic-gradient(from 90deg at 50% 100%, rgba(124,255,0,0) 0deg, rgba(124,255,0,0.13) 12deg, rgba(124,255,0,0.04) 26deg, rgba(124,255,0,0) 40deg)',
          filter: 'blur(8px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.55 }}
        animate={reduce ? { opacity: 0.55 } : { opacity: [0.4, 0.7, 0.4] }}
        transition={
          reduce
            ? undefined
            : { duration: 5, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 4. Rotating base halo (dimmer) ─────────────────
          Still rotating slowly so it sells 3D depth, but the
          ring is faded so it doesn't dominate. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: size * 0.04,
          width: containerW * 0.72,
          height: size * 0.32,
          border: '1px solid rgba(140,255,235,0.22)',
          boxShadow:
            '0 0 9px rgba(140,255,235,0.22), inset 0 0 9px rgba(124,255,0,0.12)',
          mixBlendMode: 'screen',
        }}
        animate={reduce ? { rotateZ: 0 } : { rotateZ: 360 }}
        transition={
          reduce
            ? undefined
            : { duration: 22, repeat: Infinity, ease: 'linear' }
        }
      />

      {/* ─── 5. Outer green halo (dimmer + tighter) ─────────
          v3 opacity 0.42 → v4 0.21. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          top: size * 0,
          width: size * 1.55,
          height: size * 1.55,
          background:
            'radial-gradient(circle at center, rgba(124,255,0,0.21) 0%, rgba(124,255,0,0.05) 40%, transparent 70%)',
          filter: 'blur(18px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.75 }}
        animate={reduce ? { opacity: 0.75 } : { opacity: [0.6, 0.85, 0.6] }}
        transition={
          reduce
            ? undefined
            : { duration: 4, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 6. Inner cyan core (dimmer) ───────────────────── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          top: size * 0.12,
          width: size * 0.95,
          height: size * 0.95,
          background:
            'radial-gradient(circle at center, rgba(120,255,220,0.22) 0%, rgba(120,255,220,0) 60%)',
          filter: 'blur(10px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.7 }}
        animate={reduce ? { opacity: 0.7 } : { opacity: [0.5, 0.8, 0.5] }}
        transition={
          reduce
            ? undefined
            : { duration: 3.2, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 7. The shield — close to base, smaller, gentle ─
          v3 top 0.15*size → v4 0.05*size. Sits just above the
          ring instead of floating high. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          top: size * 0.05,
          width: size,
          height: size,
        }}
        animate={float}
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
              'drop-shadow(0 0 9px rgba(124,255,0,0.42)) drop-shadow(0 0 20px rgba(124,255,0,0.22))',
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
              filter: 'brightness(1.12) saturate(1.08)',
            }}
          />

          {/* ─── 8. Subtle scanlines clipped to shield ─────
              v3 had moving scanlines + a high-contrast
              horizontal scanner sweep. v4 keeps the gentle
              scanline texture only. */}
          {!reduce && (
            <motion.div
              className="absolute inset-0 pointer-events-none"
              style={{
                backgroundImage:
                  'repeating-linear-gradient(0deg, rgba(220,255,235,0.06) 0px, rgba(220,255,235,0.06) 1px, transparent 1px, transparent 4px)',
                backgroundSize: '100% 8px',
                mixBlendMode: 'overlay',
              }}
              animate={{ backgroundPositionY: ['0px', '16px'] }}
              transition={{ duration: 2.4, repeat: Infinity, ease: 'linear' }}
            />
          )}
        </motion.div>
      </motion.div>
    </div>
  )
}
