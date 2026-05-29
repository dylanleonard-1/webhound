'use client'

// WebHound — components/sections/hero-hologram.tsx
// Hero v3 — fully realistic holographic shield.
//
// Stack (back → front, each as its own motion layer):
//   1. Projector base ring   — wide cyan/green puck, breathing
//   2. Vertical projection beam — bright shaft from base to shield
//   3. Conic projection cone — cone of green light fanning up
//   4. Rotating base halo    — slow orbital ring sells 3D depth
//   5. Outer green halo      — soft radial glow behind shield
//   6. Inner cyan core       — tighter cyan glow for emitted light
//   7. The shield itself     — float + subtle rotation + flicker
//   8. Moving scanlines      — slow vertical scroll, clipped to shield
//   9. Top sparkle highlight — tiny pulsing dot for crispness
//
// Everything respects `prefers-reduced-motion`: every animated
// layer collapses to a single static frame when reduce=true.
//
// Pure CSS + Framer Motion. No canvas. Cheap to render.

import Image from 'next/image'
import { motion, useReducedMotion } from 'framer-motion'

interface HeroHologramProps {
  /** Width of the shield itself, in px. Pass per breakpoint. */
  size?: number
}

export function HeroHologram({ size = 220 }: HeroHologramProps) {
  const reduce = useReducedMotion()

  // Total container is taller than the shield so the projector
  // base + beam + cone can live below it.
  const containerW = size * 1.4
  const containerH = size * 1.85

  // Float: the shield bobs gently up and down. Combined with
  // subtle rotation, this sells "weightless light projection".
  const float = reduce
    ? { y: 0, rotateZ: 0 }
    : { y: [0, -8, 0], rotateZ: [-1.2, 1.2, -1.2] }

  // Flicker: tiny opacity drops at irregular intervals. Holos
  // shouldn't strobe — these are subtle.
  const flicker = reduce
    ? { opacity: 1 }
    : { opacity: [1, 0.96, 1, 0.98, 1, 1, 0.93, 1] }

  return (
    <div
      className="relative pointer-events-none select-none"
      style={{ width: containerW, height: containerH }}
      aria-hidden
    >
      {/* ─── 1. Projector base ring (puck) ─────────────────
          Wide cyan/green elliptical glow at the bottom. This
          is the "enlarged projector base" the brief asked for —
          it sits over the existing base in the background image
          and makes that footprint read about 2x larger. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: 0,
          width: containerW,
          height: size * 0.28,
          background:
            'radial-gradient(ellipse at center, rgba(140,255,235,0.65) 0%, rgba(124,255,0,0.35) 30%, rgba(124,255,0,0.10) 60%, transparent 85%)',
          filter: 'blur(6px)',
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

      {/* ─── 1b. Inner base hotspot ───────────────────────── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: size * 0.07,
          width: size * 0.55,
          height: size * 0.14,
          background:
            'radial-gradient(ellipse at center, rgba(220,255,255,0.95) 0%, rgba(140,255,235,0.5) 40%, transparent 75%)',
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

      {/* ─── 2. Vertical projection beam ───────────────────
          Bright vertical shaft from base up through the shield —
          the "this is being projected" cue. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          bottom: size * 0.05,
          width: size * 0.18,
          height: containerH * 0.85,
          background:
            'linear-gradient(180deg, rgba(140,255,235,0) 0%, rgba(140,255,235,0.18) 30%, rgba(124,255,0,0.32) 60%, rgba(140,255,235,0.55) 95%, rgba(220,255,255,0.85) 100%)',
          filter: 'blur(8px)',
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

      {/* ─── 3. Conic projection cone ──────────────────────
          The fan of green light spreading from the base up to
          the shield. Wider than the beam, softer. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          bottom: size * 0.08,
          width: containerW * 0.85,
          height: containerH * 0.75,
          background:
            'conic-gradient(from 90deg at 50% 100%, rgba(124,255,0,0) 0deg, rgba(124,255,0,0.28) 15deg, rgba(124,255,0,0.08) 32deg, rgba(124,255,0,0) 50deg)',
          filter: 'blur(10px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.65 }}
        animate={reduce ? { opacity: 0.65 } : { opacity: [0.5, 0.8, 0.5] }}
        transition={
          reduce
            ? undefined
            : { duration: 5, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 4. Rotating base halo ─────────────────────────
          Slow 20s orbital rotation under the shield. Sells the
          "this object exists in 3D space" feel. Static frame
          when reduced motion is on. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: size * 0.05,
          width: containerW * 0.85,
          height: size * 0.4,
          border: '1px solid rgba(140,255,235,0.45)',
          boxShadow:
            '0 0 18px rgba(140,255,235,0.45), inset 0 0 18px rgba(124,255,0,0.25)',
          mixBlendMode: 'screen',
        }}
        animate={reduce ? { rotateZ: 0 } : { rotateZ: 360 }}
        transition={
          reduce
            ? undefined
            : { duration: 20, repeat: Infinity, ease: 'linear' }
        }
      />

      {/* ─── 5. Outer green halo behind shield ─────────────── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          top: size * 0.05,
          width: size * 1.9,
          height: size * 1.9,
          background:
            'radial-gradient(circle at center, rgba(124,255,0,0.42) 0%, rgba(124,255,0,0.10) 40%, transparent 70%)',
          filter: 'blur(24px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.75 }}
        animate={reduce ? { opacity: 0.75 } : { opacity: [0.6, 0.9, 0.6] }}
        transition={
          reduce
            ? undefined
            : { duration: 4, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 6. Inner cyan core ─────────────────────────────── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          top: size * 0.22,
          width: size * 1.15,
          height: size * 1.15,
          background:
            'radial-gradient(circle at center, rgba(120,255,220,0.45) 0%, rgba(120,255,220,0) 60%)',
          filter: 'blur(12px)',
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

      {/* ─── 7. The shield — float + rotate + flicker ─────── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          top: size * 0.15,
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
              'drop-shadow(0 0 14px rgba(124,255,0,0.65)) drop-shadow(0 0 32px rgba(124,255,0,0.4)) drop-shadow(0 0 60px rgba(140,255,235,0.25))',
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
              // Brightness lift + slight green-cyan saturation
              // shift makes the matte logo read as emitted light.
              filter: 'brightness(1.18) saturate(1.15) contrast(1.05)',
            }}
          />

          {/* ─── 8. Animated scanlines clipped to shield ─── */}
          {!reduce && (
            <motion.div
              className="absolute inset-0 pointer-events-none"
              style={{
                backgroundImage:
                  'repeating-linear-gradient(0deg, rgba(220,255,235,0.10) 0px, rgba(220,255,235,0.10) 1px, transparent 1px, transparent 4px)',
                backgroundSize: '100% 8px',
                mixBlendMode: 'overlay',
              }}
              animate={{ backgroundPositionY: ['0px', '16px'] }}
              transition={{ duration: 1.6, repeat: Infinity, ease: 'linear' }}
            />
          )}

          {/* Single moving horizontal scan line — the
              high-contrast "scanner pass" over the shield. */}
          {!reduce && (
            <motion.div
              className="absolute inset-x-0 pointer-events-none"
              style={{
                height: 2,
                background:
                  'linear-gradient(90deg, transparent 0%, rgba(220,255,235,0.85) 50%, transparent 100%)',
                boxShadow: '0 0 8px rgba(140,255,235,0.9)',
                mixBlendMode: 'screen',
              }}
              animate={{ top: ['0%', '100%'] }}
              transition={{
                duration: 4,
                repeat: Infinity,
                ease: 'linear',
              }}
            />
          )}
        </motion.div>
      </motion.div>

      {/* ─── 9. Top sparkle highlight ───────────────────────
          A tiny pulsing dot at the apex of the shield — gives
          the projection a crisp endpoint instead of fading out. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          top: size * 0.12,
          width: 4,
          height: 4,
          background: 'rgba(220,255,235,1)',
          boxShadow:
            '0 0 8px rgba(220,255,235,0.95), 0 0 16px rgba(140,255,235,0.7)',
        }}
        initial={{ opacity: 0.9, scale: 1 }}
        animate={
          reduce ? { opacity: 0.9, scale: 1 } : { opacity: [0.6, 1, 0.6], scale: [1, 1.25, 1] }
        }
        transition={
          reduce
            ? undefined
            : { duration: 2.4, repeat: Infinity, ease: 'easeInOut' }
        }
      />
    </div>
  )
}
