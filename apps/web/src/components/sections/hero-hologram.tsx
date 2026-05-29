'use client'

// WebHound — components/sections/hero-hologram.tsx
// Hero rebuild (Section 1) — coded shield hologram.
//
// The background image (hero-background-1.png) shows a small
// glowing projector base on the bottom-right of the tablet
// scene. This component renders the WebHound shield logo
// *floating above that base* in code — not baked into the
// image — so the asset can be swapped, scaled per breakpoint,
// and animated.
//
// What it does:
//   * Renders /images/webhound-logo-1.png as the projected
//     hologram, with a green tint so it reads as light, not
//     a sticker.
//   * Adds a green/cyan radial glow behind the shield.
//   * Adds a soft ground-projection cone rising from the base.
//   * Gentle 6s pulse (scale + opacity) — the holo "breathes".
//   * Subtle ~2.5s flicker — random small opacity drops.
//   * Optional 1px scanline overlay clipped to the shield.
//
// prefers-reduced-motion:
//   When the user has reduced motion on, every animation in
//   this component collapses to a single static frame. The
//   shield + glow stay, but the breath, flicker, scanlines,
//   and cone don't move. WCAG 2.1 SC 2.3.3.
//
// No canvas. Pure CSS + Framer Motion. Cheap to render.

import Image from 'next/image'
import { motion, useReducedMotion } from 'framer-motion'

interface HeroHologramProps {
  /** Width of the shield itself, in px. Pass per breakpoint. */
  size?: number
}

export function HeroHologram({ size = 150 }: HeroHologramProps) {
  const reduce = useReducedMotion()

  // Pulse: gentle breath. Frozen when reduced motion is on.
  const breath = reduce
    ? { scale: 1, opacity: 0.88 }
    : {
        scale: [1, 1.035, 1],
        opacity: [0.82, 0.95, 0.82],
      }

  // Flicker: random small opacity drops, ~2.5s loop. Frozen
  // when reduced motion is on.
  const flicker = reduce
    ? { opacity: 1 }
    : {
        opacity: [1, 0.94, 1, 0.97, 1, 1, 0.92, 1],
      }

  return (
    <div
      className="relative pointer-events-none select-none"
      style={{ width: size, height: size * 1.45 }}
      aria-hidden
    >
      {/* ─── Ground projection cone ──────────────────────────
          Rises from the projector base. Frozen when reduced
          motion is on. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          bottom: 0,
          width: size * 0.95,
          height: size * 1.1,
          background:
            'conic-gradient(from 90deg at 50% 100%, rgba(124,255,0,0) 0deg, rgba(124,255,0,0.20) 20deg, rgba(124,255,0,0.05) 35deg, rgba(124,255,0,0) 50deg)',
          filter: 'blur(8px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.55 }}
        animate={reduce ? { opacity: 0.55 } : { opacity: [0.45, 0.7, 0.45] }}
        transition={
          reduce
            ? undefined
            : { duration: 5, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── Outer halo behind the shield ───────────────────── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          top: size * 0.05,
          width: size * 1.6,
          height: size * 1.6,
          marginLeft: 0,
          transform: 'translateX(-50%)',
          background:
            'radial-gradient(circle at center, rgba(124,255,0,0.35) 0%, rgba(124,255,0,0.08) 40%, transparent 70%)',
          filter: 'blur(20px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.7 }}
        animate={reduce ? { opacity: 0.7 } : { opacity: [0.55, 0.85, 0.55] }}
        transition={
          reduce
            ? undefined
            : { duration: 4, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── Inner cyan core ─────────────────────────────────
          A tighter cyan ring inside the green halo — sells the
          "projected light" feel without going Tron. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          top: size * 0.2,
          width: size * 1.05,
          height: size * 1.05,
          background:
            'radial-gradient(circle at center, rgba(120,255,220,0.35) 0%, rgba(120,255,220,0) 60%)',
          filter: 'blur(10px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.6 }}
        animate={reduce ? { opacity: 0.6 } : { opacity: [0.4, 0.7, 0.4] }}
        transition={
          reduce
            ? undefined
            : { duration: 3.2, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── The shield itself ──────────────────────────────
          Pulse (breath) + flicker stacked. Green hue from the
          existing PNG, but lifted in brightness so the shield
          reads as emitted light. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          top: size * 0.15,
          width: size,
          height: size,
        }}
        animate={breath}
        transition={
          reduce
            ? undefined
            : { duration: 6, repeat: Infinity, ease: 'easeInOut' }
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
              'drop-shadow(0 0 12px rgba(124,255,0,0.55)) drop-shadow(0 0 28px rgba(124,255,0,0.35))',
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
              filter: 'brightness(1.15) saturate(1.1)',
            }}
          />

          {/* Scanlines — clipped to the shield via mix-blend */}
          {!reduce && (
            <div
              className="absolute inset-0 pointer-events-none"
              style={{
                backgroundImage:
                  'repeating-linear-gradient(0deg, rgba(255,255,255,0.05) 0px, rgba(255,255,255,0.05) 1px, transparent 1px, transparent 3px)',
                mixBlendMode: 'overlay',
              }}
            />
          )}
        </motion.div>
      </motion.div>

      {/* ─── Faint orbiting ring — sells the 3D base ───────── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: size * 0.02,
          width: size * 0.95,
          height: size * 0.18,
          background:
            'radial-gradient(ellipse at center, rgba(120,255,220,0.45) 0%, rgba(124,255,0,0.15) 40%, transparent 80%)',
          filter: 'blur(4px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.75 }}
        animate={reduce ? { opacity: 0.75 } : { opacity: [0.55, 0.9, 0.55] }}
        transition={
          reduce
            ? undefined
            : { duration: 3.2, repeat: Infinity, ease: 'easeInOut' }
        }
      />
    </div>
  )
}
