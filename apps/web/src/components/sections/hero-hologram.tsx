'use client'

// WebHound — components/sections/hero-hologram.tsx
// Hero v5 — restrained "light projected upward" hologram.
//
// v4 review fixes baked in here:
//   • Shield ~27% smaller (130 → 95 default).
//   • The "green rectangle/glow block" is gone — removed the
//     outer green halo (size*1.55) and inner cyan core
//     (size*0.95) plus the wide conic projection cone. Those
//     were the three layers reading as a glow block.
//   • Replaced the single thick beam with **five thin
//     projection rays** rising from the base to the shield —
//     reads as light, not a blob.
//   • Tiny projector base puck (no big halo around it).
//   • Subtle opacity flicker + scanlines only. No scanner
//     sweep, no rotating orbital halo.
//
// Pure CSS + Framer Motion. No canvas. Every animation
// collapses to a static frame when prefers-reduced-motion.

import Image from 'next/image'
import { motion, useReducedMotion } from 'framer-motion'

interface HeroHologramProps {
  /** Width of the shield itself, in px. Pass per breakpoint. */
  size?: number
}

export function HeroHologram({ size = 95 }: HeroHologramProps) {
  const reduce = useReducedMotion()
  const containerW = size * 1.05
  const containerH = size * 1.55

  const flicker = reduce
    ? { opacity: 1 }
    : { opacity: [1, 0.97, 1, 0.99, 1, 1, 0.94, 1] }

  // Five thin rays. Middle is brightest + slightly thicker;
  // outer two are dimmer + thinner. Reads as "light projected
  // upward" instead of "glow block".
  const RAYS: Array<{ xFrac: number; w: number; mid: boolean }> = [
    { xFrac: -0.18, w: 1,   mid: false },
    { xFrac: -0.09, w: 1,   mid: false },
    { xFrac:  0,    w: 1.5, mid: true  },
    { xFrac:  0.09, w: 1,   mid: false },
    { xFrac:  0.18, w: 1,   mid: false },
  ]

  return (
    <div
      className="relative pointer-events-none select-none"
      style={{ width: containerW, height: containerH }}
      aria-hidden
    >
      {/* ─── Projector base puck ────────────────────────────
          Small. Just enough to ground the shield. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: 0,
          width: size * 0.7,
          height: size * 0.11,
          background:
            'radial-gradient(ellipse at center, rgba(140,255,235,0.45) 0%, rgba(124,255,0,0.18) 40%, transparent 80%)',
          filter: 'blur(3px)',
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

      {/* ─── Inner base hotspot ─────────────────────────── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: size * 0.025,
          width: size * 0.28,
          height: size * 0.06,
          background:
            'radial-gradient(ellipse at center, rgba(220,255,255,0.85) 0%, transparent 70%)',
          filter: 'blur(1.5px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 1 }}
        animate={reduce ? { opacity: 1 } : { opacity: [0.7, 1, 0.7] }}
        transition={
          reduce
            ? undefined
            : { duration: 2.2, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── Thin projection rays ───────────────────────────
          The "light projected upward" cue. Five thin shafts
          rising from the base to the shield. Each shimmers on
          its own offset cycle so the projection feels alive
          rather than uniform. */}
      {RAYS.map((ray, i) => (
        <motion.div
          key={i}
          className="absolute"
          style={{
            left: `calc(50% + ${ray.xFrac * size}px)`,
            transform: 'translateX(-50%)',
            bottom: size * 0.04,
            width: ray.w,
            height: size * 1.0,
            background: ray.mid
              ? 'linear-gradient(180deg, rgba(140,255,235,0) 0%, rgba(140,255,235,0.45) 45%, rgba(220,255,255,0.78) 100%)'
              : 'linear-gradient(180deg, rgba(140,255,235,0) 0%, rgba(140,255,235,0.22) 45%, rgba(140,255,235,0.5) 100%)',
            filter: 'blur(0.6px)',
            mixBlendMode: 'screen',
            opacity: ray.mid ? 0.85 : 0.55,
          }}
          animate={
            reduce
              ? undefined
              : {
                  opacity: [
                    ray.mid ? 0.7 : 0.4,
                    ray.mid ? 0.95 : 0.65,
                    ray.mid ? 0.7 : 0.4,
                  ],
                }
          }
          transition={
            reduce
              ? undefined
              : {
                  duration: 2.4 + i * 0.35,
                  repeat: Infinity,
                  ease: 'easeInOut',
                }
          }
        />
      ))}

      {/* ─── The shield ─────────────────────────────────────
          Sits at the top of the container, anchored above the
          rays. Subtle float, subtle flicker, restrained drop
          shadow. No big halo box behind it — drop-shadow is
          shaped to the shield silhouette. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          top: 0,
          width: size,
          height: size,
        }}
        animate={reduce ? undefined : { y: [0, -3, 0] }}
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
            // Silhouette-shaped glow only; no halo block.
            filter:
              'drop-shadow(0 0 6px rgba(124,255,0,0.45)) drop-shadow(0 0 14px rgba(124,255,0,0.20))',
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

          {/* ─── Subtle vertical-moving scanlines ──────────
              Clipped to the shield via mix-blend-mode. */}
          {!reduce && (
            <motion.div
              className="absolute inset-0 pointer-events-none"
              style={{
                backgroundImage:
                  'repeating-linear-gradient(0deg, rgba(220,255,235,0.05) 0px, rgba(220,255,235,0.05) 1px, transparent 1px, transparent 4px)',
                backgroundSize: '100% 8px',
                mixBlendMode: 'overlay',
              }}
              animate={{ backgroundPositionY: ['0px', '16px'] }}
              transition={{ duration: 2.8, repeat: Infinity, ease: 'linear' }}
            />
          )}
        </motion.div>
      </motion.div>
    </div>
  )
}
