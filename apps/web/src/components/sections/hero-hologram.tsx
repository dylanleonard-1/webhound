'use client'

// WebHound — components/sections/hero-hologram.tsx
// Hero v6 — projection that visibly connects base to shield.
//
// v5 review fixes baked in here:
//   • Shield +14% bigger (95 → 108 default) so it reads as
//     a projected image, not a sticker.
//   • Soft cone-shaped green/cyan glow added BEHIND the
//     shield. Narrow at the projector base, widens upward to
//     just past the shield. This is what visually bridges the
//     base to the shield — the "projected upward" cue.
//   • Five thin projection rays brightened (opacity bases
//     0.85/0.55 → 0.92/0.68) and middle ray thickened 1.5 →
//     2px so the path from base to shield reads clearly.
//   • Small radial glow under the shield itself so the
//     shield sits on the cone instead of hovering above it.
//   • Scanlines + flicker + float kept.
//   • Outer green halo block stays REMOVED.
//
// All animations respect prefers-reduced-motion.

import Image from 'next/image'
import { motion, useReducedMotion } from 'framer-motion'

interface HeroHologramProps {
  /** Width of the shield itself, in px. Pass per breakpoint. */
  size?: number
}

export function HeroHologram({ size = 108 }: HeroHologramProps) {
  const reduce = useReducedMotion()
  const containerW = size * 1.05
  const containerH = size * 1.55

  const flicker = reduce
    ? { opacity: 1 }
    : { opacity: [1, 0.97, 1, 0.99, 1, 1, 0.94, 1] }

  // Five thin rays. Middle is brightest + slightly thicker;
  // outer rays dimmer + thinner. Reads as "light projected
  // upward". v6: opacities bumped so the connection from base
  // to shield is unambiguous.
  const RAYS: Array<{ xFrac: number; w: number; mid: boolean }> = [
    { xFrac: -0.18, w: 1,   mid: false },
    { xFrac: -0.09, w: 1,   mid: false },
    { xFrac:  0,    w: 2,   mid: true  },
    { xFrac:  0.09, w: 1,   mid: false },
    { xFrac:  0.18, w: 1,   mid: false },
  ]

  return (
    <div
      className="relative pointer-events-none select-none"
      style={{ width: containerW, height: containerH }}
      aria-hidden
    >
      {/* ─── 1. Projector base puck ────────────────────── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: 0,
          width: size * 0.7,
          height: size * 0.11,
          background:
            'radial-gradient(ellipse at center, rgba(140,255,235,0.5) 0%, rgba(124,255,0,0.2) 40%, transparent 80%)',
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

      {/* ─── 2. Inner base hotspot ────────────────────── */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          bottom: size * 0.025,
          width: size * 0.3,
          height: size * 0.07,
          background:
            'radial-gradient(ellipse at center, rgba(220,255,255,0.9) 0%, transparent 70%)',
          filter: 'blur(1.5px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 1 }}
        animate={reduce ? { opacity: 1 } : { opacity: [0.75, 1, 0.75] }}
        transition={
          reduce
            ? undefined
            : { duration: 2.2, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 3. Soft cone-shaped green/cyan glow ────────────
          The "projection beam" the brief asked for. A narrow
          cone widening from the base up to just past the
          shield. v8: opacity raised 0.20 → 0.26 so the
          projection clearly outshines the puck's own LED. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          bottom: size * 0.04,
          width: containerW * 0.55,
          height: containerH * 0.92,
          background:
            'conic-gradient(from 90deg at 50% 100%, rgba(124,255,0,0) 0deg, rgba(124,255,0,0.26) 12deg, rgba(140,255,235,0.16) 22deg, rgba(124,255,0,0) 38deg)',
          filter: 'blur(10px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.78 }}
        animate={reduce ? { opacity: 0.78 } : { opacity: [0.62, 0.92, 0.62] }}
        transition={
          reduce
            ? undefined
            : { duration: 4.5, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 3b. Cyan core inside the cone ─────────────────
          Tighter, cyan-leaning, just inside the cone. Sells
          the "real holographic light" temperature. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2"
        style={{
          bottom: size * 0.06,
          width: containerW * 0.3,
          height: containerH * 0.75,
          background:
            'conic-gradient(from 90deg at 50% 100%, rgba(140,255,235,0) 0deg, rgba(140,255,235,0.22) 10deg, rgba(140,255,235,0) 22deg)',
          filter: 'blur(6px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.7 }}
        animate={reduce ? { opacity: 0.7 } : { opacity: [0.55, 0.85, 0.55] }}
        transition={
          reduce
            ? undefined
            : { duration: 3.2, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 4. Thin projection rays (brighter than v5) ───
          v8: middle ray pulse target raised to 1.0 (was
          0.95) and base opacity to 1.0 so the central beam
          clearly outshines the puck's built-in LED. */}
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
              ? 'linear-gradient(180deg, rgba(140,255,235,0) 0%, rgba(140,255,235,0.62) 45%, rgba(220,255,255,1) 100%)'
              : 'linear-gradient(180deg, rgba(140,255,235,0) 0%, rgba(140,255,235,0.36) 45%, rgba(140,255,235,0.72) 100%)',
            filter: 'blur(0.6px)',
            mixBlendMode: 'screen',
            opacity: ray.mid ? 1 : 0.74,
          }}
          animate={
            reduce
              ? undefined
              : {
                  opacity: [
                    ray.mid ? 0.85 : 0.58,
                    ray.mid ? 1 : 0.82,
                    ray.mid ? 0.85 : 0.58,
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

      {/* ─── 5. Soft radial glow seated under the shield ──
          Tight, low-opacity, shaped to the shield silhouette
          so the shield sits ON the cone instead of hovering
          above it. */}
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 rounded-full"
        style={{
          top: size * 0.05,
          width: size * 1.1,
          height: size * 1.1,
          background:
            'radial-gradient(circle at center, rgba(124,255,0,0.20) 0%, rgba(140,255,235,0.10) 35%, transparent 70%)',
          filter: 'blur(12px)',
          mixBlendMode: 'screen',
        }}
        initial={{ opacity: 0.65 }}
        animate={reduce ? { opacity: 0.65 } : { opacity: [0.5, 0.8, 0.5] }}
        transition={
          reduce
            ? undefined
            : { duration: 3.5, repeat: Infinity, ease: 'easeInOut' }
        }
      />

      {/* ─── 6. The shield ──────────────────────────────────
          v5 floated at y 0→-3→0 and felt disconnected from the
          base. v6 reduces float amplitude (−2) so the shield
          stays visibly seated on the cone. */}
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
              'drop-shadow(0 0 6px rgba(124,255,0,0.50)) drop-shadow(0 0 14px rgba(124,255,0,0.24))',
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

          {/* ─── 7. Subtle vertical-moving scanlines ─────── */}
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
              transition={{ duration: 2.8, repeat: Infinity, ease: 'linear' }}
            />
          )}
        </motion.div>
      </motion.div>
    </div>
  )
}
