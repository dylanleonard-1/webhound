/**
 * Shared motion constants — single source of truth for animation values.
 * Import from here rather than hardcoding in components.
 */

// ── Easing curves ─────────────────────────────────────────────────────────────

export const EASE_CINEMATIC = [0.25, 0.46, 0.45, 0.94] as const
export const EASE_OUT       = [0.0, 0.0, 0.2, 1.0]     as const
export const EASE_IN_OUT    = [0.4, 0, 0.2, 1]          as const

// ── Durations (seconds) ───────────────────────────────────────────────────────

export const DURATION = {
  instant:  0.15,
  fast:     0.25,
  normal:   0.45,
  slow:     0.65,
  cinematic: 0.85,
} as const

// ── Spring presets ────────────────────────────────────────────────────────────

export const SPRING_GENTLE = { stiffness: 50,  damping: 20, restDelta: 0.001 }
export const SPRING_MEDIUM = { stiffness: 32,  damping: 18, restDelta: 0.001 }
export const SPRING_STIFF  = { stiffness: 180, damping: 24, restDelta: 0.001 }
export const SPRING_TILT   = { stiffness: 55,  damping: 22, restDelta: 0.001 }

// ── Reusable transition objects ───────────────────────────────────────────────

export const TRANSITION_NORMAL = {
  duration: DURATION.normal,
  ease: EASE_CINEMATIC,
} as const

export const TRANSITION_SLOW = {
  duration: DURATION.slow,
  ease: EASE_CINEMATIC,
} as const

// ── Common initial states ─────────────────────────────────────────────────────

export const FADE_UP_INITIAL    = { opacity: 0, y: 24,  filter: 'blur(8px)' } as const
export const FADE_UP_ANIMATE    = { opacity: 1, y: 0,   filter: 'blur(0px)' } as const
export const FADE_IN_INITIAL    = { opacity: 0, filter: 'blur(8px)' }         as const
export const FADE_IN_ANIMATE    = { opacity: 1, filter: 'blur(0px)' }         as const

// ── Stagger helpers ───────────────────────────────────────────────────────────

export const staggerDelay = (index: number, base = 0.08, start = 0.1) =>
  start + index * base
