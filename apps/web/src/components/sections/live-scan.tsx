'use client'

import { useRef, useState, useEffect } from 'react'
import Link from 'next/link'
import {
  motion,
  AnimatePresence,
  useScroll,
  useTransform,
  useSpring,
  useInView,
  useReducedMotion,
  type MotionValue,
} from 'framer-motion'
import { SectionContainer } from '@/components/layout/section-container'
import { PrimaryButton } from '@/components/ui/primary-button'
import { GradientDivider } from '@/components/ui/gradient-divider'

// ── Data ──────────────────────────────────────────────────────────────────────
//
// Slice 3 jargon rewrite (D6): plain-English status + metric labels.
// Replaced 'attack surface', 'enumerating technologies', 'vulnerability
// checks', 'security posture', 'threat intelligence', 'remediation
// report' with outcomes a small business owner recognises. Removed
// the LOG_ENTRIES + LEVEL_COLOR fake terminal feed (ScanTerminal was
// dropped per D5 — simulated theatre that competed with the real
// sample-finding composition for the proof slot).

const STATUSES = [
  'Looking at every page on your site...',
  'Checking the tools your site uses...',
  'Finding security weaknesses...',
  'Ranking by what to fix first...',
  'Comparing against known threats...',
  'Writing your plain-English report...',
]

const METRICS = [
  { label: 'Pages checked',           value: 245 },
  { label: 'Tools & vendors found',   value: 38  },
  { label: 'Issues found',            value: 18  },
  { label: 'Need urgent attention',   value: 4   },
]

// ── Metric count-up ───────────────────────────────────────────────────────────

function MetricItem({ label, value, inView, delay = 0 }: {
  label: string; value: number; inView: boolean; delay?: number
}) {
  const numRef = useRef<HTMLSpanElement>(null)
  const startRef = useRef<number>(0)
  const rafRef = useRef<number>(0)

  useEffect(() => {
    if (!inView) return
    cancelAnimationFrame(rafRef.current)
    startRef.current = 0
    const duration = 1400
    const delayMs = delay * 1000

    const tick = (ts: number) => {
      if (!startRef.current) startRef.current = ts
      const elapsed = ts - startRef.current
      if (elapsed < delayMs) { rafRef.current = requestAnimationFrame(tick); return }
      const p = Math.min(1, (elapsed - delayMs) / duration)
      const e = 1 - Math.pow(1 - p, 3)
      if (numRef.current) numRef.current.textContent = String(Math.round(e * value))
      if (p < 1) rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [inView, value, delay])

  return (
    <div className="flex flex-col gap-0.5">
      <span ref={numRef} className="text-2xl font-black text-white font-mono tabular-nums">0</span>
      <span className="text-[10px] text-[rgba(255,255,255,0.42)] leading-tight">{label}</span>
    </div>
  )
}

// Slice 3 D5 — removed the simulated ScanTerminal component
// entirely. Reasons documented inline in the slice commit:
// developer-aesthetic, hardcoded log data labelled "LIVE", competed
// with the real sample-finding composition for the proof slot.
// The sample composition (added Slice 2) now occupies that slot and
// uses plain English that the SBO mental model accepts.

// ── Left column ───────────────────────────────────────────────────────────────

// ── Sample findings (Slice 2 — replaces the deleted radar) ────────────────────
//
// Static composition of three plain-English findings the scanner
// actually produces. One CRITICAL + one HIGH + one MEDIUM, severity-
// tiered the same way ExampleFindings is. Designed to deliver on
// the "See WebHound scan in real time" headline on every breakpoint
// (mobile previously had narrative-only after the radar removal).
//
// Lives co-located with LiveScan to match the file's existing
// pattern of holding sub-components inline.

interface SampleFinding {
  severity: 'critical' | 'high' | 'medium'
  title: string
  detail: string
}

const SAMPLE_FINDINGS: SampleFinding[] = [
  {
    severity: 'critical',
    title: 'Customer database accessible without a password',
    detail: 'Anyone can read your customer list, including emails and order history.',
  },
  {
    severity: 'high',
    title: 'Third-party tracking script violates your privacy policy',
    detail: 'A script on every page sends visitor data to a country your policy says you don’t use.',
  },
  {
    severity: 'medium',
    title: 'Site certificate expires in 9 days',
    detail: 'Browsers will show a warning to every visitor. Most don’t come back.',
  },
]

const SEVERITY_THEME: Record<SampleFinding['severity'], { label: string; color: string; bg: string; border: string }> = {
  critical: { label: 'Critical', color: '#ef4444', bg: 'rgba(239,68,68,0.07)', border: 'rgba(239,68,68,0.32)' },
  high:     { label: 'High',     color: '#f97316', bg: 'rgba(249,115,22,0.07)', border: 'rgba(249,115,22,0.32)' },
  medium:   { label: 'Medium',   color: '#eab308', bg: 'rgba(234,179,8,0.07)', border: 'rgba(234,179,8,0.32)' },
}

function SampleFindings() {
  return (
    <div
      className="w-full max-w-[420px] rounded-[16px] p-4 flex flex-col gap-3"
      style={{
        background: 'rgba(8,12,22,0.7)',
        border: '1px solid rgba(255,255,255,0.06)',
        backdropFilter: 'blur(8px)',
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-2 pb-3"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}
      >
        <span className="text-[9px] font-bold tracking-[0.22em] uppercase" style={{ color: 'rgba(139,255,62,0.7)' }}>
          Sample scan report
        </span>
        <span className="text-[10px] font-mono" style={{ color: 'rgba(255,255,255,0.32)' }}>
          3 findings
        </span>
      </div>

      {/* Finding stack */}
      {SAMPLE_FINDINGS.map((f, i) => {
        const s = SEVERITY_THEME[f.severity]
        return (
          <div
            key={i}
            className="rounded-[10px] p-3 flex flex-col gap-1.5"
            style={{ background: 'rgba(2,6,23,0.55)', border: '1px solid rgba(255,255,255,0.05)' }}
          >
            <div className="flex items-center gap-2">
              <span
                className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider flex-shrink-0"
                style={{ background: s.bg, color: s.color, border: `1px solid ${s.border}` }}
              >
                {s.label}
              </span>
              <span className="text-[12.5px] font-semibold text-white leading-[1.3]">
                {f.title}
              </span>
            </div>
            <p className="text-[11.5px] leading-[1.55] pl-[3px]" style={{ color: 'rgba(255,255,255,0.52)' }}>
              {f.detail}
            </p>
          </div>
        )
      })}
    </div>
  )
}

function LeftContent({ inView, progressWidth }: {
  inView: boolean
  progressWidth: MotionValue<string>
}) {
  const [statusIdx, setStatusIdx] = useState(0)

  useEffect(() => {
    if (!inView) return
    const id = setInterval(() => setStatusIdx(i => (i + 1) % STATUSES.length), 2400)
    return () => clearInterval(id)
  }, [inView])

  return (
    <div className="flex flex-col">
      {/* Label — Slice 3 jargon rewrite (D6): 'Live AI Scanning'
          → 'Live scan demo'. The slot is still useful for
          signalling the section's purpose, but stripped of the
          buzzword-AI framing. */}
      <div className="inline-flex items-center gap-2 mb-7">
        <motion.span
          className="w-1.5 h-1.5 rounded-full bg-[#8BFF3E]"
          animate={{ opacity: [1, 0.2, 1] }}
          transition={{ duration: 0.9, repeat: Infinity }}
          style={{ boxShadow: '0 0 5px rgba(139,255,62,1)' }}
        />
        <span className="text-[10px] font-bold text-[#8BFF3E] tracking-[0.22em] uppercase">
          Live scan demo
        </span>
      </div>

      {/* Heading — Slice 3 outcome-named. 'See WebHound scan in
          real time' was a feature description; this is what the
          visitor cares about: what they'll actually find. */}
      <h2
        className="font-bold leading-[0.95] tracking-[-0.025em] mb-6 text-white"
        style={{ fontSize: 'clamp(2.2rem, 3.5vw, 3.6rem)' }}
      >
        See what your site is exposing right now.
      </h2>

      {/* Description — Slice 3 D6 rewrite. Removed banned jargon
          ('attack surface', 'vulnerabilities', 'AI-assisted
          intelligence'). Replaced with the three-clause SBO
          mental-model: what we look at, what we find, what we tell
          you. */}
      <p className="text-[rgba(255,255,255,0.62)] text-base leading-relaxed max-w-[440px] mb-8">
        WebHound looks at your website the same way an attacker
        would — every page, every script, every form — and tells
        you in plain English what we found and what to fix first.
      </p>

      {/* Progress bar */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] font-bold text-[rgba(255,255,255,0.55)] tracking-wider uppercase">
            Scan progress
          </span>
          <span className="text-[10px] font-bold text-[#8BFF3E] font-mono">In progress</span>
        </div>
        <div className="relative h-1.5 rounded-full bg-[rgba(139,255,62,0.08)] overflow-hidden">
          <motion.div
            className="absolute left-0 top-0 h-full rounded-full bg-[#8BFF3E]"
            style={{ width: progressWidth, boxShadow: '0 0 10px rgba(139,255,62,0.5), 4px 0 12px rgba(139,255,62,0.3)' }}
          />
          {/* Shimmer sweep */}
          <motion.div
            className="absolute top-0 bottom-0 w-16"
            style={{ background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent)' }}
            animate={{ left: ['-20%', '120%'] }}
            transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut', delay: 0.8 }}
          />
        </div>
      </div>

      {/* Status text */}
      <div className="relative h-5 overflow-hidden mb-8">
        <AnimatePresence mode="wait">
          <motion.span
            key={statusIdx}
            className="absolute text-[11px] text-[rgba(139,255,62,0.7)] font-mono"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.3 }}
          >
            {STATUSES[statusIdx]}
          </motion.span>
        </AnimatePresence>
      </div>

      {/* Metrics grid */}
      <div className="grid grid-cols-2 gap-4 mb-9 p-4 rounded-[13px] border border-[rgba(139,255,62,0.08)]"
        style={{ background: 'rgba(6,13,26,0.6)' }}>
        {METRICS.map((m, i) => (
          <MetricItem key={m.label} label={m.label} value={m.value} inView={inView} delay={0.2 + i * 0.15} />
        ))}
      </div>

      {/* CTA — unified to /scan per landing-page rebuild Slice 1 */}
      <Link href="/scan" tabIndex={-1}>
        <PrimaryButton>Start Free Scan</PrimaryButton>
      </Link>
    </div>
  )
}

// ── Section export ────────────────────────────────────────────────────────────

export function LiveScan() {
  const sectionRef = useRef<HTMLDivElement>(null)
  const inViewRef = useRef<HTMLDivElement>(null)
  const inView = useInView(inViewRef, { once: true, margin: '-80px' })

  // Slice 2 — reduced-motion guard. When the user prefers reduced
  // motion we drop the two infinite CSS background animations
  // (grid scroll + scan sweep) and the framer-motion infinite
  // pulses inherit the prefersReducedMotion default. Respects
  // WCAG 2.1 Success Criterion 2.3.3.
  const prefersReducedMotion = useReducedMotion()

  const { scrollYProgress } = useScroll({
    target: sectionRef,
    offset: ['start 0.85', 'center 0.4'],
  })
  const rawProgress = useTransform(scrollYProgress, [0, 1], [0, 73])
  const progressValue = useSpring(rawProgress, { stiffness: 55, damping: 18 })
  const progressWidth = useTransform(progressValue, v => `${v}%`)

  return (
    <section id="live-scan" ref={sectionRef} className="relative overflow-hidden bg-[#020617] py-20 sm:py-28 section-contain">
      {/* Top divider */}
      <GradientDivider className="absolute top-0 left-0 right-0" glow />

      {/* Animated cyber grid — GPU layer. Off entirely under
          prefers-reduced-motion (static decorative grid would
          continue to fight for attention). */}
      {!prefersReducedMotion && (
        <div
          aria-hidden
          className="absolute inset-0 pointer-events-none opacity-[0.028] grid-anim-layer"
          style={{
            backgroundImage: `
              linear-gradient(rgba(139,255,62,1) 1px, transparent 1px),
              linear-gradient(90deg, rgba(139,255,62,1) 1px, transparent 1px)
            `,
            backgroundSize: '40px 40px',
            animation: 'gridScroll 32s linear infinite',
          }}
        />
      )}

      {/* Moving scan line — off under prefers-reduced-motion. */}
      {!prefersReducedMotion && (
        <div aria-hidden className="absolute inset-0 overflow-hidden pointer-events-none">
          <div
            className="absolute left-0 right-0 h-px"
            style={{
              background: 'linear-gradient(90deg, transparent 0%, rgba(139,255,62,0.12) 40%, rgba(139,255,62,0.12) 60%, transparent 100%)',
              animation: 'scanSweep 9s linear infinite',
            }}
          />
        </div>
      )}

      {/* Center glow fog */}
      <div
        aria-hidden
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none"
        style={{
          width: 700,
          height: 700,
          background: 'radial-gradient(circle, rgba(139,255,62,0.04) 0%, transparent 65%)',
          filter: 'blur(50px)',
        }}
      />

      {/* Floating particles — CSS-only, no JS animation thread */}
      <style>{`@keyframes floatUpB{0%,100%{transform:translateY(0)}50%{transform:translateY(-20px);opacity:.02}}`}</style>
      <div aria-hidden className="absolute inset-0 overflow-hidden pointer-events-none">
        {Array.from({ length: 6 }, (_, i) => (
          <div
            key={i}
            className="absolute rounded-full bg-[#8BFF3E]"
            style={{
              left: `${14 + i * 14}%`,
              top: `${20 + (i % 3) * 22}%`,
              width: 1 + (i % 2) * 0.6,
              height: 1 + (i % 2) * 0.6,
              opacity: 0.06 + (i % 3) * 0.03,
              animation: `floatUpB ${5 + i * 0.8}s ease-in-out ${i * 0.9}s infinite`,
            }}
          />
        ))}
      </div>

      <SectionContainer size="xl">
        {/*
          Slice 3 D5 layout: 1 column on mobile (text + sample),
          2 columns on desktop (text + sample). ScanTerminal column
          removed — simulated developer-aesthetic that competed
          with the real sample-finding composition for the proof
          slot. The sample composition now occupies the proof slot
          on every breakpoint.
        */}
        <div ref={inViewRef} className="grid grid-cols-1 lg:grid-cols-2 gap-10 xl:gap-16 items-center">
          {/* Left — narrative + scan progress */}
          <LeftContent inView={inView} progressWidth={progressWidth} />

          {/* Right — static sample-finding composition. Visible on
              every breakpoint; on mobile this delivers the "see
              what a scan looks like" promise the headline makes. */}
          <div className="flex items-center justify-center lg:justify-end">
            <SampleFindings />
          </div>
        </div>
      </SectionContainer>

      {/* Bottom divider */}
      <GradientDivider className="absolute bottom-0 left-0 right-0" />
    </section>
  )
}
