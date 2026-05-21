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
  type MotionValue,
} from 'framer-motion'
import { SectionContainer } from '@/components/layout/section-container'
import { PrimaryButton } from '@/components/ui/primary-button'
import { GradientDivider } from '@/components/ui/gradient-divider'
import { ScanVisualization } from './scan-visualization'

// ── Data ──────────────────────────────────────────────────────────────────────

const STATUSES = [
  'Mapping attack surface...',
  'Enumerating technologies...',
  'Running vulnerability checks...',
  'Analyzing security posture...',
  'Correlating threat intelligence...',
  'Building remediation report...',
]

const METRICS = [
  { label: 'Assets Discovered', value: 245 },
  { label: 'Technologies Identified', value: 38 },
  { label: 'Vulnerabilities Found', value: 18 },
  { label: 'Critical Risks', value: 4 },
]

const LOG_ENTRIES = [
  { level: 'INFO',     text: 'Tech stack detected: Next.js' },
  { level: 'INFO',     text: 'Cloud provider: AWS' },
  { level: 'WARN',     text: 'Missing CSP header' },
  { level: 'WARN',     text: 'Outdated dependency detected' },
  { level: 'CRITICAL', text: 'Public admin endpoint exposed' },
  { level: 'INFO',     text: 'SSL/TLS configuration validated' },
  { level: 'WARN',     text: 'Cookie missing Secure flag' },
  { level: 'INFO',     text: 'Scan report generated' },
]

const LEVEL_COLOR: Record<string, string> = {
  INFO:     'rgba(139,255,62,0.65)',
  WARN:     'rgba(234,179,8,0.75)',
  CRITICAL: 'rgba(239,68,68,0.9)',
}

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

// ── Terminal ──────────────────────────────────────────────────────────────────

function ScanTerminal({ inView }: { inView: boolean }) {
  const [visibleCount, setVisibleCount] = useState(0)
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!inView) return
    let count = 0

    function step() {
      if (count < LOG_ENTRIES.length) {
        count++
        setVisibleCount(count)
        timerRef.current = setTimeout(step, 1100 + Math.random() * 700)
      } else {
        timerRef.current = setTimeout(() => {
          setVisibleCount(0)
          count = 0
          timerRef.current = setTimeout(step, 400)
        }, 2800)
      }
    }

    timerRef.current = setTimeout(step, 600)
    return () => clearTimeout(timerRef.current)
  }, [inView])

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [visibleCount])

  return (
    <div
      className="rounded-[16px] border border-[rgba(139,255,62,0.12)] overflow-hidden flex flex-col"
      style={{ background: 'rgba(3,7,18,0.92)', height: 340 }}
    >
      {/* Terminal header */}
      <div
        className="flex items-center gap-2 px-4 py-2.5 border-b border-[rgba(139,255,62,0.08)] flex-shrink-0"
        style={{ background: 'rgba(139,255,62,0.04)' }}
      >
        <div className="flex gap-1.5">
          {['rgba(239,68,68,0.6)', 'rgba(234,179,8,0.6)', 'rgba(139,255,62,0.6)'].map((c, i) => (
            <div key={i} className="w-2.5 h-2.5 rounded-full" style={{ background: c }} />
          ))}
        </div>
        <span className="text-[9px] font-mono text-[rgba(255,255,255,0.3)] ml-1">
          webhound — live scan feed
        </span>
        <div className="ml-auto flex items-center gap-1.5">
          <motion.div
            className="w-1.5 h-1.5 rounded-full bg-[#8BFF3E]"
            animate={{ opacity: [1, 0.2, 1] }}
            transition={{ duration: 0.9, repeat: Infinity }}
          />
          <span className="text-[8px] font-bold text-[rgba(139,255,62,0.6)] tracking-widest">LIVE</span>
        </div>
      </div>

      {/* Log feed */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-3 flex flex-col gap-1.5"
        style={{ scrollbarWidth: 'none' }}>
        <AnimatePresence>
          {LOG_ENTRIES.slice(0, visibleCount).map((entry, i) => (
            <motion.div
              key={i}
              className="flex items-start gap-2 font-mono"
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.25 }}
            >
              <span className="text-[rgba(255,255,255,0.22)] text-[9px] flex-shrink-0 mt-px font-mono">
                {String(i).padStart(2, '0')}
              </span>
              <span
                className="text-[9px] font-bold flex-shrink-0"
                style={{ color: LEVEL_COLOR[entry.level] }}
              >
                [{entry.level}]
              </span>
              <span className="text-[9px] text-[rgba(255,255,255,0.65)] break-words">
                {entry.text}
              </span>
            </motion.div>
          ))}
        </AnimatePresence>

        {/* Blinking cursor */}
        {visibleCount > 0 && visibleCount <= LOG_ENTRIES.length && (
          <div className="flex items-center gap-2 font-mono mt-0.5">
            <span className="text-[rgba(255,255,255,0.22)] text-[9px]">&gt;</span>
            <motion.span
              className="w-1.5 h-3 bg-[rgba(139,255,62,0.8)] inline-block"
              animate={{ opacity: [1, 0] }}
              transition={{ duration: 0.55, repeat: Infinity, repeatType: 'reverse' }}
            />
          </div>
        )}
      </div>
    </div>
  )
}

// ── Left column ───────────────────────────────────────────────────────────────

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
      {/* Label */}
      <div className="inline-flex items-center gap-2 mb-7">
        <motion.span
          className="w-1.5 h-1.5 rounded-full bg-[#8BFF3E]"
          animate={{ opacity: [1, 0.2, 1] }}
          transition={{ duration: 0.9, repeat: Infinity }}
          style={{ boxShadow: '0 0 5px rgba(139,255,62,1)' }}
        />
        <span className="text-[10px] font-bold text-[#8BFF3E] tracking-[0.22em] uppercase">
          Live AI Scanning
        </span>
      </div>

      {/* Heading */}
      <h2
        className="font-bold leading-[0.9] tracking-[-0.025em] mb-6"
        style={{ fontSize: 'clamp(2.2rem, 3.5vw, 3.6rem)' }}
      >
        <span className="text-white block">See WebHound</span>
        <span
          className="block text-[#8BFF3E]"
          style={{ textShadow: '0 0 48px rgba(139,255,62,0.28)' }}
        >
          Scan In Real Time.
        </span>
      </h2>

      {/* Description */}
      <p className="text-[rgba(255,255,255,0.44)] text-base leading-relaxed max-w-[400px] mb-8">
        WebHound continuously maps attack surfaces, analyzes vulnerabilities,
        and prioritizes threats with AI-assisted intelligence.
      </p>

      {/* Progress bar */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] font-bold text-[rgba(255,255,255,0.45)] tracking-wider uppercase">
            Scan Progress
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

      {/* CTA */}
      <Link href="/dashboard" tabIndex={-1}>
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

  const { scrollYProgress } = useScroll({
    target: sectionRef,
    offset: ['start 0.85', 'center 0.4'],
  })
  const rawProgress = useTransform(scrollYProgress, [0, 1], [0, 73])
  const progressValue = useSpring(rawProgress, { stiffness: 55, damping: 18 })
  const progressWidth = useTransform(progressValue, v => `${v}%`)

  return (
    <section id="pricing" ref={sectionRef} className="relative overflow-hidden bg-[#020617] py-28 sm:py-36 section-contain">
      {/* Top divider */}
      <GradientDivider className="absolute top-0 left-0 right-0" glow />

      {/* Animated cyber grid — GPU layer */}
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

      {/* Moving scan line */}
      <div aria-hidden className="absolute inset-0 overflow-hidden pointer-events-none">
        <div
          className="absolute left-0 right-0 h-px"
          style={{
            background: 'linear-gradient(90deg, transparent 0%, rgba(139,255,62,0.12) 40%, rgba(139,255,62,0.12) 60%, transparent 100%)',
            animation: 'scanSweep 9s linear infinite',
          }}
        />
      </div>

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
        <div ref={inViewRef} className="grid grid-cols-1 lg:grid-cols-[1fr_auto_1fr] gap-12 xl:gap-16 items-center">
          {/* Left */}
          <LeftContent inView={inView} progressWidth={progressWidth} />

          {/* Center */}
          <div className="flex items-center justify-center">
            <div className="w-full max-w-[440px] mx-auto">
              <ScanVisualization />
            </div>
          </div>

          {/* Right — hidden on mobile to prevent excessive page height */}
          <div className="hidden lg:flex flex-col gap-4">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[9px] font-bold text-[rgba(139,255,62,0.5)] tracking-[0.2em] uppercase">
                Live Findings Feed
              </span>
            </div>
            <ScanTerminal inView={inView} />
          </div>
        </div>
      </SectionContainer>

      {/* Bottom divider */}
      <GradientDivider className="absolute bottom-0 left-0 right-0" />
    </section>
  )
}
