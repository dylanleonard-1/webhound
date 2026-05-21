'use client'

import { useRef, useMemo, useEffect } from 'react'
import { motion, useMotionValue, useTransform, useSpring, useInView } from 'framer-motion'
import { cn } from '@/lib/utils'

// ── Constants ─────────────────────────────────────────────────────────────────

const METRICS = [
  { label: 'Threat Score', value: 74, suffix: ' / 100', sub: 'Medium Risk', color: '#EAB308' },
  { label: 'Total Issues', value: 186, suffix: '', sub: '+12%', color: '#EF4444' },
  { label: 'Critical', value: 18, suffix: '', sub: '', color: '#EF4444' },
  { label: 'High', value: 32, suffix: '', sub: '', color: '#F97316' },
]

const ISSUES = [
  { label: 'Missing Security Header', count: 18, color: '#EF4444' },
  { label: 'Cross-Site Scripting (XSS)', count: 15, color: '#F97316' },
  { label: 'Outdated Library', count: 12, color: '#EAB308' },
  { label: 'Cookie Without Secure Flag', count: 9, color: '#3B82F6' },
  { label: 'Content Security Policy (CSP)', count: 7, color: '#6B7280' },
]

const DONUT_SEGS = [
  { label: 'Critical', count: 18, color: '#EF4444' },
  { label: 'High', count: 32, color: '#F97316' },
  { label: 'Medium', count: 86, color: '#EAB308' },
  { label: 'Low', count: 50, color: '#8BFF3E' },
]
const DONUT_TOTAL = 186
const DONUT_R = 42
const DONUT_CIRC = 2 * Math.PI * DONUT_R

// ── Count-up card (ref-based, zero re-renders during animation) ───────────────

interface MetricCardProps {
  label: string; value: number; suffix: string; sub: string
  color: string; inView: boolean; delay: number
}

function MetricCard({ label, value, suffix, sub, color, inView, delay }: MetricCardProps) {
  const numRef = useRef<HTMLSpanElement>(null)

  useEffect(() => {
    if (!inView) return
    let rafId: number
    let t0: number | null = null
    const DURATION = 1500
    const DELAY = delay * 1000

    const tick = (t: number) => {
      if (t0 === null) t0 = t
      const elapsed = t - t0
      if (elapsed < DELAY) { rafId = requestAnimationFrame(tick); return }
      const p = Math.min(1, (elapsed - DELAY) / DURATION)
      const e = 1 - Math.pow(1 - p, 3)
      if (numRef.current) numRef.current.textContent = String(Math.round(e * value))
      if (p < 1) rafId = requestAnimationFrame(tick)
    }
    rafId = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafId)
  }, [inView, value, delay])

  return (
    <motion.div
      className="relative p-3 rounded-[14px] border border-[rgba(139,255,62,0.08)] bg-[rgba(4,10,20,0.8)] group"
      initial={{ opacity: 0, y: 12 }}
      animate={inView ? { opacity: 1, y: 0 } : { opacity: 0, y: 12 }}
      transition={{ delay, duration: 0.5, ease: [0.25, 0.46, 0.45, 0.94] }}
      whileHover={{ y: -2, boxShadow: '0 0 20px rgba(139,255,62,0.08)' }}
    >
      <span
        className="absolute top-2.5 right-2.5 w-1.5 h-1.5 rounded-full"
        style={{ background: color, boxShadow: `0 0 5px ${color}`, animation: `pulse 2s ease-in-out ${delay}s infinite` }}
      />
      <p className="text-[9px] font-semibold text-[rgba(255,255,255,0.3)] tracking-[0.15em] uppercase mb-1.5">{label}</p>
      <p className="text-xl font-bold text-white tabular-nums leading-none mb-1">
        <span ref={numRef}>0</span>
        <span className="text-sm font-medium text-[rgba(255,255,255,0.35)]">{suffix}</span>
      </p>
      {sub && <p className="text-[10px] font-medium" style={{ color }}>{sub}</p>}
    </motion.div>
  )
}

// ── Animated SVG line graph ────────────────────────────────────────────────────

function ThreatGraph({ inView }: { inView: boolean }) {
  const lineRef = useRef<SVGPathElement>(null)
  const fillRef = useRef<SVGPathElement>(null)
  const dotRef = useRef<SVGCircleElement>(null)

  useEffect(() => {
    if (!inView) return
    let rafId: number
    const W = 260, H = 52

    const draw = () => {
      const t = Date.now() / 1000
      const pts = Array.from({ length: 13 }, (_, i): [number, number] => {
        const x = (i / 12) * W
        const base = 0.52 + 0.08 * Math.sin(i * 0.65)
        const wave = Math.sin(t * 0.35 + i * 0.9) * 0.11 + Math.sin(t * 0.22 + i * 0.55) * 0.05
        const y = H * (1 - Math.max(0.1, Math.min(0.9, base + wave)))
        return [x, y]
      })

      let d = `M ${pts[0][0]} ${pts[0][1]}`
      for (let i = 0; i < pts.length - 1; i++) {
        const mx = (pts[i][0] + pts[i + 1][0]) / 2
        d += ` C ${mx} ${pts[i][1]}, ${mx} ${pts[i + 1][1]}, ${pts[i + 1][0]} ${pts[i + 1][1]}`
      }

      if (lineRef.current) lineRef.current.setAttribute('d', d)
      if (fillRef.current) fillRef.current.setAttribute('d', `${d} L ${W} ${H} L 0 ${H} Z`)
      if (dotRef.current) {
        const last = pts[pts.length - 1]
        dotRef.current.setAttribute('cx', String(last[0]))
        dotRef.current.setAttribute('cy', String(last[1]))
      }
      rafId = requestAnimationFrame(draw)
    }
    rafId = requestAnimationFrame(draw)
    return () => cancelAnimationFrame(rafId)
  }, [inView])

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <p className="text-[9px] font-semibold text-[rgba(255,255,255,0.3)] tracking-[0.14em] uppercase">Risk Trend</p>
        <div className="flex items-center gap-1.5">
          <span className="w-1 h-1 rounded-full bg-[#8BFF3E]" style={{ boxShadow: '0 0 4px rgba(139,255,62,0.9)', animation: 'pulse 2s ease-in-out infinite' }} />
          <span className="text-[9px] font-semibold text-[rgba(139,255,62,0.7)] tracking-wider">LIVE</span>
        </div>
      </div>
      <svg viewBox="0 0 260 52" className="w-full h-13" style={{ overflow: 'visible' }}>
        <defs>
          <linearGradient id="gFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#8BFF3E" stopOpacity="0.15" />
            <stop offset="100%" stopColor="#8BFF3E" stopOpacity="0" />
          </linearGradient>
          <filter id="lineGlow" x="-20%" y="-40%" width="140%" height="180%">
            <feGaussianBlur stdDeviation="1.8" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>
        <path ref={fillRef} fill="url(#gFill)" />
        <path ref={lineRef} fill="none" stroke="#8BFF3E" strokeWidth="1.5"
              strokeLinecap="round" strokeLinejoin="round" filter="url(#lineGlow)" />
        <circle ref={dotRef} r="3" fill="#8BFF3E" filter="url(#lineGlow)" />
      </svg>
    </div>
  )
}

// ── Donut chart (ref-based) ────────────────────────────────────────────────────

function DonutChart({ inView }: { inView: boolean }) {
  const segRefs = useRef<(SVGCircleElement | null)[]>([null, null, null, null])
  const centerRef = useRef<HTMLSpanElement>(null)

  useEffect(() => {
    if (!inView) return
    let rafId: number
    let t0: number | null = null
    const DURATION = 1400

    const tick = (t: number) => {
      if (t0 === null) t0 = t
      const p = Math.min(1, (t - t0) / DURATION)
      const e = 1 - Math.pow(1 - p, 2.5)

      let cum = 0
      DONUT_SEGS.forEach((seg, i) => {
        const full = (seg.count / DONUT_TOTAL) * DONUT_CIRC
        const arc = full * e
        const el = segRefs.current[i]
        if (el) {
          el.setAttribute('stroke-dasharray', `${arc} ${DONUT_CIRC}`)
          el.setAttribute('stroke-dashoffset', String(-cum))
        }
        cum += full
      })
      if (centerRef.current) centerRef.current.textContent = String(Math.round(e * DONUT_TOTAL))
      if (p < 1) rafId = requestAnimationFrame(tick)
    }
    rafId = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafId)
  }, [inView])

  return (
    <div className="flex items-center gap-4">
      <div className="relative flex-shrink-0 w-[100px] h-[100px]">
        <svg viewBox="0 0 120 120" className="w-full h-full rotate-[-90deg]">
          <circle cx="60" cy="60" r={DONUT_R} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
          <g transform="rotate(0, 60, 60)">
            {DONUT_SEGS.map((seg, i) => (
              <circle
                key={seg.label}
                ref={el => { segRefs.current[i] = el }}
                cx="60" cy="60" r={DONUT_R}
                fill="none" stroke={seg.color} strokeWidth="8" strokeLinecap="butt"
                strokeDasharray={`0 ${DONUT_CIRC}`} strokeDashoffset="0"
              />
            ))}
          </g>
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span ref={centerRef} className="text-base font-bold text-white tabular-nums">0</span>
          <span className="text-[8px] text-[rgba(255,255,255,0.35)] font-medium mt-0.5">Total</span>
        </div>
      </div>
      <div className="flex flex-col gap-1.5">
        {DONUT_SEGS.map(s => (
          <div key={s.label} className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: s.color }} />
            <span className="text-[10px] text-[rgba(255,255,255,0.45)] min-w-0">{s.label}</span>
            <span className="text-[10px] font-bold text-white ml-auto pl-2 tabular-nums">{s.count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Issues list ────────────────────────────────────────────────────────────────

function IssuesList({ inView }: { inView: boolean }) {
  return (
    <div>
      <p className="text-[9px] font-semibold text-[rgba(255,255,255,0.3)] tracking-[0.14em] uppercase mb-3">Top Issues</p>
      <div className="space-y-2.5">
        {ISSUES.map(({ label, count, color }, i) => (
          <motion.div
            key={label}
            className="group"
            initial={{ opacity: 0, y: 6 }}
            animate={inView ? { opacity: 1, y: 0 } : { opacity: 0, y: 6 }}
            transition={{ delay: 0.35 + i * 0.07, duration: 0.4, ease: [0.25, 0.46, 0.45, 0.94] }}
          >
            <div className="flex items-center gap-2 mb-1">
              <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: color, boxShadow: `0 0 4px ${color}` }} />
              <span className="text-[11px] text-[rgba(255,255,255,0.6)] truncate flex-1 group-hover:text-white transition-colors duration-200">{label}</span>
              <span className="text-[11px] font-bold text-white tabular-nums flex-shrink-0">{count}</span>
            </div>
            <div className="ml-3.5 h-[2px] bg-[rgba(255,255,255,0.05)] rounded-full overflow-hidden">
              <motion.div
                className="h-full rounded-full"
                style={{ background: color }}
                initial={{ width: '0%' }}
                animate={inView ? { width: `${(count / 18) * 100}%` } : { width: '0%' }}
                transition={{ delay: 0.45 + i * 0.07, duration: 0.6, ease: [0.25, 0.46, 0.45, 0.94] }}
              />
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  )
}

// ── Main export ───────────────────────────────────────────────────────────────

export function ThreatDashboard() {
  const wrapRef = useRef<HTMLDivElement>(null)
  const inView = useInView(wrapRef, { once: true, margin: '-80px' })

  const mouseX = useMotionValue(0)
  const mouseY = useMotionValue(0)
  const rotX = useSpring(useTransform(mouseY, [-220, 220], [2.5, -2.5]), { stiffness: 55, damping: 22 })
  const rotY = useSpring(useTransform(mouseX, [-220, 220], [-2.5, 2.5]), { stiffness: 55, damping: 22 })

  return (
    <div
      ref={wrapRef}
      style={{ perspective: '1200px' }}
      onMouseMove={e => {
        const r = e.currentTarget.getBoundingClientRect()
        mouseX.set(e.clientX - r.left - r.width / 2)
        mouseY.set(e.clientY - r.top - r.height / 2)
      }}
      onMouseLeave={() => { mouseX.set(0); mouseY.set(0) }}
    >
      <motion.div
        style={{ rotateX: rotX, rotateY: rotY }}
        initial={{ opacity: 0, y: 28, scale: 0.96 }}
        animate={inView ? { opacity: 1, y: 0, scale: 1 } : {}}
        transition={{ duration: 0.75, ease: [0.25, 0.46, 0.45, 0.94] }}
        className={cn(
          'relative rounded-[20px] p-5',
          'bg-[rgba(4,11,22,0.88)] backdrop-blur-[28px]',
          'border border-[rgba(139,255,62,0.1)]',
          'shadow-[0_32px_80px_rgba(0,0,0,0.55),0_0_0_1px_rgba(139,255,62,0.04)]',
        )}
      >
        {/* Top edge glow */}
        <div className="absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-[rgba(139,255,62,0.22)] to-transparent pointer-events-none" />
        {/* Shimmer */}
        <div className="absolute inset-0 rounded-[20px] pointer-events-none"
             style={{ background: 'linear-gradient(135deg, rgba(139,255,62,0.012) 0%, transparent 55%)' }} />

        {/* Header bar */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#8BFF3E]"
                  style={{ boxShadow: '0 0 6px rgba(139,255,62,0.9)', animation: 'pulse 2s ease-in-out infinite' }} />
            <span className="text-[10px] font-bold text-[rgba(255,255,255,0.5)] tracking-[0.18em] uppercase">
              WebHound Intelligence
            </span>
          </div>
          <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-[rgba(139,255,62,0.08)] border border-[rgba(139,255,62,0.15)]">
            <span className="w-1 h-1 rounded-full bg-[#8BFF3E]" style={{ animation: 'pulse 1.5s ease-in-out infinite' }} />
            <span className="text-[9px] font-bold text-[rgba(139,255,62,0.8)] tracking-widest">LIVE</span>
          </div>
        </div>

        {/* Metric cards */}
        <div className="grid grid-cols-4 gap-2 mb-4">
          {METRICS.map((m, i) => <MetricCard key={m.label} {...m} inView={inView} delay={0.1 + i * 0.07} />)}
        </div>

        {/* Graph */}
        <div className="rounded-[14px] p-4 mb-4 bg-[rgba(2,6,18,0.7)] border border-[rgba(139,255,62,0.06)]">
          <ThreatGraph inView={inView} />
        </div>

        {/* Bottom: donut + issues */}
        <div className="grid grid-cols-[auto_1fr] gap-4">
          <div className="rounded-[14px] p-4 bg-[rgba(2,6,18,0.7)] border border-[rgba(139,255,62,0.06)]">
            <p className="text-[9px] font-semibold text-[rgba(255,255,255,0.3)] tracking-[0.14em] uppercase mb-3">Severity</p>
            <DonutChart inView={inView} />
          </div>
          <div className="rounded-[14px] p-4 bg-[rgba(2,6,18,0.7)] border border-[rgba(139,255,62,0.06)]">
            <IssuesList inView={inView} />
          </div>
        </div>
      </motion.div>
    </div>
  )
}
