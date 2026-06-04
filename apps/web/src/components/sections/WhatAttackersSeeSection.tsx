'use client'

// WebHound — components/sections/WhatAttackersSeeSection.tsx
// "What Attackers See" — a faithful recreation of the reference composition:
// left copy column + small info card, a large browser-framed website preview
// in the centre with security callouts wired to it left/right by thin green
// connector lines + pulsing edge dots, a GreenWaveField dot-wave band, and a
// bottom panel with the "Everything is discovered" headline, a six-step
// process row, and a CTA box on the right. Dark navy (#020617), neon green
// (#7CFF00 / #84FF3A). Presentational only; respects prefers-reduced-motion.

import Image from 'next/image'
import Link from 'next/link'
import { useEffect, useRef, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Code2,
  FileText,
  Globe,
  Lock,
  Network,
  Search,
  Share2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
  Webhook,
} from 'lucide-react'

type Icon = React.FC<{ className?: string; style?: React.CSSProperties }>

interface Callout {
  id: string
  label: string
  description: string
  icon: Icon
  side: 'left' | 'right'
  top: string // even vertical rhythm within the stage (identical spacing)
}

// 4 left · 4 right, evenly distributed with identical vertical spacing.
const CALLOUTS: Callout[] = [
  { id: 'headers', label: 'Headers', description: 'Security headers can reveal weaknesses.', icon: ShieldCheck, side: 'left', top: '6%' },
  { id: 'ssl', label: 'SSL Certificate', description: 'Expired or weak certificates create trust issues.', icon: Lock, side: 'left', top: '32%' },
  { id: 'dns', label: 'DNS Records', description: 'Misconfigurations can expose infrastructure.', icon: Globe, side: 'left', top: '58%' },
  { id: 'forms', label: 'Forms', description: 'Forms can be abused to steal data or inject attacks.', icon: FileText, side: 'left', top: '84%' },
  { id: 'javascript', label: 'JavaScript', description: 'Third-party scripts can introduce vulnerabilities.', icon: Code2, side: 'right', top: '6%' },
  { id: 'third', label: 'Third Parties', description: 'External services increase your attack surface.', icon: Share2, side: 'right', top: '32%' },
  { id: 'admin', label: 'Admin Pages', description: 'Exposed admin pages are a top target for attackers.', icon: ShieldAlert, side: 'right', top: '58%' },
  { id: 'api', label: 'API Endpoints', description: 'Unprotected APIs can leak sensitive information.', icon: Webhook, side: 'right', top: '84%' },
]

const PROCESS: { title: string; body: string; icon: Icon }[] = [
  { title: 'Crawl & Discover', body: 'We crawl your entire website like an attacker.', icon: Search },
  { title: 'Map Relationships', body: 'We map how everything connects and interacts.', icon: Network },
  { title: 'Analyze Risks', body: 'We analyze for thousands of known vulnerabilities.', icon: BarChart3 },
  { title: 'Find Weaknesses', body: 'We surface misconfigurations, exposures, and risky behavior.', icon: AlertTriangle },
  { title: 'Prioritize Threats', body: 'We rank issues by impact so you know what to fix first.', icon: Target },
  { title: 'Generate Report', body: 'You get a clear report you can actually act on.', icon: FileText },
]

const GREEN = '#7CFF00'

export function WhatAttackersSeeSection() {
  const reduce = useReducedMotion()
  const show = { once: true, amount: 0.2 } as const

  return (
    <section className="relative px-4 py-16 sm:px-6 lg:py-20" style={{ background: '#020617' }} aria-labelledby="attackers-see-heading">
      <motion.div
        className="relative mx-auto max-w-[1340px] overflow-hidden rounded-[28px]"
        style={{
          border: '1px solid rgba(255,255,255,0.07)',
          background: 'radial-gradient(120% 120% at 50% 0%, #060c16 0%, #020617 60%)',
        }}
        initial={{ opacity: 0, y: 24 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={show}
        transition={{ duration: 0.6 }}
      >
        {/* subtle grid overlay */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 opacity-[0.05]"
          style={{
            backgroundImage:
              'linear-gradient(rgba(132,255,58,1) 1px, transparent 1px), linear-gradient(90deg, rgba(132,255,58,1) 1px, transparent 1px)',
            backgroundSize: '60px 60px',
            maskImage: 'radial-gradient(ellipse 90% 70% at 55% 30%, #000 0%, transparent 80%)',
            WebkitMaskImage: 'radial-gradient(ellipse 90% 70% at 55% 30%, #000 0%, transparent 80%)',
          }}
        />
        {/* faint scan lines for depth */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 opacity-[0.5]"
          style={{
            backgroundImage:
              'repeating-linear-gradient(0deg, rgba(124,255,0,0.035) 0px, rgba(124,255,0,0.035) 1px, transparent 1px, transparent 4px)',
            maskImage: 'linear-gradient(180deg, transparent, #000 22%, #000 78%, transparent)',
            WebkitMaskImage: 'linear-gradient(180deg, transparent, #000 22%, #000 78%, transparent)',
          }}
        />
        {/* very subtle ambient green light + corner glows */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              'radial-gradient(40% 45% at 72% 30%, rgba(124,255,0,0.07), transparent 70%), radial-gradient(45% 40% at 18% 18%, rgba(124,255,0,0.04), transparent 70%)',
          }}
        />

        <div className="relative px-6 pt-10 sm:px-10 lg:px-12 lg:pt-12">
          {/* ── TOP: copy + visual stage ── */}
          <TopArea reduce={!!reduce} show={show} />
        </div>

        {/* ── GREEN DATA FLOW between the visual and the process panel ── */}
        <div aria-hidden className="relative -mt-6 h-[230px] w-full sm:h-[300px]">
          <GreenWaveField reduce={!!reduce} />
        </div>

        {/* ── BOTTOM: headline + process row + CTA ── */}
        <div className="relative px-6 pb-10 sm:px-10 lg:px-12 lg:pb-12">
          <BottomPanel reduce={!!reduce} show={show} />
        </div>
      </motion.div>
    </section>
  )
}

// ── Top area (copy + visual stage) ───────────────────────────────────────────

interface Connector {
  id: string
  d: string
  ex: number
  ey: number
}

function TopArea({ reduce, show }: { reduce: boolean; show: { once: true; amount: number } }) {
  const stageRef = useRef<HTMLDivElement | null>(null)
  const previewRef = useRef<HTMLDivElement | null>(null)
  const nodeRefs = useRef<Record<string, HTMLDivElement | null>>({})
  const [hovered, setHovered] = useState<string | null>(null)
  const [geo, setGeo] = useState<{ w: number; h: number; lines: Connector[] }>({ w: 0, h: 0, lines: [] })

  // Clean technical-diagram routing: each node owns ONE destination on the
  // preview's near edge, at the node's own height (clamped to the preview).
  // Route = horizontal run + single bend into the edge. Measured in true pixel
  // space (uniform viewBox) so paths + packets are never distorted. Because the
  // edge points are monotonic with the (evenly spaced) nodes, lines never cross
  // each other, never pass through the website, and never hit another node.
  useEffect(() => {
    const stage = stageRef.current
    if (!stage) return
    const compute = () => {
      const sr = stage.getBoundingClientRect()
      const pv = previewRef.current
      if (sr.width < 10 || !pv) return // hidden (mobile) — skip
      const pr = pv.getBoundingClientRect()
      const pTop = pr.y - sr.y
      const pH = pr.height
      const pad = pH * 0.12
      const lines: Connector[] = []
      for (const c of CALLOUTS) {
        const el = nodeRefs.current[c.id]
        if (!el) continue
        const nr = el.getBoundingClientRect()
        const oy = nr.y + nr.height / 2 - sr.y
        // originate from the callout's inner edge (the side facing the preview)
        const ox = c.side === 'left' ? nr.x + nr.width - sr.x : nr.x - sr.x
        const ex = c.side === 'left' ? pr.x - sr.x : pr.x - sr.x + pr.width
        const ey = Math.min(pTop + pH - pad, Math.max(pTop + pad, oy))
        // horizontal run to a bend just outside the edge, then in. The bend
        // offset adapts to the gutter so the run is always FORWARD (no hook).
        const gutter = Math.abs(ex - ox)
        const k = Math.min(22, Math.max(6, gutter * 0.45))
        const bend = c.side === 'left' ? ex - k : ex + k
        const d = `M ${ox.toFixed(1)} ${oy.toFixed(1)} L ${bend.toFixed(1)} ${oy.toFixed(1)} L ${ex.toFixed(1)} ${ey.toFixed(1)}`
        lines.push({ id: c.id, d, ex, ey })
      }
      setGeo({ w: Math.round(sr.width), h: Math.round(sr.height), lines })
    }
    compute()
    const ro = new ResizeObserver(compute)
    ro.observe(stage)
    if (previewRef.current) ro.observe(previewRef.current)
    window.addEventListener('resize', compute)
    const settle = window.setTimeout(compute, 450) // after image/fonts settle
    return () => {
      ro.disconnect()
      window.removeEventListener('resize', compute)
      window.clearTimeout(settle)
    }
  }, [])

  return (
    <div className="grid grid-cols-1 gap-8 lg:grid-cols-[23%_77%] lg:gap-2">
      {/* LEFT copy */}
      <motion.div
        className="flex flex-col"
        initial={{ opacity: 0, x: -16 }}
        whileInView={{ opacity: 1, x: 0 }}
        viewport={show}
        transition={{ duration: 0.5 }}
      >
        <p className="mb-3 inline-flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.26em]" style={{ color: 'rgba(132,255,58,0.8)' }}>
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: GREEN, boxShadow: '0 0 8px rgba(124,255,0,0.9)' }} />
          What attackers see
        </p>
        <h2 id="attackers-see-heading" className="font-bold leading-[1.04] tracking-[-0.02em] text-white" style={{ fontSize: 'clamp(1.9rem, 2.7vw, 2.7rem)' }}>
          What hackers can see on <span style={{ color: GREEN }}>your website.</span>
        </h2>
        <p className="mt-4 max-w-[330px] text-[13.5px] leading-[1.6]" style={{ color: 'rgba(255,255,255,0.58)' }}>
          {`Attackers don't guess. They explore. WebHound maps your website the same way attackers do — finding every weakness, misconfiguration, and hidden entry point.`}
        </p>

        {/* small info card */}
        <div
          className="mt-7 flex items-start gap-3 rounded-[14px] p-4 lg:mt-auto"
          style={{
            background: 'linear-gradient(180deg, rgba(12,20,32,0.8), rgba(8,14,24,0.7))',
            border: '1px solid rgba(132,255,58,0.18)',
            backdropFilter: 'blur(10px)',
            WebkitBackdropFilter: 'blur(10px)',
            boxShadow: '0 18px 40px rgba(0,0,0,0.35), 0 0 26px rgba(124,255,0,0.05), inset 0 1px 0 rgba(255,255,255,0.05)',
          }}
        >
          <span className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-[9px]" style={{ background: 'rgba(124,255,0,0.08)', border: '1px solid rgba(124,255,0,0.22)' }}>
            <Shield className="h-4 w-4" style={{ color: GREEN }} />
          </span>
          <p className="text-[11.5px] leading-[1.5]" style={{ color: 'rgba(255,255,255,0.55)' }}>
            <span className="font-semibold text-white">WebHound leaves no stone unturned.</span>{' '}
            We map, scan, and analyze every layer of your website.
          </p>
        </div>
      </motion.div>

      {/* RIGHT visual stage (desktop) */}
      <div className="hidden lg:block">
        <div ref={stageRef} className="relative mx-auto h-[540px] w-full">
          {/* central preview — the focal point (~+16% larger). Centering lives
              on the static outer wrapper (also the connector anchor); the float
              lives on the inner motion div so Framer never clobbers centering. */}
          <div ref={previewRef} className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2" style={{ width: 'clamp(540px, 44vw, 700px)' }}>
            <motion.div animate={reduce ? undefined : { y: [0, -10, 0] }} transition={{ duration: 7, repeat: Infinity, ease: 'easeInOut' }}>
              <BrowserPreview reduce={reduce} />
            </motion.div>
          </div>

          {/* connector map — clean orthogonal routing in true pixel space. */}
          <svg aria-hidden className="pointer-events-none absolute inset-0 h-full w-full" viewBox={`0 0 ${geo.w || 1} ${geo.h || 1}`} preserveAspectRatio="none">
            {geo.lines.map((l, i) => {
              const active = hovered === l.id
              return (
                <g key={l.id} style={{ opacity: active ? 1 : 0.6, transition: 'opacity 0.25s' }}>
                  <motion.path
                    d={l.d}
                    fill="none"
                    stroke={GREEN}
                    strokeWidth={active ? 1.8 : 1.1}
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    initial={{ pathLength: reduce ? 1 : 0 }}
                    whileInView={{ pathLength: 1 }}
                    viewport={{ once: true }}
                    transition={{ duration: reduce ? 0 : 0.9, delay: reduce ? 0 : 0.3 + i * 0.09 }}
                  />
                  {/* termination marker on the preview edge */}
                  <circle cx={l.ex} cy={l.ey} r={active ? 3.4 : 2.3} fill={GREEN} style={{ filter: 'drop-shadow(0 0 5px rgba(124,255,0,0.85))' }} />
                  {/* travelling data packet (pulse along the path every 3s) */}
                  {!reduce && (
                    <circle r="2.5" fill="#e9ffc4" style={{ filter: 'drop-shadow(0 0 6px rgba(124,255,0,1))' }}>
                      <animateMotion dur="3s" begin={`${(i * 0.34).toFixed(2)}s`} repeatCount="indefinite" path={l.d} />
                    </circle>
                  )}
                </g>
              )
            })}
          </svg>

          {/* callouts (above the connectors so labels stay readable) */}
          {CALLOUTS.map((c, i) => (
            <motion.div
              key={c.id}
              ref={el => { nodeRefs.current[c.id] = el }}
              className="absolute"
              style={c.side === 'left' ? { left: 0, top: c.top, width: '14%' } : { right: 0, top: c.top, width: '14%' }}
              initial={{ opacity: 0, x: reduce ? 0 : c.side === 'left' ? -12 : 12 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={show}
              transition={{ duration: 0.45, delay: reduce ? 0 : 0.35 + i * 0.09 }}
              onMouseEnter={() => setHovered(c.id)}
              onMouseLeave={() => setHovered(h => (h === c.id ? null : h))}
            >
              <CalloutItem callout={c} reduce={reduce} pulseDelay={i * 0.3} />
            </motion.div>
          ))}
        </div>
      </div>

      {/* RIGHT visual (mobile/tablet stacked) */}
      <div className="lg:hidden">
        <div className="relative mx-auto max-w-[560px]">
          <BrowserPreview reduce={reduce} />
        </div>
        <div className="mt-7 grid grid-cols-1 gap-4 sm:grid-cols-2">
          {CALLOUTS.map((c, i) => (
            <CalloutItem key={c.id} callout={c} stacked reduce={reduce} pulseDelay={i * 0.3} />
          ))}
        </div>
      </div>
    </div>
  )
}

function CalloutItem({
  callout,
  stacked = false,
  reduce = false,
  pulseDelay = 0,
}: {
  callout: Callout
  stacked?: boolean
  reduce?: boolean
  pulseDelay?: number
}) {
  const Icon = callout.icon
  // On the desktop stage, right-side callouts read icon-left/text-right too,
  // matching the reference. Left callouts align their text away from the edge.
  return (
    <div
      className={`flex items-start gap-2.5 ${stacked ? 'rounded-[14px] p-3.5 transition-colors duration-300 hover:border-[rgba(132,255,58,0.35)]' : ''}`}
      style={stacked ? { background: 'rgba(8,14,24,0.72)', border: '1px solid rgba(132,255,58,0.16)', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.04)' } : undefined}
    >
      <span className="relative flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full" style={{ background: 'rgba(124,255,0,0.06)', border: '1px solid rgba(124,255,0,0.3)' }}>
        {!reduce && (
          <motion.span
            aria-hidden
            className="absolute inset-0 rounded-full"
            animate={{ boxShadow: ['0 0 0 0 rgba(124,255,0,0.35)', '0 0 0 6px rgba(124,255,0,0)'] }}
            transition={{ duration: 2.8, repeat: Infinity, ease: 'easeOut', delay: pulseDelay }}
          />
        )}
        <Icon className="h-4 w-4" style={{ color: GREEN }} />
      </span>
      <div>
        <h3 className="text-[13px] font-bold leading-tight text-white">{callout.label}</h3>
        <p className="mt-1 text-[11px] leading-[1.45]" style={{ color: 'rgba(255,255,255,0.5)' }}>
          {callout.description}
        </p>
      </div>
    </div>
  )
}

function BrowserPreview({ reduce = false }: { reduce?: boolean }) {
  return (
    <div className="relative">
      <div aria-hidden className="pointer-events-none absolute -inset-6 rounded-[26px]" style={{ background: 'radial-gradient(closest-side, rgba(124,255,0,0.16), transparent 80%)', filter: 'blur(8px)' }} />
      <div
        className="relative overflow-hidden rounded-[14px]"
        style={{
          border: '1px solid rgba(124,255,0,0.26)',
          boxShadow: '0 34px 90px rgba(0,0,0,0.6), 0 0 46px rgba(124,255,0,0.08), inset 0 1px 0 rgba(255,255,255,0.06)',
        }}
      >
        <div className="flex items-center gap-3 px-4 py-2.5" style={{ background: 'rgba(8,12,22,0.94)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <span className="flex-1 truncate rounded-[6px] px-3 py-1 text-[11px]" style={{ background: 'rgba(2,6,23,0.6)', color: 'rgba(255,255,255,0.45)' }}>
            🔒 northstarcommerce.com
          </span>
          <span className="flex gap-1.5">
            <span className="h-2 w-2 rounded-full" style={{ background: 'rgba(255,255,255,0.18)' }} />
            <span className="h-2 w-2 rounded-full" style={{ background: 'rgba(255,255,255,0.18)' }} />
            <span className="h-2 w-2 rounded-full" style={{ background: 'rgba(124,255,0,0.5)' }} />
          </span>
        </div>
        <div className="relative">
          <Image
            src="/images/northstar-commerce-preview.jpeg"
            alt="A real e-commerce website, mapped by WebHound to reveal its attack surface."
            width={1536}
            height={1024}
            priority
            sizes="(max-width: 1024px) 90vw, 700px"
            className="block h-auto w-full"
          />
          {/* occasional scan sweep */}
          {!reduce && (
            <motion.div
              aria-hidden
              className="pointer-events-none absolute inset-x-0 top-0 h-1/3"
              style={{ background: 'linear-gradient(180deg, transparent 0%, rgba(124,255,0,0.10) 50%, transparent 100%)' }}
              initial={{ y: '-120%' }}
              animate={{ y: ['-120%', '330%'] }}
              transition={{ duration: 2.6, repeat: Infinity, repeatDelay: 4.5, ease: 'easeInOut' }}
            />
          )}
        </div>
      </div>
    </div>
  )
}

// ── Bottom panel (headline + process row + CTA) ──────────────────────────────

function BottomPanel({ reduce, show }: { reduce: boolean; show: { once: true; amount: number } }) {
  return (
    <div className="relative rounded-[20px] p-5 sm:p-7" style={{ background: 'rgba(5,9,17,0.72)', border: '1px solid rgba(255,255,255,0.07)', backdropFilter: 'blur(10px)', WebkitBackdropFilter: 'blur(10px)' }}>
      <div className="flex flex-col gap-7 lg:flex-row lg:gap-8">
        {/* left: headline + process cards */}
        <div className="flex-1">
          <h3 className="mb-6 text-center text-[15px] font-bold text-white">
            Everything is discovered. <span style={{ color: 'rgba(255,255,255,0.55)' }}>Nothing is missed.</span>
          </h3>
          <div className="grid grid-cols-2 gap-x-4 gap-y-6 sm:grid-cols-3 lg:grid-cols-6">
            {PROCESS.map((p, i) => {
              const Icon = p.icon
              return (
                <motion.div
                  key={p.title}
                  className="flex flex-col items-center text-center"
                  initial={{ opacity: 0, y: 14 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={show}
                  transition={{ duration: 0.4, delay: reduce ? 0 : i * 0.08 }}
                >
                  <span className="mb-3 flex h-10 w-10 items-center justify-center rounded-full" style={{ background: 'rgba(124,255,0,0.06)', border: '1px solid rgba(124,255,0,0.28)' }}>
                    <Icon className="h-4 w-4" style={{ color: GREEN }} />
                  </span>
                  <h4 className="text-[12px] font-bold leading-tight text-white">{p.title}</h4>
                  <p className="mt-1.5 text-[10.5px] leading-[1.45]" style={{ color: 'rgba(255,255,255,0.45)' }}>
                    {p.body}
                  </p>
                </motion.div>
              )
            })}
          </div>
        </div>

        {/* right: CTA box */}
        <motion.div
          className="lg:w-[280px] lg:flex-shrink-0"
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={show}
          transition={{ duration: 0.45, delay: reduce ? 0 : 0.3 }}
        >
          <Link href="/scanner" className="group block h-full" tabIndex={-1}>
            <div
              className="flex h-full flex-col justify-center rounded-[16px] p-5 transition-all duration-300 group-hover:-translate-y-0.5 motion-reduce:transition-none motion-reduce:group-hover:translate-y-0"
              style={{
                background: 'linear-gradient(180deg, rgba(12,20,32,0.8), rgba(8,14,24,0.7))',
                border: '1px solid rgba(124,255,0,0.3)',
                backdropFilter: 'blur(10px)',
                WebkitBackdropFilter: 'blur(10px)',
                boxShadow: '0 18px 44px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.05)',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.boxShadow = '0 22px 60px rgba(0,0,0,0.45), 0 0 50px rgba(124,255,0,0.24), inset 0 1px 0 rgba(255,255,255,0.07)'
                e.currentTarget.style.borderColor = 'rgba(124,255,0,0.55)'
              }}
              onMouseLeave={e => {
                e.currentTarget.style.boxShadow = '0 18px 44px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.05)'
                e.currentTarget.style.borderColor = 'rgba(124,255,0,0.3)'
              }}
            >
              <h4 className="text-[16px] font-bold leading-snug text-white">Want to see how we do it?</h4>
              <p className="mt-2 text-[12px] leading-[1.55]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                Learn more about our scanner and how we find what others miss.
              </p>
              <span
                className="mt-4 inline-flex items-center gap-2 self-start rounded-[10px] px-4 py-2 text-[12.5px] font-semibold text-[#020617] transition-transform duration-200 group-hover:translate-x-0.5 motion-reduce:transform-none"
                style={{ background: GREEN, boxShadow: '0 0 20px rgba(124,255,0,0.3)' }}
              >
                Click here to learn more
                <ArrowRight className="h-4 w-4" />
              </span>
            </div>
          </Link>
        </motion.div>
      </div>
    </div>
  )
}

// ── GreenWaveField — animated dot-wave terrain (canvas, no image) ─────────────

// Layered, edge-to-edge perspective particle fields — "streams of data moving
// under the website". Three bands at different depths/speeds give parallax;
// additive blending makes the dense centre glow without a hard blob.
const WAVE_LAYERS = [
  { cols: 250, rows: 18, yTop: 0.24, yBot: 1.05, spread: 1.26, dot: 1.7, bright: 0.6, speed: 1.0, amp: 18, drift: 0.018 },
  { cols: 270, rows: 22, yTop: 0.12, yBot: 1.0, spread: 1.14, dot: 1.45, bright: 0.78, speed: 1.45, amp: 14, drift: 0.03 },
  { cols: 230, rows: 16, yTop: 0.04, yBot: 0.82, spread: 0.94, dot: 1.05, bright: 0.4, speed: 0.7, amp: 10, drift: 0.012 },
]

function GreenWaveField({ reduce }: { reduce: boolean }) {
  const ref = useRef<HTMLCanvasElement | null>(null)

  useEffect(() => {
    const canvas = ref.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let raf = 0
    let w = 0
    let h = 0
    let dpr = 1
    let visible = true

    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2)
      w = canvas.clientWidth
      h = canvas.clientHeight
      canvas.width = Math.max(1, Math.floor(w * dpr))
      canvas.height = Math.max(1, Math.floor(h * dpr))
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }

    const render = (ms: number) => {
      const t = ms * 0.000216 // ~35% faster than before
      ctx.clearRect(0, 0, w, h)
      ctx.globalCompositeOperation = 'lighter' // additive: dense streams glow
      for (const L of WAVE_LAYERS) {
        const flow = t * L.speed
        const driftX = Math.sin(t * 0.25 * L.speed) * w * L.drift
        for (let r = 0; r < L.rows; r++) {
          const rz = r / (L.rows - 1) // 0 far → 1 near
          const persp = Math.pow(rz, 1.4)
          const rowY = h * (L.yTop + persp * (L.yBot - L.yTop))
          const spread = L.spread * (0.5 + rz * 0.7)
          const dotR = L.dot * (0.4 + rz * 1.0)
          const amp = 2 + rz * L.amp
          const rb = L.bright * (0.18 + rz)
          for (let c = 0; c < L.cols; c++) {
            const cx = c / (L.cols - 1) - 0.5 // -0.5..0.5
            const phase = cx * 7
            const wave =
              Math.sin(phase + flow + rz * 2.2) * 0.55 +
              Math.sin(cx * 15 - flow * 0.7 + rz * 4) * 0.27 +
              Math.sin(cx * 3.2 + flow * 0.4) * 0.3
            const x = w / 2 + cx * w * spread + driftX
            const y = rowY + wave * amp
            const crest = 0.6 + 0.4 * Math.sin(phase + flow + rz * 2.2)
            const edgeFade = Math.max(0, 1 - Math.pow(Math.abs(cx) * 2, 1.6))
            let a = rb * edgeFade * crest
            if (a < 0.014) continue
            if (a > 0.85) a = 0.85
            ctx.fillStyle = `rgba(124,255,0,${a})`
            ctx.fillRect(x, y, dotR, dotR)
          }
        }
      }
      ctx.globalCompositeOperation = 'source-over'
      if (!reduce && visible) raf = window.requestAnimationFrame(render)
    }

    resize()
    window.addEventListener('resize', resize)

    // Pause the loop when the band scrolls out of view.
    const io = new IntersectionObserver(
      entries => {
        const wasVisible = visible
        visible = entries[0]?.isIntersecting ?? true
        if (visible && !wasVisible && !reduce) raf = window.requestAnimationFrame(render)
      },
      { rootMargin: '140px' },
    )
    io.observe(canvas)

    if (reduce) render(0)
    else raf = window.requestAnimationFrame(render)

    return () => {
      window.cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
      io.disconnect()
    }
  }, [reduce])

  return (
    <canvas
      ref={ref}
      aria-hidden
      className="absolute inset-0 h-full w-full"
      style={{
        maskImage:
          'radial-gradient(145% 165% at 50% 70%, #000 52%, rgba(0,0,0,0.5) 76%, transparent 96%)',
        WebkitMaskImage:
          'radial-gradient(145% 165% at 50% 70%, #000 52%, rgba(0,0,0,0.5) 76%, transparent 96%)',
      }}
    />
  )
}
