'use client'

// WebHound — components/sections/WhatAttackersSeeSection.tsx
// "What Attackers See" — left copy column + small info card, a large
// browser-framed website preview in the centre with floating security
// discovery nodes around it. There are NO permanent connectors: a short green
// pulse periodically travels from the website to a node ("just discovered that
// asset"). Beneath sits a flowing particle/network-telemetry field, then a
// bottom panel with the "Everything is discovered" headline, a six-step process
// row, and a CTA box. Dark navy (#020617), neon green (#7CFF00 / #84FF3A).
// Presentational only; respects prefers-reduced-motion.

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

// Discovery geometry: per node, a SOURCE point on the website edge and the
// node anchor. No permanent line is drawn — a transient pulse travels src→node
// to signal "WebHound discovered that asset". Measured in stage pixel space.
interface NodeGeo {
  id: string
  sx: number // source on the preview edge
  sy: number
  nx: number // node inner edge (the side facing the website)
  ny: number
}

function TopArea({ reduce, show }: { reduce: boolean; show: { once: true; amount: number } }) {
  const stageRef = useRef<HTMLDivElement | null>(null)
  const previewRef = useRef<HTMLDivElement | null>(null)
  const nodeRefs = useRef<Record<string, HTMLDivElement | null>>({})
  const [geo, setGeo] = useState<{ w: number; h: number; nodes: NodeGeo[] }>({ w: 0, h: 0, nodes: [] })

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
      const nodes: NodeGeo[] = []
      for (const c of CALLOUTS) {
        const el = nodeRefs.current[c.id]
        if (!el) continue
        const nr = el.getBoundingClientRect()
        const ny = nr.y + nr.height / 2 - sr.y
        const nx = c.side === 'left' ? nr.x + nr.width - sr.x : nr.x - sr.x
        const sx = c.side === 'left' ? pr.x - sr.x : pr.x - sr.x + pr.width
        const sy = Math.min(pTop + pH - pad, Math.max(pTop + pad, ny))
        nodes.push({ id: c.id, sx, sy, nx, ny })
      }
      setGeo({ w: Math.round(sr.width), h: Math.round(sr.height), nodes })
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

          {/* discovery pulses — NO permanent lines. A short green pulse travels
              from the website to each node every few seconds (~0.5s) then
              vanishes: "WebHound just discovered that asset". */}
          {!reduce &&
            geo.nodes.map((n, i) => (
              <motion.span
                key={`${n.id}-pulse`}
                aria-hidden
                className="pointer-events-none absolute left-0 top-0 h-[7px] w-[7px] rounded-full"
                style={{ background: '#eaffc4', boxShadow: '0 0 10px 2px rgba(124,255,0,0.9)' }}
                initial={{ x: n.sx, y: n.sy, opacity: 0, scale: 0.5 }}
                animate={{
                  x: [n.sx, n.sx, n.nx, n.nx, n.nx],
                  y: [n.sy, n.sy, n.ny, n.ny, n.ny],
                  opacity: [0, 1, 1, 0, 0],
                  scale: [0.5, 1, 1, 0.4, 0.4],
                }}
                transition={{
                  duration: 4.6,
                  times: [0, 0.02, 0.12, 0.17, 1],
                  ease: 'easeOut',
                  repeat: Infinity,
                  delay: 0.6 + i * 0.5,
                }}
              />
            ))}

          {/* floating discovery nodes (icon + label + subtle glow). The outer
              wrapper is the measured rest anchor; the float lives on the inner
              div so the pulse target stays stable. */}
          {CALLOUTS.map((c, i) => (
            <motion.div
              key={c.id}
              ref={el => { nodeRefs.current[c.id] = el }}
              className="absolute"
              style={c.side === 'left' ? { left: 0, top: c.top, width: '14%' } : { right: 0, top: c.top, width: '14%' }}
              initial={{ opacity: 0, scale: reduce ? 1 : 0.8 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={show}
              transition={{ duration: 0.45, delay: reduce ? 0 : 0.3 + i * 0.09 }}
            >
              <motion.div
                animate={reduce ? undefined : { y: [0, -6, 0, 5, 0], x: [0, 3, 0, -3, 0] }}
                transition={{ duration: 7 + (i % 4) * 1.3, repeat: Infinity, ease: 'easeInOut', delay: i * 0.4 }}
              >
                <CalloutItem callout={c} reduce={reduce} pulseDelay={i * 0.3} glow />
              </motion.div>
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
  glow = false,
}: {
  callout: Callout
  stacked?: boolean
  reduce?: boolean
  pulseDelay?: number
  glow?: boolean
}) {
  const Icon = callout.icon
  // On the desktop stage, right-side callouts read icon-left/text-right too,
  // matching the reference. Left callouts align their text away from the edge.
  return (
    <div
      className={`group flex items-start gap-2.5 ${stacked ? 'rounded-[14px] p-3.5 transition-colors duration-300 hover:border-[rgba(132,255,58,0.35)]' : ''}`}
      style={stacked ? { background: 'rgba(8,14,24,0.72)', border: '1px solid rgba(132,255,58,0.16)', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.04)' } : undefined}
    >
      <span
        className="relative flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full transition-shadow duration-300 group-hover:shadow-[0_0_18px_rgba(124,255,0,0.55)]"
        style={{
          background: 'rgba(124,255,0,0.07)',
          border: '1px solid rgba(124,255,0,0.32)',
          boxShadow: glow ? '0 0 16px rgba(124,255,0,0.22)' : undefined,
        }}
      >
        {/* subtle radial glow behind the node */}
        {glow && (
          <span aria-hidden className="pointer-events-none absolute -inset-2 rounded-full" style={{ background: 'radial-gradient(closest-side, rgba(124,255,0,0.22), transparent 75%)' }} />
        )}
        {!reduce && (
          <motion.span
            aria-hidden
            className="absolute inset-0 rounded-full"
            animate={{ boxShadow: ['0 0 0 0 rgba(124,255,0,0.4)', '0 0 0 7px rgba(124,255,0,0)'] }}
            transition={{ duration: 2.8, repeat: Infinity, ease: 'easeOut', delay: pulseDelay }}
          />
        )}
        <Icon className="relative h-4 w-4" style={{ color: GREEN }} />
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

// ── GreenWaveField — flowing particle / network-telemetry field (canvas) ──────

// Three parallax layers of particles streaming horizontally beneath the site —
// "flowing network traffic", not a sine wave. L1 small dots, L2 larger dots,
// L3 glowing particles; each layer moves at a different speed for depth.
interface ParticleLayer {
  count: number
  sizeMin: number
  sizeMax: number
  speedMin: number // px/s — flow speed
  speedMax: number
  alphaMin: number
  alphaMax: number
  glow: boolean
}

const PARTICLE_LAYERS: ParticleLayer[] = [
  // L1 — small dots, far/slow (dense background telemetry)
  { count: 460, sizeMin: 0.5, sizeMax: 1.2, speedMin: 32, speedMax: 70, alphaMin: 0.22, alphaMax: 0.5, glow: false },
  // L2 — larger dots, mid
  { count: 180, sizeMin: 1.3, sizeMax: 2.4, speedMin: 55, speedMax: 120, alphaMin: 0.35, alphaMax: 0.7, glow: false },
  // L3 — glowing particles, near/fast (the bright streaks)
  { count: 50, sizeMin: 2.2, sizeMax: 3.8, speedMin: 95, speedMax: 200, alphaMin: 0.55, alphaMax: 0.95, glow: true },
]

interface Particle {
  x: number
  y: number
  vx: number
  vy: number
  s: number
  a: number
  glow: boolean
}

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
    let last = 0
    let dots: Particle[] = []
    let glows: Particle[] = []

    const build = () => {
      dots = []
      glows = []
      for (const L of PARTICLE_LAYERS) {
        for (let i = 0; i < L.count; i++) {
          const p: Particle = {
            x: Math.random() * w,
            y: Math.random() * h,
            vx: L.speedMin + Math.random() * (L.speedMax - L.speedMin),
            vy: (Math.random() - 0.5) * 6,
            s: L.sizeMin + Math.random() * (L.sizeMax - L.sizeMin),
            a: L.alphaMin + Math.random() * (L.alphaMax - L.alphaMin),
            glow: L.glow,
          }
          ;(L.glow ? glows : dots).push(p)
        }
      }
    }

    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2)
      w = canvas.clientWidth
      h = canvas.clientHeight
      canvas.width = Math.max(1, Math.floor(w * dpr))
      canvas.height = Math.max(1, Math.floor(h * dpr))
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      build()
    }

    const fade = 90 // px horizontal in/out fade (streams flow in & out)
    const step = (p: Particle, dt: number) => {
      p.x += p.vx * dt
      p.y += p.vy * dt
      if (p.x > w + 6) {
        p.x = -6
        p.y = Math.random() * h
      }
      if (p.y < -6) p.y = h + 6
      else if (p.y > h + 6) p.y = -6
    }
    const edgeAlpha = (x: number) => Math.max(0, Math.min(1, x / fade) * Math.min(1, (w - x) / fade))

    const render = (ms: number) => {
      const dt = last ? Math.min(0.05, (ms - last) / 1000) : 0
      last = ms
      ctx.clearRect(0, 0, w, h)

      // dots (source-over)
      ctx.globalCompositeOperation = 'source-over'
      for (const p of dots) {
        step(p, dt)
        const a = p.a * edgeAlpha(p.x)
        if (a < 0.02) continue
        ctx.fillStyle = `rgba(124,255,0,${a})`
        ctx.fillRect(p.x, p.y, p.s, p.s)
      }

      // glowing particles (additive + soft glow)
      ctx.globalCompositeOperation = 'lighter'
      ctx.shadowColor = 'rgba(124,255,0,0.95)'
      for (const p of glows) {
        step(p, dt)
        const a = p.a * edgeAlpha(p.x)
        if (a < 0.02) continue
        ctx.shadowBlur = p.s * 3.5
        ctx.fillStyle = `rgba(180,255,110,${a})`
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.s, 0, Math.PI * 2)
        ctx.fill()
      }
      ctx.shadowBlur = 0
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
        if (visible && !wasVisible && !reduce) {
          last = 0
          raf = window.requestAnimationFrame(render)
        }
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
        maskImage: 'linear-gradient(180deg, transparent 0%, #000 16%, #000 84%, transparent 100%)',
        WebkitMaskImage: 'linear-gradient(180deg, transparent 0%, #000 16%, #000 84%, transparent 100%)',
      }}
    />
  )
}
