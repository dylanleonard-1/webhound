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
import { useEffect, useRef } from 'react'
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
  status: string
  side: 'left' | 'right'
  top: string // card vertical placement within the stage
  node: { x: number; y: number } // line endpoint at the callout (stage %)
  edge: { x: number; y: number } // line endpoint + glow dot on the preview edge
}

// 3 left · 5 right, exactly like the reference.
const CALLOUTS: Callout[] = [
  { id: 'headers', label: 'Headers', description: 'Security headers can reveal weaknesses.', icon: ShieldCheck, status: 'Checked', side: 'left', top: '13%', node: { x: 18, y: 17 }, edge: { x: 21, y: 19 } },
  { id: 'ssl', label: 'SSL Certificate', description: 'Expired or weak certificates create trust issues.', icon: Lock, status: 'Trust', side: 'left', top: '40%', node: { x: 18, y: 44 }, edge: { x: 21, y: 44 } },
  { id: 'dns', label: 'DNS Records', description: 'Misconfigurations can expose infrastructure.', icon: Globe, status: 'Exposed', side: 'left', top: '67%', node: { x: 18, y: 71 }, edge: { x: 21, y: 69 } },
  { id: 'forms', label: 'Forms', description: 'Forms can be abused to steal data or inject attacks.', icon: FileText, status: 'Input', side: 'right', top: '4%', node: { x: 82, y: 9 }, edge: { x: 79, y: 14 } },
  { id: 'javascript', label: 'JavaScript', description: 'Third-party scripts can introduce vulnerabilities.', icon: Code2, status: 'Script', side: 'right', top: '24%', node: { x: 82, y: 29 }, edge: { x: 79, y: 31 } },
  { id: 'third', label: 'Third Parties', description: 'External services increase your attack surface.', icon: Share2, status: 'Supply', side: 'right', top: '44%', node: { x: 82, y: 49 }, edge: { x: 79, y: 49 } },
  { id: 'admin', label: 'Admin Pages', description: 'Exposed admin pages are a top target for attackers.', icon: ShieldAlert, status: 'Target', side: 'right', top: '64%', node: { x: 82, y: 69 }, edge: { x: 79, y: 67 } },
  { id: 'api', label: 'API Endpoints', description: 'Unprotected APIs can leak sensitive information.', icon: Webhook, status: 'Data', side: 'right', top: '84%', node: { x: 82, y: 89 }, edge: { x: 79, y: 85 } },
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
        <div className="relative px-6 pt-10 sm:px-10 lg:px-12 lg:pt-12">
          {/* ── TOP: copy + visual stage ── */}
          <TopArea reduce={!!reduce} show={show} />
        </div>

        {/* ── GREEN WAVE between the visual and the process panel ── */}
        <div aria-hidden className="pointer-events-none relative z-0 -mt-14 h-[175px] w-full sm:-mt-12 sm:h-[185px] lg:-mt-4 lg:h-[180px]">
          <GreenWaveField reduce={!!reduce} />
        </div>

        {/* ── BOTTOM: headline + process row + CTA ── */}
        <div className="relative z-10 -mt-8 px-6 pb-10 sm:-mt-8 sm:px-10 lg:mt-0 lg:px-12 lg:pb-12">
          <BottomPanel reduce={!!reduce} show={show} />
        </div>
      </motion.div>
    </section>
  )
}

// ── Top area (copy + visual stage) ───────────────────────────────────────────

function TopArea({ reduce, show }: { reduce: boolean; show: { once: true; amount: number } }) {
  return (
    <div className="grid grid-cols-1 gap-8 lg:grid-cols-[24%_76%] lg:gap-2">
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
          style={{ background: 'rgba(8,14,24,0.7)', border: '1px solid rgba(132,255,58,0.16)' }}
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
        <div className="relative mx-auto h-[480px] w-full">
          {/* connector lines */}
          <svg aria-hidden className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
            {CALLOUTS.map((c, i) => (
              <motion.line
                key={c.id}
                x1={c.node.x}
                y1={c.node.y}
                x2={c.edge.x}
                y2={c.edge.y}
                stroke={GREEN}
                strokeWidth={1}
                strokeOpacity={0.45}
                vectorEffect="non-scaling-stroke"
                initial={{ pathLength: reduce ? 1 : 0, opacity: reduce ? 1 : 0 }}
                whileInView={{ pathLength: 1, opacity: 1 }}
                viewport={show}
                transition={{ duration: reduce ? 0 : 0.5, delay: reduce ? 0 : 0.5 + i * 0.1 }}
              />
            ))}
          </svg>
          {/* pulsing edge dots */}
          {CALLOUTS.map((c, i) => (
            <motion.span
              key={`${c.id}-dot`}
              aria-hidden
              className="absolute h-2 w-2 rounded-full"
              style={{ left: `${c.edge.x}%`, top: `${c.edge.y}%`, transform: 'translate(-50%,-50%)', background: GREEN, boxShadow: '0 0 8px rgba(124,255,0,0.9)' }}
              initial={{ opacity: 0, scale: 0 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={show}
              transition={{ duration: 0.3, delay: reduce ? 0 : 0.5 + i * 0.1 }}
            >
              {!reduce && (
                <motion.span className="absolute inset-0 rounded-full" style={{ background: GREEN }} animate={{ opacity: [0.6, 0, 0.6], scale: [1, 2.6, 1] }} transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut', delay: i * 0.18 }} />
              )}
            </motion.span>
          ))}

          {/* central preview — large + dominant. Centering lives on the
              static outer wrapper; the float lives on the inner motion div so
              Framer's transform never clobbers the translate centering. */}
          <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2" style={{ width: 'clamp(460px, 38vw, 600px)' }}>
            <motion.div animate={reduce ? undefined : { y: [0, -10, 0] }} transition={{ duration: 7, repeat: Infinity, ease: 'easeInOut' }}>
              <BrowserPreview />
            </motion.div>
          </div>

          {/* callouts */}
          {CALLOUTS.map((c, i) => (
            <motion.div
              key={c.id}
              className="absolute"
              style={c.side === 'left' ? { left: 0, top: c.top, width: '17%' } : { right: 0, top: c.top, width: '17%' }}
              initial={{ opacity: 0, x: reduce ? 0 : c.side === 'left' ? -12 : 12 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={show}
              transition={{ duration: 0.45, delay: reduce ? 0 : 0.35 + i * 0.09 }}
            >
              <CalloutItem callout={c} />
            </motion.div>
          ))}
        </div>
      </div>

      {/* RIGHT visual (mobile/tablet wheel) */}
      <div className="lg:hidden">
        <div className="relative mx-auto max-w-[560px]">
          <BrowserPreview />
        </div>
        <MobileScanWheel reduce={reduce} />
      </div>
    </div>
  )
}

function MobileScanWheel({ reduce }: { reduce: boolean }) {
  return (
    <div className="relative z-20 mx-auto mt-7 max-w-[560px] rounded-[24px] p-3" style={{ background: 'rgba(2,6,14,0.92)', border: '1px solid rgba(124,255,0,0.16)' }}>
      <div className="px-3 pb-3 pt-2">
        <p className="text-[10px] font-bold uppercase tracking-[0.24em]" style={{ color: 'rgba(124,255,0,0.78)' }}>Scan wheel</p>
        <p className="mt-1 text-[11px]" style={{ color: 'rgba(255,255,255,0.45)' }}>Swipe the findings or keep scrolling past.</p>
      </div>

      <div
        className="relative h-[350px] overflow-y-auto overflow-x-hidden rounded-[18px] px-2 py-4 [perspective:900px]"
        style={{
          background: 'rgba(2,6,14,0.72)',
          WebkitOverflowScrolling: 'touch',
          scrollbarWidth: 'thin',
        }}
      >
        <div className="relative flex flex-col gap-3 pb-4 pt-1">
          <div aria-hidden className="pointer-events-none absolute bottom-8 left-[34px] top-5 w-px bg-gradient-to-b from-transparent via-[rgba(124,255,0,0.34)] to-transparent" />
          {CALLOUTS.map((c, i) => (
            <motion.div
              key={c.id}
              className="relative z-10"
              initial={{ opacity: 0, y: reduce ? 0 : 16, rotateX: reduce ? 0 : -10 }}
              whileInView={{ opacity: 1, y: 0, rotateX: 0 }}
              viewport={{ once: true, amount: 0.45 }}
              transition={{ duration: 0.36, delay: reduce ? 0 : i * 0.035 }}
              style={{ transformOrigin: 'center center' }}
            >
              <CalloutItem callout={c} stacked index={i + 1} />
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  )
}

function CalloutItem({ callout, stacked = false, index }: { callout: Callout; stacked?: boolean; index?: number }) {
  const Icon = callout.icon
  // On the desktop stage, right-side callouts read icon-left/text-right too,
  // matching the reference. Left callouts align their text away from the edge.
  return (
    <div
      className={`relative flex items-start gap-2.5 overflow-hidden ${stacked ? 'rounded-[16px] p-3.5 pr-4' : ''}`}
      style={
        stacked
          ? {
              background: 'linear-gradient(135deg, rgba(5,10,20,0.82), rgba(5,10,20,0.58))',
              border: '1px solid rgba(124,255,0,0.25)',
              backdropFilter: 'blur(16px)',
              WebkitBackdropFilter: 'blur(16px)',
              boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.06), 0 16px 40px rgba(0,0,0,0.3), 0 0 26px rgba(124,255,0,0.05)',
            }
          : undefined
      }
    >
      {stacked && (
        <span
          aria-hidden
          className="pointer-events-none absolute inset-x-0 top-0 h-px"
          style={{ background: 'linear-gradient(90deg, transparent, rgba(124,255,0,0.55), transparent)' }}
        />
      )}
      <span className="relative flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-full" style={{ background: 'rgba(124,255,0,0.075)', border: '1px solid rgba(124,255,0,0.34)', boxShadow: stacked ? '0 0 18px rgba(124,255,0,0.13)' : undefined }}>
        {typeof index === 'number' ? <span className="text-[10px] font-bold" style={{ color: GREEN }}>{String(index).padStart(2, '0')}</span> : <Icon className="h-4 w-4" style={{ color: GREEN }} />}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-start justify-between gap-2">
          <h3 className="text-[13px] font-bold leading-tight text-white">{callout.label}</h3>
          {stacked && (
            <span className="shrink-0 rounded-full px-2 py-0.5 text-[8.5px] font-bold uppercase tracking-[0.12em]" style={{ color: 'rgba(124,255,0,0.9)', background: 'rgba(124,255,0,0.07)', border: '1px solid rgba(124,255,0,0.2)' }}>
              {callout.status}
            </span>
          )}
        </div>
        <p className="mt-1 text-[11px] leading-[1.45]" style={{ color: 'rgba(255,255,255,0.52)' }}>
          {callout.description}
        </p>
        {typeof index === 'number' && (
          <div className="mt-2 flex items-center gap-2">
            <Icon className="h-3.5 w-3.5" style={{ color: GREEN }} />
            <span className="text-[9px] font-semibold uppercase tracking-[0.16em]" style={{ color: 'rgba(255,255,255,0.34)' }}>Mapped surface</span>
          </div>
        )}
      </div>
    </div>
  )
}

function BrowserPreview() {
  return (
    <div className="relative">
      <div aria-hidden className="pointer-events-none absolute -inset-5 rounded-[24px]" style={{ background: 'radial-gradient(closest-side, rgba(124,255,0,0.14), transparent 80%)', filter: 'blur(6px)' }} />
      <div className="relative overflow-hidden rounded-[14px]" style={{ border: '1px solid rgba(124,255,0,0.24)', boxShadow: '0 26px 70px rgba(0,0,0,0.55), 0 0 36px rgba(124,255,0,0.07)' }}>
        <div className="flex items-center gap-3 px-4 py-2.5" style={{ background: 'rgba(8,12,22,0.92)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <span className="flex-1 truncate rounded-[6px] px-3 py-1 text-[11px]" style={{ background: 'rgba(2,6,23,0.6)', color: 'rgba(255,255,255,0.45)' }}>
            🔒 northstarcommerce.com
          </span>
          <span className="flex gap-1.5">
            <span className="h-2 w-2 rounded-full" style={{ background: 'rgba(255,255,255,0.18)' }} />
            <span className="h-2 w-2 rounded-full" style={{ background: 'rgba(255,255,255,0.18)' }} />
            <span className="h-2 w-2 rounded-full" style={{ background: 'rgba(124,255,0,0.5)' }} />
          </span>
        </div>
        <Image
          src="/images/northstar-commerce-preview.jpeg"
          alt="A real e-commerce website, mapped by WebHound to reveal its attack surface."
          width={1536}
          height={1024}
          priority
          sizes="(max-width: 1024px) 90vw, 600px"
          className="block h-auto w-full"
        />
      </div>
    </div>
  )
}

// ── Bottom panel (headline + process row + CTA) ──────────────────────────────

function BottomPanel({ reduce, show }: { reduce: boolean; show: { once: true; amount: number } }) {
  return (
    <div
      className="relative rounded-[20px] p-5 sm:p-7"
      style={{
        background: 'rgba(5,9,17,0.66)',
        border: '1px solid rgba(124,255,0,0.18)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05), 0 20px 70px rgba(0,0,0,0.38), 0 0 42px rgba(124,255,0,0.08)',
      }}
    >
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
              className="flex h-full flex-col justify-center rounded-[16px] p-5 transition-all duration-300 motion-reduce:transition-none"
              style={{ background: 'rgba(8,14,24,0.7)', border: '1px solid rgba(124,255,0,0.28)' }}
              onMouseEnter={e => {
                e.currentTarget.style.boxShadow = '0 0 44px rgba(124,255,0,0.22)'
                e.currentTarget.style.borderColor = 'rgba(124,255,0,0.5)'
              }}
              onMouseLeave={e => {
                e.currentTarget.style.boxShadow = 'none'
                e.currentTarget.style.borderColor = 'rgba(124,255,0,0.28)'
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
    const COLS = 76
    const ROWS = 18

    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2)
      w = canvas.clientWidth
      h = canvas.clientHeight
      canvas.width = Math.max(1, Math.floor(w * dpr))
      canvas.height = Math.max(1, Math.floor(h * dpr))
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }

    const render = (ms: number) => {
      const t = ms * 0.00035
      ctx.clearRect(0, 0, w, h)
      for (let r = 0; r < ROWS; r++) {
        const rz = r / (ROWS - 1) // 0 = far/top, 1 = near/bottom
        const rowY = h * (0.12 + Math.pow(rz, 1.5) * 0.86)
        const spread = 0.62 + rz * 0.5
        const dotR = 0.35 + rz * 1.5
        for (let c = 0; c < COLS; c++) {
          const cx = c / (COLS - 1) // 0..1
          const x = w / 2 + (cx - 0.5) * w * spread
          const wave =
            Math.sin(cx * 7 + t + r * 0.35) * 0.6 +
            Math.sin(cx * 13 - t * 0.7 + r * 0.2) * 0.4
          const y = rowY + wave * (4 + rz * 18)
          const edgeFade = Math.max(0, 1 - Math.pow(Math.abs(cx - 0.5) * 2, 2.2))
          const alpha = edgeFade * (0.06 + rz * 0.5)
          if (alpha <= 0.01) continue
          ctx.beginPath()
          ctx.fillStyle = `rgba(124,255,0,${alpha})`
          ctx.arc(x, y, dotR, 0, Math.PI * 2)
          ctx.fill()
        }
      }
      if (!reduce) raf = window.requestAnimationFrame(render)
    }

    resize()
    window.addEventListener('resize', resize)
    if (reduce) render(0)
    else raf = window.requestAnimationFrame(render)

    return () => {
      window.cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
    }
  }, [reduce])

  return (
    <canvas
      ref={ref}
      aria-hidden
      className="absolute inset-0 h-full w-full"
      style={{ maskImage: 'linear-gradient(90deg, transparent, #000 12%, #000 88%, transparent)', WebkitMaskImage: 'linear-gradient(90deg, transparent, #000 12%, #000 88%, transparent)' }}
    />
  )
}
