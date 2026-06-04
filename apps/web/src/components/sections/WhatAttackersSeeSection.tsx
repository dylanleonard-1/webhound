'use client'

// WebHound — components/sections/WhatAttackersSeeSection.tsx
// Homepage section "What Attackers See". Premium animated map of a real
// website (NorthStar Commerce preview) with callouts wired to the image via
// SVG connector lines on desktop, a stacked layout on mobile, a glass
// process row, and a CTA into the scanner. Matches the hero aesthetic:
// dark navy (#020617), neon green (#7CFF00 / #8BFF3E), subtle grid + glow.
//
// Self-contained: helper cards live in this file. No backend/scanner code is
// touched; this is presentational only. Respects prefers-reduced-motion.

import Image from 'next/image'
import Link from 'next/link'
import { motion, useReducedMotion } from 'framer-motion'
import {
  ArrowRight,
  Boxes,
  Bug,
  FileCode,
  FileText,
  FormInput,
  Gauge,
  Globe,
  ListOrdered,
  Lock,
  Search,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Webhook,
} from 'lucide-react'

type Icon = React.FC<{ className?: string; style?: React.CSSProperties }>

interface Callout {
  id: string
  title: string
  body: string
  icon: Icon
  side: 'left' | 'right'
  // Coordinates in the 0–100 viewBox space used for the SVG connectors.
  node: { x: number; y: number } // dot at the callout's inner edge
  target: { x: number; y: number } // point on the image perimeter
  // Vertical placement (%) of the absolutely-positioned desktop card.
  top: number
}

// Eight surfaces, four per side, wired left/right to the central preview.
const CALLOUTS: Callout[] = [
  { id: 'headers', title: 'Headers', body: 'Security headers can reveal weaknesses.', icon: ShieldCheck, side: 'left', node: { x: 23, y: 18 }, target: { x: 33, y: 26 }, top: 9 },
  { id: 'tls', title: 'TLS Certificate', body: 'Expired or weak certificates create trust issues.', icon: Lock, side: 'left', node: { x: 23, y: 40 }, target: { x: 33, y: 43 }, top: 31 },
  { id: 'dns', title: 'DNS Records', body: 'Misconfigurations can expose infrastructure.', icon: Globe, side: 'left', node: { x: 23, y: 60 }, target: { x: 33, y: 57 }, top: 52 },
  { id: 'forms', title: 'Forms', body: 'Forms can be abused to steal data or inject attacks.', icon: FormInput, side: 'left', node: { x: 23, y: 82 }, target: { x: 33, y: 74 }, top: 74 },
  { id: 'js', title: 'JavaScript', body: 'Third-party scripts can introduce vulnerabilities.', icon: FileCode, side: 'right', node: { x: 77, y: 18 }, target: { x: 67, y: 26 }, top: 9 },
  { id: 'third', title: 'Third Parties', body: 'External services increase attack surface.', icon: Boxes, side: 'right', node: { x: 77, y: 40 }, target: { x: 67, y: 43 }, top: 31 },
  { id: 'admin', title: 'Admin Pages', body: 'Exposed admin pages are a top target.', icon: ShieldAlert, side: 'right', node: { x: 77, y: 60 }, target: { x: 67, y: 57 }, top: 52 },
  { id: 'api', title: 'API Endpoints', body: 'Unprotected APIs can leak sensitive information.', icon: Webhook, side: 'right', node: { x: 77, y: 82 }, target: { x: 67, y: 74 }, top: 74 },
]

const PROCESS: { title: string; icon: Icon }[] = [
  { title: 'Crawl & Discover', icon: Search },
  { title: 'Map Relationships', icon: Share2 },
  { title: 'Analyze Risks', icon: Gauge },
  { title: 'Find Weaknesses', icon: Bug },
  { title: 'Prioritize Threats', icon: ListOrdered },
  { title: 'Generate Report', icon: FileText },
]

const GREEN = '#7CFF00'

export function WhatAttackersSeeSection() {
  const reduce = useReducedMotion()

  // Slow float for the central preview (disabled under reduced motion).
  const floatAnim = reduce
    ? undefined
    : { y: [0, -14, 0] }
  const floatTransition = { duration: 7, repeat: Infinity, ease: 'easeInOut' as const }

  return (
    <section
      className="relative overflow-hidden py-20 lg:py-28"
      style={{ background: '#020617' }}
      aria-labelledby="attackers-see-heading"
    >
      {/* Subtle grid */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(139,255,62,1) 1px, transparent 1px), linear-gradient(90deg, rgba(139,255,62,1) 1px, transparent 1px)',
          backgroundSize: '64px 64px',
          maskImage: 'radial-gradient(ellipse 80% 60% at 50% 40%, #000 0%, transparent 75%)',
          WebkitMaskImage: 'radial-gradient(ellipse 80% 60% at 50% 40%, #000 0%, transparent 75%)',
        }}
      />
      {/* Ambient cinematic glow */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            'radial-gradient(60% 50% at 50% 38%, rgba(124,255,0,0.08) 0%, transparent 70%)',
        }}
      />

      <div className="relative z-10 mx-auto w-full max-w-[1280px] px-5 sm:px-8 lg:px-12 xl:px-16">
        {/* ── 1. Left text block ── */}
        <motion.div
          className="max-w-[560px]"
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
        >
          <p
            className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3"
            style={{ color: 'rgba(139,255,62,0.7)' }}
          >
            What attackers see
          </p>
          <h2
            id="attackers-see-heading"
            className="font-bold leading-[1.05] tracking-[-0.02em] text-white mb-5"
            style={{ fontSize: 'clamp(1.9rem, 3.6vw, 3rem)' }}
          >
            What hackers can see on your website.
          </h2>
          <p
            className="text-[14.5px] leading-[1.65] max-w-[500px]"
            style={{ color: 'rgba(255,255,255,0.62)' }}
          >
            Every website leaves clues. WebHound maps your site the same way
            attackers do — finding exposed paths, risky scripts, weak headers,
            and hidden entry points.
          </p>
        </motion.div>

        {/* ── 2 + 3. Center visual with desktop spider-web callouts ── */}
        <div className="relative mt-12 hidden lg:block">
          <div className="relative mx-auto h-[640px] max-w-[1120px]">
            {/* SVG connectors (draw in on view). Hidden from a11y tree. */}
            <svg
              aria-hidden
              className="absolute inset-0 h-full w-full"
              viewBox="0 0 100 100"
              preserveAspectRatio="none"
            >
              {CALLOUTS.map((c, i) => (
                <g key={c.id}>
                  <motion.line
                    x1={c.node.x}
                    y1={c.node.y}
                    x2={c.target.x}
                    y2={c.target.y}
                    stroke={GREEN}
                    strokeWidth={1}
                    strokeOpacity={0.32}
                    vectorEffect="non-scaling-stroke"
                    initial={{ pathLength: reduce ? 1 : 0, opacity: reduce ? 1 : 0 }}
                    whileInView={{ pathLength: 1, opacity: 1 }}
                    viewport={{ once: true, amount: 0.3 }}
                    transition={{ duration: reduce ? 0 : 0.8, delay: reduce ? 0 : 0.2 + i * 0.08 }}
                  />
                  {/* node dot */}
                  <circle cx={c.node.x} cy={c.node.y} r={0.55} fill={GREEN} vectorEffect="non-scaling-stroke" />
                </g>
              ))}
            </svg>

            {/* Soft green dot field underneath the preview */}
            <div
              aria-hidden
              className="pointer-events-none absolute left-1/2 top-[58%] h-[260px] w-[640px] -translate-x-1/2"
              style={{
                backgroundImage: `radial-gradient(rgba(124,255,0,0.5) 1px, transparent 1.4px)`,
                backgroundSize: '22px 22px',
                maskImage: 'radial-gradient(ellipse 60% 70% at 50% 30%, #000 0%, transparent 72%)',
                WebkitMaskImage: 'radial-gradient(ellipse 60% 70% at 50% 30%, #000 0%, transparent 72%)',
                opacity: 0.5,
              }}
            />

            {/* Floating preview card */}
            <motion.div
              className="absolute left-1/2 top-1/2 w-[clamp(440px,42vw,560px)] -translate-x-1/2 -translate-y-1/2"
              animate={floatAnim}
              transition={floatTransition}
            >
              <PreviewCard priority />
            </motion.div>

            {/* Callout cards */}
            {CALLOUTS.map((c, i) => (
              <motion.div
                key={c.id}
                className="absolute w-[19%]"
                style={c.side === 'left' ? { left: 0, top: `${c.top}%` } : { right: 0, top: `${c.top}%` }}
                initial={{ opacity: 0, x: reduce ? 0 : c.side === 'left' ? -16 : 16 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true, amount: 0.3 }}
                transition={{ duration: 0.5, delay: 0.3 + i * 0.06 }}
              >
                <CalloutCard callout={c} align={c.side === 'left' ? 'right' : 'left'} reduce={!!reduce} />
              </motion.div>
            ))}
          </div>
        </div>

        {/* ── Mobile / tablet: stacked (image → callout cards) ── */}
        <div className="mt-10 lg:hidden">
          <motion.div
            className="relative mx-auto max-w-[560px]"
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.25 }}
            transition={{ duration: 0.5 }}
            animate={floatAnim}
          >
            <PreviewCard />
          </motion.div>

          <div className="mt-8 grid grid-cols-1 gap-3">
            {CALLOUTS.map((c, i) => (
              <motion.div
                key={c.id}
                initial={{ opacity: 0, y: 12 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.2 }}
                transition={{ duration: 0.4, delay: i * 0.04 }}
              >
                <CalloutCard callout={c} align="left" reduce={!!reduce} />
              </motion.div>
            ))}
          </div>
        </div>

        {/* ── 4. Process row (glass panel) ── */}
        <div className="mt-16 lg:mt-24">
          <motion.div
            className="rounded-[18px] p-5 sm:p-7"
            style={{
              background: 'rgba(8,12,22,0.6)',
              border: '1px solid rgba(255,255,255,0.07)',
              backdropFilter: 'blur(12px)',
              WebkitBackdropFilter: 'blur(12px)',
              boxShadow: '0 0 60px rgba(124,255,0,0.05)',
            }}
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.2 }}
            transition={{ duration: 0.5 }}
          >
            <p
              className="text-[10px] font-bold tracking-[0.24em] uppercase mb-5"
              style={{ color: 'rgba(139,255,62,0.6)' }}
            >
              How WebHound maps your site
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {PROCESS.map((p, i) => {
                const Icon = p.icon
                return (
                  <motion.div
                    key={p.title}
                    className="flex flex-col items-start gap-2.5 rounded-[12px] p-4"
                    style={{
                      background: 'rgba(8,12,22,0.85)',
                      border: '1px solid rgba(255,255,255,0.05)',
                    }}
                    initial={{ opacity: 0, y: 12 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true, amount: 0.3 }}
                    transition={{ duration: 0.4, delay: i * 0.07 }}
                  >
                    <div
                      className="flex h-8 w-8 items-center justify-center rounded-[8px]"
                      style={{ background: 'rgba(124,255,0,0.06)', border: '1px solid rgba(124,255,0,0.18)' }}
                    >
                      <Icon className="h-3.5 w-3.5" style={{ color: GREEN }} />
                    </div>
                    <span className="text-[12.5px] font-semibold leading-[1.3] text-white">
                      {p.title}
                    </span>
                    <span className="text-[10px] font-bold tabular-nums" style={{ color: 'rgba(124,255,0,0.45)' }}>
                      {String(i + 1).padStart(2, '0')}
                    </span>
                  </motion.div>
                )
              })}
            </div>
          </motion.div>
        </div>

        {/* ── 5. CTA box ── */}
        <motion.div
          className="mt-10 flex justify-center lg:justify-end"
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
        >
          <Link href="/scanner" className="group block w-full max-w-[440px]" tabIndex={-1}>
            <div
              className="rounded-[16px] p-6 transition-all duration-300 motion-reduce:transition-none group-hover:-translate-y-0.5"
              style={{
                background: 'rgba(8,12,22,0.7)',
                border: '1px solid rgba(124,255,0,0.18)',
                backdropFilter: 'blur(12px)',
                WebkitBackdropFilter: 'blur(12px)',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.boxShadow = '0 0 50px rgba(124,255,0,0.22)'
                e.currentTarget.style.borderColor = 'rgba(124,255,0,0.4)'
              }}
              onMouseLeave={e => {
                e.currentTarget.style.boxShadow = 'none'
                e.currentTarget.style.borderColor = 'rgba(124,255,0,0.18)'
              }}
            >
              <h3 className="text-[16px] font-bold text-white mb-2">
                Want to see how WebHound scans?
              </h3>
              <p className="text-[13px] leading-[1.6] mb-5" style={{ color: 'rgba(255,255,255,0.6)' }}>
                Learn how the scanner maps your site, finds risks, and explains
                what to fix first.
              </p>
              <span
                className="inline-flex items-center gap-2 rounded-[10px] px-5 py-2.5 text-[13.5px] font-semibold text-[#020617] transition-all duration-200 motion-reduce:transition-none"
                style={{ background: GREEN, boxShadow: '0 0 22px rgba(124,255,0,0.28)' }}
              >
                Explore the scanner
                <ArrowRight className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-0.5 motion-reduce:transform-none" />
              </span>
            </div>
          </Link>
        </motion.div>
      </div>
    </section>
  )
}

// ── Helpers ────────────────────────────────────────────────────────────────

function PreviewCard({ priority = false }: { priority?: boolean }) {
  return (
    <div className="relative">
      {/* green glow behind */}
      <div
        aria-hidden
        className="pointer-events-none absolute -inset-6 rounded-[28px]"
        style={{ background: 'radial-gradient(closest-side, rgba(124,255,0,0.22), transparent 78%)', filter: 'blur(8px)' }}
      />
      <div
        className="relative overflow-hidden rounded-[14px]"
        style={{
          border: '1px solid rgba(124,255,0,0.22)',
          boxShadow: '0 24px 70px rgba(0,0,0,0.55), 0 0 40px rgba(124,255,0,0.08)',
        }}
      >
        <Image
          src="/images/northstar-commerce-preview.jpeg"
          alt="A real e-commerce website mapped by WebHound, with its attack surface highlighted."
          width={1536}
          height={1024}
          priority={priority}
          sizes="(max-width: 1024px) 90vw, 560px"
          className="block h-auto w-full"
        />
        {/* thin scan sheen */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0"
          style={{ background: 'linear-gradient(180deg, transparent 70%, rgba(2,6,23,0.35) 100%)' }}
        />
      </div>
    </div>
  )
}

function CalloutCard({
  callout,
  align,
  reduce,
}: {
  callout: Callout
  align: 'left' | 'right'
  reduce: boolean
}) {
  const Icon = callout.icon
  return (
    <div
      className={`rounded-[11px] p-3.5 ${align === 'right' ? 'text-right' : 'text-left'}`}
      style={{ background: 'rgba(8,12,22,0.88)', border: '1px solid rgba(255,255,255,0.06)' }}
    >
      <div className={`flex items-center gap-2 mb-1.5 ${align === 'right' ? 'flex-row-reverse' : ''}`}>
        <span className="relative flex h-6 w-6 flex-shrink-0 items-center justify-center">
          {/* subtle pulse ring */}
          {!reduce && (
            <motion.span
              aria-hidden
              className="absolute inset-0 rounded-[7px]"
              style={{ background: 'rgba(124,255,0,0.18)' }}
              animate={{ opacity: [0.5, 0.1, 0.5], scale: [1, 1.18, 1] }}
              transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}
            />
          )}
          <span
            className="relative flex h-6 w-6 items-center justify-center rounded-[7px]"
            style={{ background: 'rgba(124,255,0,0.08)', border: '1px solid rgba(124,255,0,0.2)' }}
          >
            <Icon className="h-3 w-3" style={{ color: GREEN }} />
          </span>
        </span>
        <h3 className="text-[12.5px] font-bold leading-tight text-white">{callout.title}</h3>
      </div>
      <p className="text-[11px] leading-[1.5]" style={{ color: 'rgba(255,255,255,0.5)' }}>
        {callout.body}
      </p>
    </div>
  )
}
