'use client'

// WebHound — components/sections/WhatAttackersSeeSection.tsx
// Homepage "What Attackers See" section. Explains what WebHound looks at.
// Enterprise product-demo layout: left copy column + a large browser-framed
// NorthStar Commerce preview as the visual hero, with security callouts
// orbiting close around it, wired by short thin green SVG connector lines
// with softly pulsing endpoint dots. Fits ~one desktop viewport. Matches the
// hero aesthetic (dark navy #020617, neon green #7CFF00 / #84FF3A).
// Presentational only — no backend touched. Respects prefers-reduced-motion.
//
// NOTE: this section is "what WebHound looks at" (security surfaces). The
// asset-discovery animation (Homepage/Collections/… "31 assets") belongs to a
// separate Live Scan Demo scene, not here.

import Image from 'next/image'
import Link from 'next/link'
import { motion, useReducedMotion } from 'framer-motion'
import {
  ArrowRight,
  Boxes,
  FileCode,
  FormInput,
  Globe,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Webhook,
} from 'lucide-react'

type Icon = React.FC<{ className?: string; style?: React.CSSProperties }>

interface SurfaceNode {
  id: string
  label: string
  description: string
  icon: Icon
  side: 'left' | 'right'
  top: string // vertical placement of the card within the stage
  // connector geometry in the stage's 0–100 viewBox space
  cardPoint: { x: number; y: number } // dot at the card's inner edge
  edgePoint: { x: number; y: number } // dot on the preview frame edge
}

const NODES: SurfaceNode[] = [
  { id: 'headers', label: 'Headers', description: 'Security headers can reveal weaknesses.', icon: ShieldCheck, side: 'left', top: '13%', cardPoint: { x: 15, y: 22 }, edgePoint: { x: 17, y: 22 } },
  { id: 'ssl', label: 'SSL Certificate', description: 'Expired or weak certificates create trust issues.', icon: Lock, side: 'left', top: '34%', cardPoint: { x: 15, y: 42 }, edgePoint: { x: 17, y: 42 } },
  { id: 'dns', label: 'DNS Records', description: 'Misconfigurations can expose infrastructure.', icon: Globe, side: 'left', top: '54%', cardPoint: { x: 15, y: 60 }, edgePoint: { x: 17, y: 60 } },
  { id: 'forms', label: 'Forms', description: 'Forms can be abused to steal data or inject attacks.', icon: FormInput, side: 'left', top: '74%', cardPoint: { x: 15, y: 78 }, edgePoint: { x: 17, y: 78 } },
  { id: 'javascript', label: 'JavaScript', description: 'Third-party scripts can introduce vulnerabilities.', icon: FileCode, side: 'right', top: '13%', cardPoint: { x: 85, y: 22 }, edgePoint: { x: 83, y: 22 } },
  { id: 'third', label: 'Third Parties', description: 'External services increase attack surface.', icon: Boxes, side: 'right', top: '34%', cardPoint: { x: 85, y: 42 }, edgePoint: { x: 83, y: 42 } },
  { id: 'admin', label: 'Admin Pages', description: 'Exposed admin pages are a top target.', icon: ShieldAlert, side: 'right', top: '54%', cardPoint: { x: 85, y: 60 }, edgePoint: { x: 83, y: 60 } },
  { id: 'api', label: 'API Endpoints', description: 'Unprotected APIs can leak sensitive information.', icon: Webhook, side: 'right', top: '74%', cardPoint: { x: 85, y: 78 }, edgePoint: { x: 83, y: 78 } },
]

const GREEN = '#7CFF00'

export function WhatAttackersSeeSection() {
  const reduce = useReducedMotion()
  const show = { once: true, amount: 0.3 } as const

  return (
    <section
      className="relative flex items-center overflow-hidden py-20 lg:min-h-[800px]"
      style={{ background: '#020617' }}
      aria-labelledby="attackers-see-heading"
    >
      {/* Subtle grid */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(132,255,58,1) 1px, transparent 1px), linear-gradient(90deg, rgba(132,255,58,1) 1px, transparent 1px)',
          backgroundSize: '64px 64px',
          maskImage: 'radial-gradient(ellipse 80% 65% at 62% 45%, #000 0%, transparent 78%)',
          WebkitMaskImage: 'radial-gradient(ellipse 80% 65% at 62% 45%, #000 0%, transparent 78%)',
        }}
      />
      {/* Ambient glow behind the visual */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{ background: 'radial-gradient(46% 50% at 70% 50%, rgba(124,255,0,0.07) 0%, transparent 70%)' }}
      />

      <div className="relative z-10 mx-auto w-full max-w-[1440px] px-5 sm:px-8 lg:px-12 xl:px-16">
        <div className="grid grid-cols-1 items-center gap-10 lg:grid-cols-[30%_70%] lg:gap-4">
          {/* ── LEFT: copy ── */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={show}
            transition={{ duration: 0.5 }}
          >
            <p className="mb-3 text-[10px] font-bold uppercase tracking-[0.28em]" style={{ color: 'rgba(132,255,58,0.75)' }}>
              What attackers see
            </p>
            <h2
              id="attackers-see-heading"
              className="mb-4 font-bold leading-[1.05] tracking-[-0.02em] text-white"
              style={{ fontSize: 'clamp(1.9rem, 3vw, 2.9rem)' }}
            >
              What hackers can see on{' '}
              <span style={{ color: GREEN }}>your website.</span>
            </h2>
            <p className="mb-7 max-w-[440px] text-[14.5px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.62)' }}>
              Every website leaves clues. WebHound maps your site the same way
              attackers do — finding exposed paths, risky scripts, weak headers,
              and hidden entry points.
            </p>
            <Link
              href="/scanner"
              className="group inline-flex items-center gap-2 rounded-[10px] px-6 py-3 text-[14px] font-semibold text-[#020617] transition-all duration-200 motion-reduce:transition-none hover:-translate-y-px motion-reduce:hover:translate-y-0"
              style={{ background: GREEN, boxShadow: '0 0 24px rgba(124,255,0,0.3)' }}
            >
              Explore the scanner
              <ArrowRight className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-0.5 motion-reduce:transform-none" />
            </Link>
          </motion.div>

          {/* ── RIGHT (desktop): visual stage with orbiting callouts ── */}
          <div className="hidden lg:block">
            <motion.div
              className="relative mx-auto h-[580px] w-full max-w-[980px]"
              initial={{ opacity: 0, scale: 0.98 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={show}
              transition={{ duration: 0.55 }}
            >
              {/* connector lines + endpoint dots */}
              <svg aria-hidden className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
                {NODES.map((n, i) => (
                  <g key={n.id}>
                    <motion.line
                      x1={n.cardPoint.x}
                      y1={n.cardPoint.y}
                      x2={n.edgePoint.x}
                      y2={n.edgePoint.y}
                      stroke={GREEN}
                      strokeWidth={1}
                      strokeOpacity={0.32}
                      vectorEffect="non-scaling-stroke"
                      initial={{ pathLength: reduce ? 1 : 0, opacity: reduce ? 1 : 0 }}
                      whileInView={{ pathLength: 1, opacity: 1 }}
                      viewport={show}
                      transition={{ duration: reduce ? 0 : 0.5, delay: reduce ? 0 : 0.5 + i * 0.12 }}
                    />
                  </g>
                ))}
              </svg>
              {/* pulsing endpoint dots (separate layer so the glow isn't clipped) */}
              {NODES.map((n, i) => (
                <motion.span
                  key={`${n.id}-dot`}
                  aria-hidden
                  className="absolute h-2 w-2 rounded-full"
                  style={{
                    left: `${n.edgePoint.x}%`,
                    top: `${n.edgePoint.y}%`,
                    transform: 'translate(-50%,-50%)',
                    background: GREEN,
                    boxShadow: '0 0 8px rgba(124,255,0,0.8)',
                  }}
                  initial={{ opacity: 0, scale: 0 }}
                  whileInView={{ opacity: 1, scale: 1 }}
                  viewport={show}
                  transition={{ duration: 0.3, delay: reduce ? 0 : 0.5 + i * 0.12 }}
                >
                  {!reduce && (
                    <motion.span
                      className="absolute inset-0 rounded-full"
                      style={{ background: GREEN }}
                      animate={{ opacity: [0.6, 0, 0.6], scale: [1, 2.4, 1] }}
                      transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut', delay: i * 0.15 }}
                    />
                  )}
                </motion.span>
              ))}

              {/* central preview (the visual hero) */}
              <motion.div
                className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2"
                style={{ width: 'clamp(480px, 44vw, 620px)' }}
                animate={reduce ? undefined : { y: [0, -10, 0] }}
                transition={{ duration: 7, repeat: Infinity, ease: 'easeInOut' }}
              >
                <BrowserPreview />
              </motion.div>

              {/* callout cards */}
              {NODES.map((n, i) => (
                <motion.div
                  key={n.id}
                  className="absolute"
                  style={n.side === 'left' ? { left: 0, top: n.top } : { right: 0, top: n.top }}
                  initial={{ opacity: 0, x: reduce ? 0 : n.side === 'left' ? -14 : 14 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={show}
                  transition={{ duration: 0.45, delay: reduce ? 0 : 0.3 + i * 0.1 }}
                >
                  <NodeCard node={n} align={n.side === 'left' ? 'left' : 'right'} reduce={!!reduce} />
                </motion.div>
              ))}
            </motion.div>
          </div>

          {/* ── RIGHT (mobile/tablet): stacked ── */}
          <div className="lg:hidden">
            <motion.div
              className="relative mx-auto max-w-[560px]"
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={show}
              transition={{ duration: 0.5 }}
            >
              <BrowserPreview />
            </motion.div>
            <div className="mt-8 grid grid-cols-1 gap-3 sm:grid-cols-2">
              {NODES.map((n, i) => (
                <motion.div
                  key={n.id}
                  initial={{ opacity: 0, y: 12 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, amount: 0.2 }}
                  transition={{ duration: 0.4, delay: i * 0.04 }}
                >
                  <NodeCard node={n} align="left" reduce={!!reduce} fullWidth />
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

// ── Helpers ────────────────────────────────────────────────────────────────

function BrowserPreview() {
  return (
    <div className="relative">
      {/* subtle green glow behind */}
      <div
        aria-hidden
        className="pointer-events-none absolute -inset-5 rounded-[24px]"
        style={{ background: 'radial-gradient(closest-side, rgba(124,255,0,0.16), transparent 80%)', filter: 'blur(6px)' }}
      />
      <div
        className="relative overflow-hidden rounded-[14px]"
        style={{
          border: '1px solid rgba(124,255,0,0.22)',
          boxShadow: '0 26px 70px rgba(0,0,0,0.55), 0 0 36px rgba(124,255,0,0.07)',
        }}
      >
        {/* browser chrome */}
        <div
          className="flex items-center gap-3 px-4 py-2.5"
          style={{ background: 'rgba(8,12,22,0.92)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}
        >
          <span className="flex gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: 'rgba(255,255,255,0.18)' }} />
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: 'rgba(255,255,255,0.18)' }} />
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: 'rgba(124,255,0,0.5)' }} />
          </span>
          <span
            className="flex-1 truncate rounded-[6px] px-3 py-1 text-center text-[11px]"
            style={{ background: 'rgba(2,6,23,0.6)', color: 'rgba(255,255,255,0.42)' }}
          >
            northstarcommerce.com
          </span>
        </div>
        <Image
          src="/images/northstar-commerce-preview.jpeg"
          alt="A real e-commerce website, mapped by WebHound to reveal its attack surface."
          width={1536}
          height={1024}
          priority
          sizes="(max-width: 1024px) 90vw, 660px"
          className="block h-auto w-full"
        />
      </div>
    </div>
  )
}

function NodeCard({
  node,
  align,
  reduce,
  fullWidth = false,
}: {
  node: SurfaceNode
  align: 'left' | 'right'
  reduce: boolean
  fullWidth?: boolean
}) {
  const Icon = node.icon
  return (
    <div
      className={`rounded-[18px] p-3.5 ${align === 'right' ? 'text-right' : 'text-left'}`}
      style={{
        width: fullWidth ? '100%' : 156,
        background: 'rgba(8,14,24,0.72)',
        border: '1px solid rgba(132,255,58,0.18)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
      }}
    >
      <div className={`mb-1.5 flex items-center gap-2 ${align === 'right' ? 'flex-row-reverse' : ''}`}>
        <span
          className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full"
          style={{ background: 'rgba(124,255,0,0.08)', border: '1px solid rgba(124,255,0,0.22)' }}
        >
          <Icon className="h-3.5 w-3.5" style={{ color: GREEN }} />
        </span>
        <h3 className="text-[13px] font-bold leading-tight text-white">{node.label}</h3>
      </div>
      <p className="text-[11.5px] leading-[1.5]" style={{ color: 'rgba(255,255,255,0.5)' }}>
        {node.description}
      </p>
    </div>
  )
}
