'use client'

// WebHound — components/sections/WhatAttackersSeeSection.tsx
// Homepage "Live Scan Demo" (Scene 2). A compact, single-viewport product
// demo: heading + paragraph on the left, an animated "demo player" on the
// right that maps a real website (NorthStar Commerce preview) by popping up
// discovery nodes one/two at a time and drawing a connector line after each
// node appears. The Admin node lands last as an orange warning. The whole
// scene is sized to fit one desktop viewport — no process row, no terminal
// logs, no dot field, no giant counters. Matches the hero aesthetic
// (dark navy #020617, neon green #7CFF00 / #8BFF3E). Presentational only.

import Image from 'next/image'
import Link from 'next/link'
import { motion, useReducedMotion } from 'framer-motion'
import {
  ArrowRight,
  FileCode,
  Home,
  LayoutGrid,
  LogIn,
  Mail,
  Package,
  ShieldAlert,
  Webhook,
} from 'lucide-react'

type Icon = React.FC<{ className?: string; style?: React.CSSProperties }>

interface Node {
  id: string
  label: string
  icon: Icon
  side: 'left' | 'right' | 'bottom'
  // chip placement + connector geometry in the player's 0–100 viewBox space
  pos: { x: number; y: number } // chip anchor (node dot)
  target: { x: number; y: number } // point on the preview edge
  order: number // appearance order
  warn?: boolean // Admin = orange warning, appears last
}

// 3 left · 3 right · 2 bottom, wired tight around the central preview.
const NODES: Node[] = [
  { id: 'homepage', label: 'Homepage', icon: Home, side: 'left', pos: { x: 17, y: 22 }, target: { x: 31, y: 27 }, order: 0 },
  { id: 'collections', label: 'Collections', icon: LayoutGrid, side: 'left', pos: { x: 15, y: 45 }, target: { x: 30, y: 45 }, order: 1 },
  { id: 'products', label: 'Products', icon: Package, side: 'left', pos: { x: 17, y: 67 }, target: { x: 31, y: 60 }, order: 2 },
  { id: 'contact', label: 'Contact', icon: Mail, side: 'right', pos: { x: 83, y: 22 }, target: { x: 69, y: 27 }, order: 3 },
  { id: 'api', label: 'API', icon: Webhook, side: 'right', pos: { x: 85, y: 45 }, target: { x: 70, y: 45 }, order: 4 },
  { id: 'javascript', label: 'JavaScript', icon: FileCode, side: 'right', pos: { x: 83, y: 67 }, target: { x: 69, y: 60 }, order: 5 },
  { id: 'login', label: 'Login', icon: LogIn, side: 'bottom', pos: { x: 38, y: 84 }, target: { x: 44, y: 70 }, order: 6 },
  { id: 'admin', label: 'Admin', icon: ShieldAlert, side: 'bottom', pos: { x: 62, y: 84 }, target: { x: 56, y: 70 }, order: 7, warn: true },
]

const GREEN = '#7CFF00'
const ORANGE = '#FF8A1E'

// Timing — node pops, then its line draws after it lands.
const BASE = 0.35
const STEP = 0.34
const POP = 0.4
const nodeDelay = (order: number) => BASE + order * STEP
const lineDelay = (order: number) => nodeDelay(order) + POP * 0.6
const TOTAL = nodeDelay(NODES.length - 1) + POP

export function WhatAttackersSeeSection() {
  const reduce = useReducedMotion()
  const show = { once: true, amount: 0.4 } as const

  return (
    <section
      className="relative flex flex-col justify-center overflow-hidden py-14 lg:h-screen lg:py-0"
      style={{ background: '#020617' }}
      aria-labelledby="livescan-heading"
    >
      {/* Subtle grid */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(139,255,62,1) 1px, transparent 1px), linear-gradient(90deg, rgba(139,255,62,1) 1px, transparent 1px)',
          backgroundSize: '64px 64px',
          maskImage: 'radial-gradient(ellipse 75% 60% at 60% 45%, #000 0%, transparent 75%)',
          WebkitMaskImage: 'radial-gradient(ellipse 75% 60% at 60% 45%, #000 0%, transparent 75%)',
        }}
      />
      {/* Ambient glow behind the player */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background: 'radial-gradient(50% 50% at 68% 50%, rgba(124,255,0,0.08) 0%, transparent 70%)',
        }}
      />

      <div className="relative z-10 mx-auto grid w-full max-w-[1280px] grid-cols-1 items-center gap-10 px-5 sm:px-8 lg:grid-cols-12 lg:gap-8 lg:px-12 xl:px-16">
        {/* ── Left: heading + paragraph + compact CTA ── */}
        <motion.div
          className="lg:col-span-5"
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={show}
          transition={{ duration: 0.5 }}
        >
          <p className="mb-3 text-[10px] font-bold uppercase tracking-[0.28em]" style={{ color: 'rgba(139,255,62,0.7)' }}>
            Live scan demo
          </p>
          <h2
            id="livescan-heading"
            className="mb-4 font-bold leading-[1.05] tracking-[-0.02em] text-white"
            style={{ fontSize: 'clamp(1.8rem, 3.2vw, 2.8rem)' }}
          >
            What hackers can see on your website.
          </h2>
          <p className="mb-6 max-w-[460px] text-[14px] leading-[1.6]" style={{ color: 'rgba(255,255,255,0.62)' }}>
            Every website leaves clues. WebHound maps your site the same way
            attackers do — finding exposed paths, risky scripts, weak headers,
            and hidden entry points.
          </p>
          <Link
            href="/scanner"
            className="group inline-flex items-center gap-2 rounded-[10px] px-5 py-2.5 text-[13.5px] font-semibold text-[#020617] transition-all duration-200 motion-reduce:transition-none hover:-translate-y-px motion-reduce:hover:translate-y-0"
            style={{ background: GREEN, boxShadow: '0 0 22px rgba(124,255,0,0.28)' }}
          >
            Explore the scanner
            <ArrowRight className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-0.5 motion-reduce:transform-none" />
          </Link>
        </motion.div>

        {/* ── Right: the demo player ── */}
        <motion.div
          className="lg:col-span-7"
          initial={{ opacity: 0, y: 16, scale: 0.985 }}
          whileInView={{ opacity: 1, y: 0, scale: 1 }}
          viewport={show}
          transition={{ duration: 0.55 }}
        >
          <DemoPlayer reduce={!!reduce} />
        </motion.div>
      </div>
    </section>
  )
}

// ── Demo player ──────────────────────────────────────────────────────────────

function DemoPlayer({ reduce }: { reduce: boolean }) {
  return (
    <div
      className="relative mx-auto w-full max-w-[760px] overflow-hidden rounded-[16px]"
      style={{
        background: 'rgba(6,10,20,0.85)',
        border: '1px solid rgba(255,255,255,0.08)',
        boxShadow: '0 24px 70px rgba(0,0,0,0.5), 0 0 50px rgba(124,255,0,0.06)',
      }}
    >
      {/* player title bar */}
      <div
        className="flex items-center gap-2 px-4 py-2.5"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(8,12,22,0.7)' }}
      >
        <span className="flex gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: 'rgba(255,255,255,0.18)' }} />
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: 'rgba(255,255,255,0.18)' }} />
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: 'rgba(124,255,0,0.5)' }} />
        </span>
        <span className="ml-2 text-[11px] font-medium" style={{ color: 'rgba(255,255,255,0.4)' }}>
          webhound · mapping northstarcommerce.com
        </span>
      </div>

      {/* stage: preview + nodes + connectors */}
      <div className="relative w-full" style={{ aspectRatio: '16 / 11' }}>
        {/* connectors (draw after each node appears) */}
        <svg aria-hidden className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
          {NODES.map((n) => (
            <motion.line
              key={n.id}
              x1={n.pos.x}
              y1={n.pos.y}
              x2={n.target.x}
              y2={n.target.y}
              stroke={n.warn ? ORANGE : GREEN}
              strokeWidth={1}
              strokeOpacity={n.warn ? 0.5 : 0.3}
              vectorEffect="non-scaling-stroke"
              initial={{ pathLength: reduce ? 1 : 0, opacity: reduce ? 1 : 0 }}
              whileInView={{ pathLength: 1, opacity: 1 }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ duration: reduce ? 0 : 0.5, delay: reduce ? 0 : lineDelay(n.order) }}
            />
          ))}
        </svg>

        {/* central website preview (slightly reduced) */}
        <div className="absolute left-1/2 top-[43%] w-[52%] -translate-x-1/2 -translate-y-1/2">
          <div
            className="relative overflow-hidden rounded-[8px]"
            style={{ border: '1px solid rgba(124,255,0,0.22)', boxShadow: '0 12px 36px rgba(0,0,0,0.5), 0 0 26px rgba(124,255,0,0.08)' }}
          >
            <div
              aria-hidden
              className="pointer-events-none absolute -inset-4 rounded-[16px]"
              style={{ background: 'radial-gradient(closest-side, rgba(124,255,0,0.18), transparent 78%)', filter: 'blur(6px)' }}
            />
            <Image
              src="/images/northstar-commerce-preview.jpeg"
              alt="A real e-commerce website being mapped by WebHound, with its pages and entry points discovered."
              width={1536}
              height={1024}
              priority
              sizes="(max-width: 1024px) 70vw, 400px"
              className="relative block h-auto w-full"
            />
          </div>
        </div>

        {/* discovery nodes */}
        {NODES.map((n) => (
          <NodeChip key={n.id} node={n} reduce={reduce} />
        ))}
      </div>

      {/* footer summary (small) */}
      <div
        className="flex items-center justify-between gap-3 px-4 py-3"
        style={{ borderTop: '1px solid rgba(255,255,255,0.06)', background: 'rgba(8,12,22,0.7)' }}
      >
        <span className="flex items-center gap-2 text-[12px]" style={{ color: 'rgba(255,255,255,0.55)' }}>
          <motion.span
            className="h-1.5 w-1.5 rounded-full"
            style={{ background: GREEN }}
            animate={reduce ? undefined : { opacity: [1, 0.25, 1] }}
            transition={{ duration: 1.3, repeat: Infinity, ease: 'easeInOut' }}
          />
          Discovering your attack surface…
        </span>
        <motion.span
          className="text-[12px] font-semibold tabular-nums"
          style={{ color: GREEN }}
          initial={{ opacity: reduce ? 1 : 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.4, delay: reduce ? 0 : TOTAL }}
        >
          31 assets discovered
        </motion.span>
      </div>
    </div>
  )
}

function NodeChip({ node, reduce }: { node: Node; reduce: boolean }) {
  const Icon = node.icon
  const color = node.warn ? ORANGE : GREEN
  const tintBg = node.warn ? 'rgba(255,138,30,0.1)' : 'rgba(124,255,0,0.08)'
  const tintBorder = node.warn ? 'rgba(255,138,30,0.35)' : 'rgba(124,255,0,0.22)'

  // Anchor the chip to the nearest edge so labels never overflow the player.
  const style: React.CSSProperties =
    node.side === 'left'
      ? { left: '2.5%', top: `${node.pos.y}%`, transform: 'translateY(-50%)' }
      : node.side === 'right'
        ? { right: '2.5%', top: `${node.pos.y}%`, transform: 'translateY(-50%)' }
        : { left: `${node.pos.x}%`, top: `${node.pos.y}%`, transform: 'translate(-50%,-50%)' }

  const rowReverse = node.side === 'right'

  return (
    <motion.div
      className="absolute"
      style={style}
      initial={{ opacity: reduce ? 1 : 0, scale: reduce ? 1 : 0.6 }}
      whileInView={{ opacity: 1, scale: 1 }}
      viewport={{ once: true, amount: 0.4 }}
      transition={
        reduce
          ? { duration: 0 }
          : { type: 'spring', stiffness: 420, damping: 22, delay: nodeDelay(node.order) }
      }
    >
      <div
        className={`flex items-center gap-1.5 rounded-[8px] px-2 py-1 ${rowReverse ? 'flex-row-reverse' : ''}`}
        style={{ background: 'rgba(8,12,22,0.92)', border: `1px solid ${tintBorder}` }}
      >
        <span
          className="relative flex h-5 w-5 items-center justify-center rounded-[6px]"
          style={{ background: tintBg, border: `1px solid ${tintBorder}` }}
        >
          {!reduce && (
            <motion.span
              aria-hidden
              className="absolute inset-0 rounded-[6px]"
              style={{ background: color, opacity: 0.16 }}
              animate={{ opacity: [0.16, 0.02, 0.16], scale: [1, 1.25, 1] }}
              transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut', delay: nodeDelay(node.order) }}
            />
          )}
          <Icon className="relative h-3 w-3" style={{ color }} />
        </span>
        <span className="whitespace-nowrap text-[11px] font-semibold text-white">{node.label}</span>
      </div>
    </motion.div>
  )
}
