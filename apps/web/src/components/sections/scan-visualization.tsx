'use client'

import { useRef, useState, useEffect } from 'react'
import { motion, useMotionValue, useSpring, useTransform, useInView } from 'framer-motion'

// ── Constants ─────────────────────────────────────────────────────────────────

const VW = 440
const CX = 220
const CY = 220
const SWEEP_DURATION = 4 // seconds per revolution

function polar(deg: number, r: number) {
  const rad = (deg - 90) * (Math.PI / 180)
  return { x: Math.round(CX + r * Math.cos(rad)), y: Math.round(CY + r * Math.sin(rad)) }
}

interface NodeDef {
  id: string
  label: string
  type: 'domain' | 'service' | 'cloud' | 'network' | 'critical'
  x: number
  y: number
  delay: number
}

const NODES: NodeDef[] = [
  { id: 'domain', label: 'acme-corp.com', type: 'domain',   x: CX, y: CY, delay: 0    },
  { id: 'dns',    label: 'DNS',           type: 'service',   ...polar(40,  88),  delay: 0.44 },
  { id: 'api',    label: 'API',           type: 'service',   ...polar(155, 88),  delay: 1.72 },
  { id: 'ssl',    label: 'SSL/TLS',       type: 'service',   ...polar(275, 88),  delay: 3.06 },
  { id: 'aws',    label: 'AWS',           type: 'cloud',     ...polar(10,  152), delay: 0.11 },
  { id: 'cdn',    label: 'CDN',           type: 'network',   ...polar(80,  152), delay: 0.89 },
  { id: 'auth',   label: 'Auth',          type: 'service',   ...polar(148, 152), delay: 1.64 },
  { id: 'admin',  label: '/admin',        type: 'critical',  ...polar(218, 152), delay: 2.42 },
  { id: 'db',     label: 'Database',      type: 'service',   ...polar(300, 152), delay: 3.33 },
]

const NODE_MAP = Object.fromEntries(NODES.map(n => [n.id, n])) as Record<string, NodeDef>

const EDGES: [string, string][] = [
  ['domain', 'dns'],   ['domain', 'api'],  ['domain', 'ssl'],
  ['domain', 'aws'],   ['domain', 'cdn'],  ['domain', 'auth'],
  ['domain', 'admin'], ['domain', 'db'],
  ['dns', 'aws'],      ['api', 'cdn'],
]

const TYPE_COLOR: Record<string, string> = {
  domain: '#8BFF3E', service: '#4F9CF9', cloud: '#00E5A8',
  network: '#60A5FA', critical: '#EF4444',
}
const TYPE_R: Record<string, number> = {
  domain: 9, service: 4.5, cloud: 5.5, network: 4.5, critical: 5.5,
}

function edgeLength(fromId: string, toId: string) {
  const a = NODE_MAP[fromId], b = NODE_MAP[toId]
  return Math.sqrt((b.x - a.x) ** 2 + (b.y - a.y) ** 2)
}

// ── Component ─────────────────────────────────────────────────────────────────

export function ScanVisualization() {
  const containerRef = useRef<HTMLDivElement>(null)
  const inView = useInView(containerRef, { once: true, margin: '-60px' })
  const [activeNodes, setActiveNodes] = useState<Set<string>>(new Set())

  // Node activation — staggered by radar angle
  useEffect(() => {
    if (!inView) return
    const timers: ReturnType<typeof setTimeout>[] = []
    NODES.forEach(node => {
      timers.push(setTimeout(
        () => setActiveNodes(prev => new Set([...prev, node.id])),
        node.delay * 1000,
      ))
    })
    return () => timers.forEach(clearTimeout)
  }, [inView])

  // Mouse tilt
  const mouseX = useMotionValue(0)
  const mouseY = useMotionValue(0)
  const rotX = useSpring(useTransform(mouseY, [-VW / 2, VW / 2], [3, -3]), { stiffness: 50, damping: 20 })
  const rotY = useSpring(useTransform(mouseX, [-VW / 2, VW / 2], [-3, 3]), { stiffness: 50, damping: 20 })

  return (
    <div
      ref={containerRef}
      className="relative select-none w-full max-w-[440px]"
      style={{ aspectRatio: '1', perspective: '800px' }}
      onMouseMove={e => {
        const r = e.currentTarget.getBoundingClientRect()
        mouseX.set(e.clientX - r.left - r.width / 2)
        mouseY.set(e.clientY - r.top - r.height / 2)
      }}
      onMouseLeave={() => { mouseX.set(0); mouseY.set(0) }}
    >
      <motion.div
        style={{ rotateX: rotX, rotateY: rotY, transformStyle: 'preserve-3d' }}
        className="relative w-full h-full"
      >
        <svg
          viewBox={`0 0 ${VW} ${VW}`}
          className="absolute inset-0 w-full h-full"
          style={{ overflow: 'visible' }}
        >
          <defs>
            {/* Radial glow from center */}
            <radialGradient id="centerGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="rgba(139,255,62,0.08)" />
              <stop offset="100%" stopColor="rgba(139,255,62,0)" />
            </radialGradient>
            {/* Critical node glow */}
            <filter id="critGlow">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Center radial ambient */}
          <circle cx={CX} cy={CY} r={200} fill="url(#centerGlow)" />

          {/* Concentric rings */}
          {[88, 152, 195].map((r, i) => (
            <circle key={r} cx={CX} cy={CY} r={r}
              fill="none"
              stroke="rgba(139,255,62,0.07)"
              strokeWidth={i === 2 ? 0.5 : 0.8}
              strokeDasharray={i === 2 ? '3 6' : undefined}
            />
          ))}

          {/* Crosshair ticks on inner ring */}
          {[0, 90, 180, 270].map(deg => {
            const inner = polar(deg, 84)
            const outer = polar(deg, 92)
            return (
              <line key={deg} x1={inner.x} y1={inner.y} x2={outer.x} y2={outer.y}
                stroke="rgba(139,255,62,0.25)" strokeWidth={0.8} />
            )
          })}

          {/* Target reticle on center node */}
          {[[-20, -9, -20, -20, -9, -20], [9, -20, 20, -20, 20, -9],
            [-20, 9, -20, 20, -9, 20], [9, 20, 20, 20, 20, 9]].map(([x1, y1, x2, y2, x3, y3], i) => (
            <path key={i}
              d={`M ${CX + x1} ${CY + y1} L ${CX + x2} ${CY + y2} L ${CX + x3} ${CY + y3}`}
              fill="none" stroke="rgba(139,255,62,0.45)" strokeWidth={0.8} />
          ))}

          {/* Radar sweep — trailing wedge */}
          {inView && (
            <motion.path
              d={`M ${CX} ${CY} L ${CX} ${CY - 165} A 165 165 0 0 1 ${polar(38, 165).x} ${polar(38, 165).y} Z`}
              fill="rgba(139,255,62,0.07)"
              style={{ transformOrigin: `${CX}px ${CY}px` }}
              animate={{ rotate: 360 }}
              transition={{ duration: SWEEP_DURATION, repeat: Infinity, ease: 'linear' }}
            />
          )}

          {/* Radar sweep — leading edge beam */}
          {inView && (
            <motion.line
              x1={CX} y1={CY} x2={CX} y2={CY - 165}
              stroke="rgba(139,255,62,0.55)" strokeWidth={1.2}
              style={{ transformOrigin: `${CX}px ${CY}px` }}
              animate={{ rotate: 360 }}
              transition={{ duration: SWEEP_DURATION, repeat: Infinity, ease: 'linear' }}
            />
          )}

          {/* Connection lines */}
          {EDGES.map(([fromId, toId], i) => {
            const from = NODE_MAP[fromId]
            const to = NODE_MAP[toId]
            const len = edgeLength(fromId, toId)
            const bothActive = activeNodes.has(fromId) && activeNodes.has(toId)

            return (
              <g key={`edge-${i}`}>
                <motion.line
                  x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                  stroke="rgba(139,255,62,0.14)"
                  strokeWidth={0.6}
                  strokeDasharray={len}
                  animate={{ strokeDashoffset: bothActive ? 0 : len }}
                  transition={{ duration: 0.7, ease: 'easeOut' }}
                />
                {/* Data pulse */}
                {bothActive && (
                  <motion.circle
                    r={1.8}
                    fill={TYPE_COLOR[from.type]}
                    fillOpacity={0.85}
                    animate={{
                      cx: [from.x, to.x],
                      cy: [from.y, to.y],
                      opacity: [0, 0.9, 0],
                    }}
                    transition={{ duration: 1.6, repeat: Infinity, delay: i * 0.38, ease: 'easeInOut' }}
                  />
                )}
              </g>
            )
          })}

          {/* Nodes */}
          {NODES.map(node => {
            const isActive = activeNodes.has(node.id)
            const color = TYPE_COLOR[node.type]
            const r = TYPE_R[node.type]
            const isCritical = node.type === 'critical'
            const isDomain = node.type === 'domain'

            return (
              <g key={node.id}>
                {/* Expanding pulse ring — only on critical/domain nodes to cap repeat: Infinity count */}
                {isActive && (isCritical || isDomain) && (
                  <motion.circle
                    cx={node.x} cy={node.y} r={r + 3} fill="none"
                    stroke={color} strokeWidth={0.6} strokeOpacity={0.45}
                    animate={{ r: [r + 3, r + 14], opacity: [0.45, 0] }}
                    transition={{ duration: isCritical ? 1.2 : 2.6, repeat: Infinity, delay: node.delay % 0.6 }}
                  />
                )}
                {/* Glow halo */}
                {isActive && (
                  <circle cx={node.x} cy={node.y} r={r + 4}
                    fill={color} fillOpacity={isDomain ? 0.18 : 0.12}
                    style={{ filter: `blur(${isDomain ? 8 : 5}px)` }}
                  />
                )}
                {/* Core */}
                <motion.circle
                  cx={node.x} cy={node.y} r={r}
                  fill={isActive ? color : 'rgba(255,255,255,0.07)'}
                  animate={{ opacity: isActive ? 1 : 0.18 }}
                  transition={{ duration: 0.5 }}
                />
                {/* Domain ring */}
                {isDomain && (
                  <circle cx={node.x} cy={node.y} r={r + 5}
                    fill="none" stroke="rgba(139,255,62,0.3)" strokeWidth={0.8} />
                )}
              </g>
            )
          })}

          {/* Node labels */}
          {NODES.filter(n => n.id !== 'domain').map(node => {
            const isActive = activeNodes.has(node.id)
            const labelY = node.y < CY ? node.y - 11 : node.y + 15
            return (
              <motion.text
                key={`lbl-${node.id}`}
                x={node.x} y={labelY}
                textAnchor="middle"
                fontSize={8.5}
                fontFamily="monospace"
                fill={node.type === 'critical' ? 'rgba(239,68,68,0.9)' : 'rgba(255,255,255,0.7)'}
                animate={{ opacity: isActive ? 1 : 0.12 }}
                transition={{ duration: 0.4 }}
              >
                {node.label}
              </motion.text>
            )
          })}

          {/* Center domain label */}
          <text x={CX} y={CY + 22} textAnchor="middle" fontSize={7}
            fontFamily="monospace" fill="rgba(255,255,255,0.55)">
            acme-corp.com
          </text>
          <text x={CX} y={CY - 16} textAnchor="middle" fontSize={6.5}
            fontFamily="monospace" fill="rgba(139,255,62,0.6)" letterSpacing={1}>
            TARGET
          </text>
        </svg>
      </motion.div>
    </div>
  )
}
