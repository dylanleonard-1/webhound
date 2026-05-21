'use client'

import { memo } from 'react'
import { motion, useMotionValue, useSpring, useTransform } from 'framer-motion'
import { Shield } from 'lucide-react'

// ── Constants ─────────────────────────────────────────────────────────────────

const LAYERS = [
  { num: '01', title: 'Reconnaissance',         short: 'Asset discovery & fingerprinting',  action: 'Mapping subdomains & scanning open ports...'    },
  { num: '02', title: 'DNS & Infrastructure',   short: 'DNS analysis & hosting audit',       action: 'Auditing DNS records & CNAME chains...'         },
  { num: '03', title: 'SSL / TLS Analysis',     short: 'Encryption validation',              action: 'Testing cipher suites & certificate validity...' },
  { num: '04', title: 'Vulnerability Scanning', short: 'CVE matching & detection',           action: 'Correlating CVE database — 18,400 checks...'    },
  { num: '05', title: 'Web App Scanning',       short: 'OWASP Top 10 & more',                action: 'Probing endpoints for injection vectors...'     },
  { num: '06', title: 'Configuration Review',   short: 'Misconfiguration detection',         action: 'Auditing headers, CORS & cookie policies...'    },
  { num: '07', title: 'Threat Intelligence',    short: 'Global feed matching',               action: 'Cross-referencing global threat feeds...'       },
  { num: '08', title: 'Monitoring & Alerts',    short: '24/7 continuous protection',         action: 'Establishing continuous surveillance...'        },
]

export const LAYER_THEMES = [
  { color: '#7CFF00', glow: 'rgba(124,255,0,0.35)'   },  // 01 Recon
  { color: '#00e5ff', glow: 'rgba(0,229,255,0.35)'   },  // 02 DNS
  { color: '#a78bfa', glow: 'rgba(167,139,250,0.35)' },  // 03 SSL
  { color: '#f87171', glow: 'rgba(248,113,113,0.35)' },  // 04 CVE
  { color: '#fb923c', glow: 'rgba(251,146,60,0.35)'  },  // 05 WebApp
  { color: '#fbbf24', glow: 'rgba(251,191,36,0.35)'  },  // 06 Config
  { color: '#22d3ee', glow: 'rgba(34,211,238,0.35)'  },  // 07 Threat
  { color: '#8BFF3E', glow: 'rgba(139,255,62,0.35)'  },  // 08 Monitor
]

// ── Shield logo ───────────────────────────────────────────────────────────────

function ShieldLogo({ activeLayer }: { activeLayer: number }) {
  const { color, glow } = LAYER_THEMES[activeLayer]
  return (
    <div className="flex justify-center mb-4">
      <motion.div
        className="w-10 h-10 rounded-[12px] flex items-center justify-center opacity-80"
        animate={{
          background: color,
          boxShadow: `0 0 18px ${glow.replace('0.35', '0.30')}`,
        }}
        transition={{ duration: 0.5 }}
      >
        <Shield className="w-5 h-5 text-[#020617]" strokeWidth={2.5} />
      </motion.div>
    </div>
  )
}

// ── Individual layer card ─────────────────────────────────────────────────────

interface LayerCardProps {
  index:       number
  layer:       typeof LAYERS[0]
  activeLayer: number
}

const LayerCard = memo(function LayerCard({ index, layer, activeLayer }: LayerCardProps) {
  const isCurrent = activeLayer === index
  const isDone    = activeLayer > index
  const { color } = LAYER_THEMES[activeLayer]

  return (
    <motion.div
      layout
      transition={{ duration: 0.4, ease: [0.25, 0.46, 0.45, 0.94] }}
      animate={{
        opacity: isCurrent ? 1 : isDone ? 0.60 : 0.28,
        scale:   isCurrent ? 1 : 0.985,
      }}
      className="relative rounded-[11px] border overflow-hidden"
      style={{
        borderColor: isCurrent
          ? color + '60'
          : isDone
          ? 'rgba(139,255,62,0.14)'
          : 'rgba(255,255,255,0.05)',
        background: isCurrent
          ? 'rgba(4,8,18,0.97)'
          : isDone
          ? 'rgba(4,8,18,0.75)'
          : 'rgba(4,8,18,0.45)',
        boxShadow: isCurrent
          ? `0 0 0 1px ${color}22, 0 0 14px ${color}12`
          : 'none',
      }}
    >
      {/* Horizontal scan sweep — active only */}
      {isCurrent && (
        <div className="absolute inset-0 rounded-[11px] overflow-hidden pointer-events-none">
          <div
            className="absolute top-0 bottom-0 w-[35%]"
            style={{
              background: `linear-gradient(90deg, transparent, ${color}18, transparent)`,
              animation: 'scanH 2.2s ease-in-out infinite',
            }}
          />
        </div>
      )}

      {/* Top edge highlight — active only */}
      {isCurrent && (
        <div
          className="absolute inset-x-6 top-0 h-px pointer-events-none"
          style={{ background: `linear-gradient(to right, transparent, ${color}75, transparent)` }}
        />
      )}

      <div className={`flex items-center gap-3 px-4 ${isCurrent ? 'py-3' : 'py-[9px]'}`}>
        {/* Layer number */}
        <span
          className="text-[10px] font-black font-mono tracking-wider flex-shrink-0 w-6"
          style={{
            color: isCurrent
              ? color
              : isDone
              ? 'rgba(139,255,62,0.45)'
              : 'rgba(255,255,255,0.18)',
          }}
        >
          {layer.num}
        </span>

        {/* Title + action */}
        <div className="flex-1 min-w-0">
          <span
            className="block font-semibold truncate"
            style={{
              fontSize: isCurrent ? 13 : 12,
              color: isCurrent
                ? '#fff'
                : isDone
                ? 'rgba(255,255,255,0.52)'
                : 'rgba(255,255,255,0.22)',
            }}
          >
            {layer.title}
          </span>
          {isCurrent && (
            <motion.span
              key={index}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.3, delay: 0.1 }}
              className="text-[10px] font-mono block mt-0.5 truncate"
              style={{ color: color + 'a0' }}
            >
              {layer.action}
            </motion.span>
          )}
        </div>

        {/* Done checkmark */}
        {isDone && (
          <span className="text-[10px] font-bold flex-shrink-0 text-[rgba(139,255,62,0.5)]">✓</span>
        )}

        {/* Active indicator */}
        {isCurrent && (
          <div className="flex items-center gap-1.5 flex-shrink-0">
            <span
              className="w-1.5 h-1.5 rounded-full flex-shrink-0"
              style={{
                background: color,
                boxShadow: `0 0 5px ${color}`,
                animation: 'pulse 1.2s ease-in-out infinite',
              }}
            />
            <span
              className="text-[9px] font-bold tracking-widest"
              style={{ color: color + 'bf' }}
            >
              ACTIVE
            </span>
          </div>
        )}
      </div>
    </motion.div>
  )
})

// ── Engine stack export ───────────────────────────────────────────────────────

export function EngineStack({ activeLayer }: { activeLayer: number }) {
  const mouseX = useMotionValue(0)
  const mouseY = useMotionValue(0)
  const rotX   = useSpring(useTransform(mouseY, [-200, 200], [ 2, -2]), { stiffness: 40, damping: 22 })
  const rotY   = useSpring(useTransform(mouseX, [-200, 200], [-2,  2]), { stiffness: 40, damping: 22 })

  return (
    <div
      className="relative select-none"
      style={{ width: 360, perspective: '900px' }}
      onMouseMove={e => {
        const r = e.currentTarget.getBoundingClientRect()
        mouseX.set(e.clientX - r.left - r.width / 2)
        mouseY.set(e.clientY - r.top - r.height / 2)
      }}
      onMouseLeave={() => { mouseX.set(0); mouseY.set(0) }}
    >
      <motion.div
        style={{ rotateX: rotX, rotateY: rotY, willChange: 'transform' }}
      >
        <ShieldLogo activeLayer={activeLayer} />

        <div className="flex flex-col gap-1.5">
          {LAYERS.map((layer, i) => (
            <LayerCard key={i} index={i} layer={layer} activeLayer={activeLayer} />
          ))}
        </div>
      </motion.div>
    </div>
  )
}
