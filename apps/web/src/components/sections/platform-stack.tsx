'use client'

// WebHound — components/sections/platform-stack.tsx
// Slice 6 — Platform deep-dive (5 feature cards).
// Modeled on Cynet 'One AI-Powered Platform for Complete
// Protection'. Each card maps a real product engine to a
// plain-English capability. NO engine names in the marketing
// surface (per D6 — 'WADE' stays as the route, never in copy).

import { motion } from 'framer-motion'
import { Search, Eye, Brain, FileText, ShieldCheck } from 'lucide-react'

interface Feature {
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  title: string
  body: string
}

const FEATURES: Feature[] = [
  {
    icon: Search,
    title: 'Scan engine',
    body: 'Twenty-plus security checks per scan, severity-tiered, ranked by what to fix first.',
  },
  {
    icon: Eye,
    title: 'Continuous monitoring',
    body: 'Daily re-scans compare against your baseline. Alerts only on real changes — no noise.',
  },
  {
    icon: Brain,
    title: 'Smart change detection',
    body: 'Learns what your site normally looks like. Flags the unusual without crying wolf.',
  },
  {
    icon: FileText,
    title: 'Plain-English reports',
    body: 'Every finding rewritten for owners. No acronyms unless you ask for them.',
  },
  {
    icon: ShieldCheck,
    title: 'Compliance mapping',
    body: 'Findings auto-mapped to GDPR, PCI DSS, SOC 2, ISO 27001, HIPAA, OWASP, NIST, and CWE.',
  },
]

export function PlatformStack() {
  return (
    <section className="relative py-20 lg:py-28 px-6 sm:px-12 xl:px-20 overflow-hidden" style={{ background: '#02060f' }}>
      <div className="max-w-6xl mx-auto">
        <motion.div
          className="mb-12 max-w-[680px]"
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
        >
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(139,255,62,0.7)' }}>
            One platform
          </p>
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em] text-white"
            style={{ fontSize: 'clamp(1.8rem, 3.4vw, 2.8rem)' }}
          >
            Five things WebHound does
            <span className="block" style={{ color: 'rgba(255,255,255,0.55)' }}>
              so you don’t have to.
            </span>
          </h2>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {FEATURES.map((f, i) => {
            const Icon = f.icon
            return (
              <motion.div
                key={f.title}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.3 }}
                transition={{ duration: 0.45, delay: i * 0.06 }}
                className="rounded-[14px] p-6 h-full flex flex-col"
                style={{
                  background: 'rgba(8,12,22,0.9)',
                  border: '1px solid rgba(255,255,255,0.06)',
                }}
              >
                <div
                  className="w-9 h-9 rounded-[9px] flex items-center justify-center mb-4"
                  style={{ background: 'rgba(124,255,0,0.06)', border: '1px solid rgba(124,255,0,0.2)' }}
                >
                  <Icon className="w-4 h-4" style={{ color: '#7CFF00' }} />
                </div>
                <h3 className="text-[15.5px] font-bold text-white leading-[1.3] mb-2.5">
                  {f.title}
                </h3>
                <p className="text-[13px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                  {f.body}
                </p>
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
