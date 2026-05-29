'use client'

// WebHound — components/sections/webhound-advantage.tsx
// Slice 6 — "The WebHound Advantage" (4 pillars).
// Modeled on Cynet Advantage / Linear Why-Linear. Outcome-named
// pillars that answer 'why is WebHound different' in 4 lines.
// All-dark surface; matches surrounding sections.

import { motion } from 'framer-motion'
import { ScanSearch, MessagesSquare, Activity, Brain } from 'lucide-react'

interface Pillar {
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  title: string
  body: string
  accent: string
  accentBg: string
}

const PILLARS: Pillar[] = [
  {
    icon: ScanSearch,
    title: 'One scan, every angle',
    body: 'We check headers, certificates, third-party scripts, redirects, exposed paths, and more in a single pass.',
    accent: '#7CFF00',
    accentBg: 'rgba(124,255,0,0.07)',
  },
  {
    icon: MessagesSquare,
    title: 'Written for owners',
    body: 'Every finding explains what’s wrong, who’s affected, and what it costs. No security vocabulary required.',
    accent: '#4F9CF9',
    accentBg: 'rgba(79,156,249,0.08)',
  },
  {
    icon: Activity,
    title: 'Watches for changes',
    body: 'After your first scan we re-check daily and tell you the moment something changes — before it becomes a breach.',
    accent: '#22d3ee',
    accentBg: 'rgba(34,211,238,0.08)',
  },
  {
    icon: Brain,
    title: 'Catches what others miss',
    body: 'We learn what your site normally looks like and flag anything unusual — including scripts that appear overnight.',
    accent: '#a78bfa',
    accentBg: 'rgba(167,139,250,0.08)',
  },
]

export function WebHoundAdvantage() {
  return (
    <section className="relative py-20 lg:py-28 px-6 sm:px-12 xl:px-20" style={{ background: '#020617' }}>
      <div className="max-w-6xl mx-auto">
        <motion.div
          className="mb-12 max-w-[680px]"
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
        >
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(139,255,62,0.7)' }}>
            The WebHound advantage
          </p>
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em] text-white"
            style={{ fontSize: 'clamp(1.8rem, 3.4vw, 2.8rem)' }}
          >
            What makes us different
            <span className="block" style={{ color: 'rgba(255,255,255,0.55)' }}>
              from every other scanner.
            </span>
          </h2>
        </motion.div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {PILLARS.map((p, i) => {
            const Icon = p.icon
            return (
              <motion.div
                key={p.title}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.3 }}
                transition={{ duration: 0.45, delay: i * 0.08 }}
                className="rounded-[14px] p-6 h-full flex flex-col"
                style={{
                  background: 'rgba(8,12,22,0.85)',
                  border: '1px solid rgba(255,255,255,0.06)',
                }}
              >
                <div
                  className="w-10 h-10 rounded-[10px] flex items-center justify-center mb-5"
                  style={{ background: p.accentBg, border: `1px solid ${p.accent}30` }}
                >
                  <Icon className="w-4 h-4" style={{ color: p.accent }} />
                </div>
                <h3 className="text-[16px] font-bold text-white leading-[1.3] mb-3">
                  {p.title}
                </h3>
                <p className="text-[13.5px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                  {p.body}
                </p>
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
