'use client'

import { motion } from 'framer-motion'
import { ShieldCheck, Lock, CheckSquare, Eye } from 'lucide-react'

const COMPANIES = ['Acme Corp', 'Bright Digital', 'Vertex Agency', 'NovaTech', 'ClearPath', 'IronSide']

const BADGES = [
  { icon: ShieldCheck, label: 'SOC 2 Aligned',   color: '#4F9CF9' },
  { icon: Lock,        label: 'GDPR Safe',        color: '#8BFF3E' },
  { icon: CheckSquare, label: 'OWASP Coverage',   color: '#a78bfa' },
  { icon: Eye,         label: 'Passive Scanning', color: '#22d3ee' },
]

export function TrustBar() {
  return (
    <section className="py-14 border-t border-white/[0.04]" style={{ background: '#020617' }}>
      <div className="max-w-5xl mx-auto px-5">
        <motion.p
          className="text-center text-[10px] font-semibold uppercase tracking-[0.22em] mb-8"
          style={{ color: 'rgba(255,255,255,0.22)' }}
          initial={{ opacity: 0, y: 8 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
        >
          Trusted by security teams at leading organizations
        </motion.p>

        <motion.div
          className="flex flex-wrap justify-center items-center gap-x-10 gap-y-4 mb-12"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.1 }}
        >
          {COMPANIES.map(name => (
            <span
              key={name}
              className="text-[13px] font-bold"
              style={{ color: 'rgba(255,255,255,0.14)', letterSpacing: '0.05em' }}
            >
              {name}
            </span>
          ))}
        </motion.div>

        <motion.div
          className="flex flex-wrap justify-center gap-3"
          initial={{ opacity: 0, y: 6 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          {BADGES.map(({ icon: Icon, label, color }) => (
            <div
              key={label}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full"
              style={{
                background: `${color}0d`,
                border: `1px solid ${color}22`,
              }}
            >
              <Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color }} />
              <span className="text-[11px] font-semibold tracking-wide" style={{ color: `${color}cc` }}>
                {label}
              </span>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  )
}
