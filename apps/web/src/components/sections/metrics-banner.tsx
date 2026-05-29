'use client'

// WebHound — components/sections/metrics-banner.tsx
// Slice 6 — Key metrics banner.
//
// Per L1 modification: only metrics that are unquestionably true
// and verifiable. No marketing numbers. No claims that could
// become inaccurate later. Four numbers:
//   * 20+ security engines (we have 25+; the floor "20+" is safe
//     even if engines are pruned for performance later)
//   * Under 2 minutes (QUICK profile real wall clock)
//   * 8 compliance frameworks (GDPR, PCI DSS, SOC 2, ISO 27001,
//     HIPAA, OWASP, NIST 800-53, CWE — count is auditable)
//   * Zero changes (the scanner is strictly read-only — every
//     engine is GET/HEAD only, never POST/PUT/DELETE)

import { motion } from 'framer-motion'
import { Cpu, Timer, BadgeCheck, ShieldCheck } from 'lucide-react'

interface Metric {
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  value: string
  label: string
  sub: string
}

const METRICS: Metric[] = [
  {
    icon: Cpu,
    value: '20+',
    label: 'Security checks per scan',
    sub: 'Headers, certificate, scripts, forms, paths, domain.',
  },
  {
    icon: Timer,
    value: '< 2 min',
    label: 'Average scan duration',
    sub: 'Free scans finish in under two minutes.',
  },
  {
    icon: BadgeCheck,
    value: '8',
    label: 'Compliance frameworks mapped',
    sub: 'GDPR · PCI DSS · SOC 2 · ISO 27001 · HIPAA · OWASP · NIST · CWE.',
  },
  {
    icon: ShieldCheck,
    value: 'Zero',
    label: 'Changes to your site',
    sub: 'Read-only. No credentials. No modifications. No risk.',
  },
]

export function MetricsBanner() {
  return (
    <section className="relative py-20 lg:py-24 px-6 sm:px-12 xl:px-20 overflow-hidden" style={{ background: '#02060f' }}>
      {/* Subtle inset border at top + bottom to frame the banner */}
      <div aria-hidden className="absolute top-0 inset-x-0 h-px" style={{ background: 'linear-gradient(90deg, transparent, rgba(139,255,62,0.18), transparent)' }} />
      <div aria-hidden className="absolute bottom-0 inset-x-0 h-px" style={{ background: 'linear-gradient(90deg, transparent, rgba(139,255,62,0.18), transparent)' }} />

      <div className="max-w-6xl mx-auto">
        <motion.div
          className="mb-10 text-center max-w-[640px] mx-auto"
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
        >
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(139,255,62,0.7)' }}>
            The numbers
          </p>
          <h2
            className="font-bold leading-[1.1] tracking-[-0.02em] text-white"
            style={{ fontSize: 'clamp(1.4rem, 2.6vw, 2rem)' }}
          >
            What every WebHound scan delivers.
          </h2>
        </motion.div>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {METRICS.map((m, i) => {
            const Icon = m.icon
            return (
              <motion.div
                key={m.label}
                initial={{ opacity: 0, y: 12 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.3 }}
                transition={{ duration: 0.45, delay: i * 0.06 }}
                className="rounded-[12px] p-5 flex flex-col items-start"
                style={{
                  background: 'rgba(8,12,22,0.85)',
                  border: '1px solid rgba(255,255,255,0.06)',
                }}
              >
                <Icon className="w-4 h-4 mb-3" style={{ color: '#7CFF00' }} />
                <div
                  className="font-bold text-white leading-[1] tracking-[-0.02em] mb-2"
                  style={{ fontSize: 'clamp(1.7rem, 2.6vw, 2.4rem)' }}
                >
                  {m.value}
                </div>
                <div className="text-[12.5px] font-semibold text-white leading-[1.3] mb-1.5">
                  {m.label}
                </div>
                <p className="text-[11.5px] leading-[1.5]" style={{ color: 'rgba(255,255,255,0.42)' }}>
                  {m.sub}
                </p>
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
