'use client'

import Link from 'next/link'
import { motion } from 'framer-motion'
import { ArrowRight, DollarSign, TrendingDown, FileWarning } from 'lucide-react'

interface Stake {
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  stat: string
  body: string
}

// Slice 2 Q3 — stat softening with explicit IBM citation on
// retained numbers. Removed the widely-disputed "60% close within
// six months" stat (the canonical source traces to a misreported
// NCSA piece and is risky to keep on a security-product trust
// surface). Replaced with a citable detection-time stat from the
// same IBM report.
const STAKES: Stake[] = [
  {
    icon: DollarSign,
    stat: '$4.45M',
    body: 'is the average cost of a data breach (IBM Cost of a Data Breach Report, 2024). Most of that is incident response, legal fees, and lost customers — not the breach itself.',
  },
  {
    icon: TrendingDown,
    stat: '200+ days',
    body: 'is the average time before a breach is even detected (IBM, 2024). That’s months of exposure before anyone notices — long enough for data to leave and never come back.',
  },
  {
    icon: FileWarning,
    stat: 'GDPR · PCI · SOC 2',
    body: 'all require you to know what you have exposed and to find issues before attackers do. "We didn’t know" is no longer a defense.',
  },
]

export function WhyMatters() {
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
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(239,68,68,0.75)' }}>
            Why this matters
          </p>
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em] text-white"
            style={{ fontSize: 'clamp(1.8rem, 3.4vw, 2.8rem)' }}
          >
            A single missed vulnerability
            <span className="block" style={{ color: 'rgba(255,255,255,0.55)' }}>
              can end a business.
            </span>
          </h2>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-14">
          {STAKES.map((s, i) => {
            const Icon = s.icon
            return (
              <motion.div
                key={s.stat}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.3 }}
                transition={{ duration: 0.45, delay: i * 0.08 }}
                className="rounded-[14px] p-6"
                style={{ background: 'rgba(8,12,22,0.85)', border: '1px solid rgba(255,255,255,0.06)' }}
              >
                <div
                  className="w-10 h-10 rounded-[10px] flex items-center justify-center mb-5"
                  style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.18)' }}
                >
                  <Icon className="w-4 h-4" style={{ color: '#ef4444' }} />
                </div>
                <div
                  className="font-bold text-white mb-3 leading-[1] tracking-[-0.02em]"
                  style={{ fontSize: 'clamp(1.6rem, 2.4vw, 2.1rem)' }}
                >
                  {s.stat}
                </div>
                <p className="text-[13.5px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                  {s.body}
                </p>
              </motion.div>
            )
          })}
        </div>

        <motion.div
          className="flex flex-col items-center text-center gap-5"
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
        >
          <h3
            className="font-bold leading-[1.15] text-white tracking-[-0.02em] max-w-[640px]"
            style={{ fontSize: 'clamp(1.4rem, 2.6vw, 2rem)' }}
          >
            Two minutes is shorter than the call you&apos;d have to make
            after a breach.
          </h3>
          <Link href="/scan">
            <button
              className="inline-flex items-center gap-2 px-7 py-3.5 rounded-[10px] text-[14px] font-semibold text-[#020617] transition-all duration-300 hover:shadow-[0_0_30px_rgba(124,255,0,0.4)] hover:scale-[1.02]"
              style={{ background: '#7CFF00', boxShadow: '0 0 20px rgba(124,255,0,0.22)' }}
            >
              Start Free Scan
              <ArrowRight className="w-4 h-4" />
            </button>
          </Link>
          <p className="text-[12px]" style={{ color: 'rgba(255,255,255,0.32)' }}>
            No credit card. Results in under two minutes.
          </p>
        </motion.div>
      </div>
    </section>
  )
}
