'use client'

import { motion } from 'framer-motion'
import { DollarSign, TrendingDown, FileWarning } from 'lucide-react'

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
    // Slice 3 D6 — softened phrasing per the jargon rule:
    // 'know what you have exposed' → "know what's exposed on
    // your site". Same meaning, fewer ambiguous nouns.
    body: 'all require you to know what’s exposed on your site and to find issues before attackers do. "We didn’t know" is no longer a defense.',
  },
]

export function WhyMatters() {
  // Slice 6 — reverted to dark surface per user directive
  // ("two colors looks horrible — either white or dark, not both").
  // The Slice 3 hybrid #F4F5F7 light theme and the N5 light-button
  // halo treatment are gone. The closing CTA that used to live at
  // the bottom of this section has been moved to its own
  // <ClosingCTA /> rail so this section can focus on a single job:
  // 'why this matters' stake-setting.
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
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(239,68,68,0.85)' }}>
            Why this matters
          </p>
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em] text-white"
            style={{ fontSize: 'clamp(1.8rem, 3.4vw, 2.8rem)' }}
          >
            One missed security issue
            <span className="block" style={{ color: 'rgba(255,255,255,0.55)' }}>
              can end a small business.
            </span>
          </h2>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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
                  style={{ background: 'rgba(239,68,68,0.10)', border: '1px solid rgba(239,68,68,0.30)' }}
                >
                  <Icon className="w-4 h-4" style={{ color: '#ef4444' }} />
                </div>
                <div
                  className="font-bold mb-3 leading-[1] tracking-[-0.02em] text-white"
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
      </div>
    </section>
  )
}
