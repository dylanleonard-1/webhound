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
    // Slice 3 D6 — softened phrasing per the jargon rule:
    // 'know what you have exposed' → "know what's exposed on
    // your site". Same meaning, fewer ambiguous nouns.
    body: 'all require you to know what’s exposed on your site and to find issues before attackers do. "We didn’t know" is no longer a defense.',
  },
]

export function WhyMatters() {
  // Slice 3 hybrid-theme: this section is now LIGHT. Stake stats
  // sit on a white-surface card with a slate border — same
  // pattern Stripe / Vercel / Cloudflare use at the "why it
  // matters" break. The dark monotone gets a relief break here
  // before the Footer resumes dark.
  return (
    <section className="relative py-20 lg:py-28 px-6 sm:px-12 xl:px-20" style={{ background: '#F4F5F7' }}>
      <div className="max-w-6xl mx-auto">
        <motion.div
          className="mb-12 max-w-[680px]"
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
        >
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(180,30,30,0.9)' }}>
            Why this matters
          </p>
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em]"
            style={{ fontSize: 'clamp(1.8rem, 3.4vw, 2.8rem)', color: '#0B1220' }}
          >
            One missed security issue
            <span className="block" style={{ color: 'rgba(15,23,42,0.55)' }}>
              can end a small business.
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
                style={{ background: '#FFFFFF', border: '1px solid rgba(15,23,42,0.07)' }}
              >
                <div
                  className="w-10 h-10 rounded-[10px] flex items-center justify-center mb-5"
                  style={{ background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.22)' }}
                >
                  <Icon className="w-4 h-4" style={{ color: '#ef4444' }} />
                </div>
                <div
                  className="font-bold mb-3 leading-[1] tracking-[-0.02em]"
                  style={{ fontSize: 'clamp(1.6rem, 2.4vw, 2.1rem)', color: '#0B1220' }}
                >
                  {s.stat}
                </div>
                <p className="text-[13.5px] leading-[1.65]" style={{ color: 'rgba(15,23,42,0.62)' }}>
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
            className="font-bold leading-[1.15] tracking-[-0.02em] max-w-[640px]"
            style={{ fontSize: 'clamp(1.4rem, 2.6vw, 2rem)', color: '#0B1220' }}
          >
            Two minutes is shorter than the call you&apos;d have to make
            after a breach.
          </h3>
          <Link href="/scan">
            <button
              className="inline-flex items-center gap-2 px-7 py-3.5 rounded-[10px] text-[14px] font-semibold text-[#020617] transition-all duration-300 hover:shadow-[0_8px_28px_rgba(124,255,0,0.45)] hover:scale-[1.02]"
              style={{ background: '#7CFF00', boxShadow: '0 4px 18px rgba(124,255,0,0.28)' }}
            >
              Start Free Scan
              <ArrowRight className="w-4 h-4" />
            </button>
          </Link>
          <p className="text-[12px]" style={{ color: 'rgba(15,23,42,0.5)' }}>
            No credit card. Results in under two minutes.
          </p>
        </motion.div>
      </div>
    </section>
  )
}
