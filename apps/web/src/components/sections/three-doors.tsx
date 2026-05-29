'use client'

import Link from 'next/link'
import { motion } from 'framer-motion'
import { ArrowRight, ScanLine, Activity, Brain } from 'lucide-react'

interface Door {
  question: string
  preview: string
  href: string
  cta: string
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  accent: string
  accentBg: string
}

// Slice 2 D2 — copy reframe. Card titles moved from
// internal-question / engine-name framing ("AI baseline", "WADE")
// to outcome-named for the small business owner mental model.
// Routes unchanged; engine names removed from marketing-visible
// copy.
const DOORS: Door[] = [
  {
    question: 'What you get from a single scan',
    preview:
      'A plain-English report listing every issue we found on your site, ranked by what to fix first.',
    href: '/scanner',
    cta: 'See how a scan works',
    icon: ScanLine,
    accent: '#7CFF00',
    accentBg: 'rgba(124,255,0,0.06)',
  },
  {
    question: 'What changes when nobody’s watching',
    preview:
      'We re-scan your site daily and tell you the moment something changes — before it becomes a breach.',
    href: '/monitoring',
    cta: 'See how monitoring works',
    icon: Activity,
    accent: '#4F9CF9',
    accentBg: 'rgba(79,156,249,0.07)',
  },
  {
    question: 'What other scanners miss',
    preview:
      'WebHound learns what your site normally looks like and flags anything unusual — like a new script that quietly appeared overnight.',
    href: '/wade',
    cta: 'See what we catch',
    icon: Brain,
    accent: '#a78bfa',
    accentBg: 'rgba(167,139,250,0.07)',
  },
]

export function ThreeDoors() {
  // Slice 3 hybrid-theme: this section is now LIGHT.
  // Background #FAFAFB; cards white with subtle slate border. The
  // light break interrupts the dark monotone and signals "calmer
  // documentation entry points" the way Stripe / Linear / Vercel
  // surface their feature-index pages.
  return (
    <section className="relative py-20 lg:py-28 px-6 sm:px-12 xl:px-20" style={{ background: '#FAFAFB' }}>
      <div className="max-w-6xl mx-auto">
        <motion.div
          className="mb-12 max-w-[640px]"
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
        >
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(38,99,12,0.85)' }}>
            Want to know more?
          </p>
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em]"
            style={{ fontSize: 'clamp(1.8rem, 3.4vw, 2.8rem)', color: '#0B1220' }}
          >
            Pick the part you&apos;re curious about.
          </h2>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {DOORS.map((d, i) => {
            const Icon = d.icon
            return (
              <motion.div
                key={d.href}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.3 }}
                transition={{ duration: 0.45, delay: i * 0.08 }}
              >
                {/* Slice 3 hybrid-theme: light card on the light
                    section. White surface, slate border, dark text. */}
                <Link
                  href={d.href}
                  className="group block rounded-[14px] p-6 h-full transition-[border-color,transform,box-shadow] duration-200 motion-reduce:transition-none hover:-translate-y-0.5 motion-reduce:hover:translate-y-0 hover:shadow-[0_8px_24px_rgba(15,23,42,0.06)]"
                  style={{
                    background: '#FFFFFF',
                    border: '1px solid rgba(15,23,42,0.07)',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = `${d.accent}60` }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(15,23,42,0.07)' }}
                >
                  <div
                    className="w-10 h-10 rounded-[10px] flex items-center justify-center mb-5"
                    style={{ background: d.accentBg, border: `1px solid ${d.accent}30` }}
                  >
                    <Icon className="w-4 h-4" style={{ color: d.accent }} />
                  </div>

                  <h3 className="text-[16.5px] font-bold leading-[1.3] mb-3" style={{ color: '#0B1220' }}>
                    {d.question}
                  </h3>

                  <p className="text-[13.5px] leading-[1.65] mb-5" style={{ color: 'rgba(15,23,42,0.62)' }}>
                    {d.preview}
                  </p>

                  <span
                    className="inline-flex items-center gap-1.5 text-[12.5px] font-semibold"
                    style={{ color: d.accent }}
                  >
                    {d.cta}
                    <ArrowRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-1" />
                  </span>
                </Link>
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
