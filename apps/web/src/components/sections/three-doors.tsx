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

const DOORS: Door[] = [
  {
    question: 'How does the scan work?',
    preview:
      'A scan is like a security checkup for your website — we look at it the same way an attacker would, but we never touch anything.',
    href: '/scanner',
    cta: 'See how a scan works',
    icon: ScanLine,
    accent: '#7CFF00',
    accentBg: 'rgba(124,255,0,0.06)',
  },
  {
    question: 'Will you keep watching after the scan?',
    preview:
      'Yes. We re-scan daily, compare against your baseline, and alert you the moment something changes — before it becomes a breach.',
    href: '/monitoring',
    cta: 'See how monitoring works',
    icon: Activity,
    accent: '#4F9CF9',
    accentBg: 'rgba(79,156,249,0.07)',
  },
  {
    question: 'What does the AI baseline catch?',
    preview:
      'WADE learns what your site normally looks like and flags anomalies traditional scanners miss — like a script that quietly appeared at 2am.',
    href: '/wade',
    cta: 'See what WADE catches',
    icon: Brain,
    accent: '#a78bfa',
    accentBg: 'rgba(167,139,250,0.07)',
  },
]

export function ThreeDoors() {
  return (
    <section className="relative py-20 lg:py-28 px-6 sm:px-12 xl:px-20" style={{ background: '#02060f' }}>
      <div className="max-w-6xl mx-auto">
        <motion.div
          className="mb-12 max-w-[640px]"
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
        >
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(139,255,62,0.65)' }}>
            Want to know more?
          </p>
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em] text-white"
            style={{ fontSize: 'clamp(1.8rem, 3.4vw, 2.8rem)' }}
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
                <Link
                  href={d.href}
                  className="group block rounded-[14px] p-6 h-full transition-all duration-200"
                  style={{
                    background: 'rgba(8,12,22,0.95)',
                    border: '1px solid rgba(255,255,255,0.06)',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = `${d.accent}50`; e.currentTarget.style.transform = 'translateY(-2px)' }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'; e.currentTarget.style.transform = 'translateY(0)' }}
                >
                  <div
                    className="w-10 h-10 rounded-[10px] flex items-center justify-center mb-5"
                    style={{ background: d.accentBg, border: `1px solid ${d.accent}30` }}
                  >
                    <Icon className="w-4 h-4" style={{ color: d.accent }} />
                  </div>

                  <h3 className="text-[16.5px] font-bold text-white leading-[1.3] mb-3">
                    {d.question}
                  </h3>

                  <p className="text-[13.5px] leading-[1.65] mb-5" style={{ color: 'rgba(255,255,255,0.5)' }}>
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
