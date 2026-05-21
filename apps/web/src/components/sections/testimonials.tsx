'use client'

import { motion } from 'framer-motion'
import { Quote } from 'lucide-react'

const TESTIMONIALS = [
  {
    quote: "WebHound found a misconfigured CORS policy that had been exposing our API to cross-origin requests for months. The report was clear enough to hand directly to our dev team.",
    name: 'Sarah M.',
    role: 'Security Lead',
    company: 'FinOps Agency',
    initials: 'SM',
    color: '#8BFF3E',
  },
  {
    quote: "We run WebHound on every site we launch. The WADE baseline comparison catches regressions before clients do — it's saved us from awkward conversations more than once.",
    name: 'James K.',
    role: 'CTO',
    company: 'Brightmoor Digital',
    initials: 'JK',
    color: '#4F9CF9',
  },
  {
    quote: "As a solo dev running a SaaS, I can't afford a security team. WebHound gives me enterprise-grade visibility at a fraction of the cost. CVSS scoring helps me prioritize what matters.",
    name: 'Alex R.',
    role: 'Founder',
    company: 'Self-funded SaaS',
    initials: 'AR',
    color: '#a78bfa',
  },
]

export function Testimonials() {
  return (
    <section className="py-20 border-t border-white/[0.04]" style={{ background: '#020617' }}>
      <div className="max-w-6xl mx-auto px-5">
        <motion.div
          className="text-center mb-12"
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
        >
          <p
            className="text-[11px] font-semibold uppercase tracking-[0.2em] mb-3"
            style={{ color: 'rgba(139,255,62,0.7)' }}
          >
            What teams are saying
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold text-white tracking-tight">
            Security teams trust WebHound
          </h2>
        </motion.div>

        <div className="grid md:grid-cols-3 gap-5">
          {TESTIMONIALS.map(({ quote, name, role, company, initials, color }, i) => (
            <motion.div
              key={name}
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: i * 0.1 }}
              className="relative rounded-2xl p-6 flex flex-col"
              style={{
                background: 'rgba(8,12,22,0.8)',
                border: '1px solid rgba(255,255,255,0.06)',
              }}
            >
              <Quote className="w-6 h-6 mb-4 opacity-30" style={{ color }} />
              <p className="text-[13.5px] text-gray-300 leading-relaxed flex-1 mb-6">
                &ldquo;{quote}&rdquo;
              </p>
              <div className="flex items-center gap-3 pt-4 border-t border-white/[0.06]">
                <div
                  className="w-9 h-9 rounded-full flex items-center justify-center text-[11px] font-bold flex-shrink-0"
                  style={{ background: `${color}1a`, color }}
                >
                  {initials}
                </div>
                <div>
                  <p className="text-[13px] font-semibold text-white">{name}</p>
                  <p className="text-[11px]" style={{ color: 'rgba(255,255,255,0.35)' }}>
                    {role} · {company}
                  </p>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
