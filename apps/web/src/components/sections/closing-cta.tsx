'use client'

// WebHound — components/sections/closing-cta.tsx
// Slice 6 — Final closing CTA rail. Modeled on Cynet's "Ready
// to start?" final block. Holds the page's last persuasive ask.

import Link from 'next/link'
import { motion } from 'framer-motion'
import { ArrowRight } from 'lucide-react'

export function ClosingCTA() {
  return (
    <section
      className="relative py-24 lg:py-32 px-6 sm:px-12 xl:px-20 overflow-hidden"
      style={{ background: '#02060f' }}
    >
      {/* Soft accent glow centered behind the headline */}
      <div
        aria-hidden
        className="pointer-events-none absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2"
        style={{
          width: 700,
          height: 700,
          background: 'radial-gradient(circle, rgba(139,255,62,0.06) 0%, transparent 60%)',
        }}
      />

      <div className="relative max-w-3xl mx-auto text-center">
        <motion.p
          className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3"
          style={{ color: 'rgba(139,255,62,0.7)' }}
          initial={{ opacity: 0, y: 8 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
        >
          Ready to see what’s exposed?
        </motion.p>
        <motion.h2
          className="font-bold leading-[1.1] tracking-[-0.025em] text-white mb-6"
          style={{ fontSize: 'clamp(2rem, 4.2vw, 3.4rem)' }}
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.55, delay: 0.05 }}
        >
          Two minutes is shorter than the call
          <span className="block" style={{ color: 'rgba(255,255,255,0.55)' }}>
            you’d have to make after a breach.
          </span>
        </motion.h2>

        <motion.div
          className="flex flex-col items-center gap-4 mt-9"
          initial={{ opacity: 0, y: 10 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5, delay: 0.15 }}
        >
          <Link href="/scan">
            <button
              className="inline-flex items-center gap-2 px-8 py-4 rounded-[10px] text-[15px] font-semibold text-[#020617] transition-all duration-200 motion-reduce:transition-none hover:shadow-[0_12px_36px_rgba(124,255,0,0.45)] hover:-translate-y-px motion-reduce:hover:translate-y-0"
              style={{ background: '#7CFF00', boxShadow: '0 6px 22px rgba(124,255,0,0.30)' }}
            >
              Start Free Scan
              <ArrowRight className="w-4 h-4" />
            </button>
          </Link>
          <p className="text-[12px]" style={{ color: 'rgba(255,255,255,0.42)' }}>
            No credit card. No signup until you save your report.
          </p>
        </motion.div>
      </div>
    </section>
  )
}
