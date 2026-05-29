'use client'

// WebHound — components/sections/solutions-grid.tsx
// Slice 6 — "What we check" (6-card grid).
// Modeled on Cynet Solutions row. Each card maps a scanner
// capability to a plain-English checkup the SBO recognises.

import { motion } from 'framer-motion'
import { FileCode, Lock, Globe2, MessageSquare, FolderTree, Mail } from 'lucide-react'

interface Solution {
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  title: string
  body: string
}

const SOLUTIONS: Solution[] = [
  {
    icon: FileCode,
    title: 'Your headers',
    body: 'What your site tells browsers about itself — and what attackers can read from it.',
  },
  {
    icon: Lock,
    title: 'Your certificate',
    body: 'The lock on your door — and whether it’s about to expire.',
  },
  {
    icon: Globe2,
    title: 'Your scripts',
    body: 'Every external script your site loads — and the risky ones you didn’t know about.',
  },
  {
    icon: MessageSquare,
    title: 'Your forms',
    body: 'Login pages, contact forms, anything a visitor can fill in.',
  },
  {
    icon: FolderTree,
    title: 'Your exposed paths',
    body: 'Admin doors, staging endpoints, anything left lying around.',
  },
  {
    icon: Mail,
    title: 'Your domain',
    body: 'DNS, email-sender records, anything that lets attackers impersonate you.',
  },
]

export function SolutionsGrid() {
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
            What we check
          </p>
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em] text-white"
            style={{ fontSize: 'clamp(1.8rem, 3.4vw, 2.8rem)' }}
          >
            Six things every website owner
            <span className="block" style={{ color: 'rgba(255,255,255,0.55)' }}>
              should know about their site.
            </span>
          </h2>
        </motion.div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {SOLUTIONS.map((s, i) => {
            const Icon = s.icon
            return (
              <motion.div
                key={s.title}
                initial={{ opacity: 0, y: 12 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.25 }}
                transition={{ duration: 0.4, delay: i * 0.05 }}
                className="rounded-[12px] p-5"
                style={{
                  background: 'rgba(8,12,22,0.85)',
                  border: '1px solid rgba(255,255,255,0.05)',
                }}
              >
                <div className="flex items-center gap-3 mb-3">
                  <div
                    className="w-8 h-8 rounded-[8px] flex items-center justify-center flex-shrink-0"
                    style={{ background: 'rgba(124,255,0,0.06)', border: '1px solid rgba(124,255,0,0.18)' }}
                  >
                    <Icon className="w-3.5 h-3.5" style={{ color: '#7CFF00' }} />
                  </div>
                  <h3 className="text-[14.5px] font-bold text-white leading-[1.25]">
                    {s.title}
                  </h3>
                </div>
                <p className="text-[12.5px] leading-[1.6]" style={{ color: 'rgba(255,255,255,0.5)' }}>
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
