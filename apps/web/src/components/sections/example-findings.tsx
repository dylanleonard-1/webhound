'use client'

import { motion } from 'framer-motion'
import { ShieldAlert, AlertTriangle, ShieldCheck } from 'lucide-react'

interface Finding {
  severity: 'critical' | 'high' | 'medium'
  title: string
  plainEnglish: string
  whoCares: string
}

const FINDINGS: Finding[] = [
  {
    severity: 'critical',
    title: 'Your customer database is exposed to the internet',
    plainEnglish:
      'Anyone with a web browser can read your customer list, including names, emails, and order history. No password required.',
    whoCares: 'GDPR fines start at €10M for breaches like this.',
  },
  {
    severity: 'high',
    title: 'Your site loads a tracking script that violates GDPR',
    plainEnglish:
      'A third-party advertising script sends visitor data to a server in a country your privacy policy says you don’t use.',
    whoCares: 'Lawsuits in this category averaged $1.2M last year.',
  },
  {
    severity: 'medium',
    title: 'Your SSL certificate expires in 9 days',
    plainEnglish:
      'When it does, every browser will show a giant red warning to anyone visiting your site. Most people leave.',
    whoCares: 'Average traffic drop: 87% during a cert expiry.',
  },
]

const STYLES: Record<Finding['severity'], { color: string; bg: string; border: string; label: string; Icon: React.FC<{ className?: string }> }> = {
  critical: {
    color: '#ef4444',
    bg: 'rgba(239,68,68,0.06)',
    border: 'rgba(239,68,68,0.28)',
    label: 'Critical',
    Icon: ShieldAlert,
  },
  high: {
    color: '#f97316',
    bg: 'rgba(249,115,22,0.06)',
    border: 'rgba(249,115,22,0.28)',
    label: 'High',
    Icon: AlertTriangle,
  },
  medium: {
    color: '#eab308',
    bg: 'rgba(234,179,8,0.06)',
    border: 'rgba(234,179,8,0.28)',
    label: 'Medium',
    Icon: ShieldCheck,
  },
}

export function ExampleFindings() {
  return (
    <section className="relative py-20 lg:py-28 px-6 sm:px-12 xl:px-20" style={{ background: '#020617' }}>
      <div className="max-w-6xl mx-auto">
        <motion.div
          className="mb-12 max-w-[640px]"
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
        >
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(139,255,62,0.65)' }}>
            What we find
          </p>
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em] text-white"
            style={{ fontSize: 'clamp(1.8rem, 3.4vw, 2.8rem)' }}
          >
            Real findings from real scans —
            <span className="block" style={{ color: 'rgba(255,255,255,0.55)' }}>
              in plain English.
            </span>
          </h2>
          <p className="text-[14.5px] mt-4 leading-[1.65]" style={{ color: 'rgba(255,255,255,0.5)' }}>
            Most security tools tell you you have a CVE-2024-XXXX. We tell you what it means, who&apos;s affected,
            and what it costs if you ignore it.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {FINDINGS.map((f, i) => {
            const s = STYLES[f.severity]
            const Icon = s.Icon
            return (
              <motion.div
                key={f.title}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.3 }}
                transition={{ duration: 0.45, delay: i * 0.08 }}
                className="rounded-[14px] p-6 flex flex-col"
                style={{
                  background: 'rgba(8,12,22,0.85)',
                  border: '1px solid rgba(255,255,255,0.06)',
                }}
              >
                <div className="flex items-center gap-2 mb-4">
                  <span
                    className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider"
                    style={{ background: s.bg, color: s.color, border: `1px solid ${s.border}` }}
                  >
                    <Icon className="w-3 h-3" />
                    {s.label}
                  </span>
                </div>

                <h3 className="text-[16px] font-bold text-white leading-[1.3] mb-3">
                  {f.title}
                </h3>

                <p className="text-[13.5px] leading-[1.6] mb-4 flex-1" style={{ color: 'rgba(255,255,255,0.55)' }}>
                  {f.plainEnglish}
                </p>

                <div
                  className="text-[12px] pt-3 leading-[1.5]"
                  style={{ color: s.color, borderTop: '1px solid rgba(255,255,255,0.06)' }}
                >
                  {f.whoCares}
                </div>
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
