'use client'

// WebHound — components/sections/compliance-strip.tsx
// Slice 6 — Compliance & Standards strip.
// Honest framing: WebHound MAPS findings to the frameworks listed.
// We are NOT certified as SOC 2 / ISO 27001 / etc. The honest
// claim — and the user-relevant one — is 'we help you stay
// compliant with what you owe your customers'.

import { motion } from 'framer-motion'
import { ShieldCheck } from 'lucide-react'

interface Framework {
  short: string
  long: string
}

const FRAMEWORKS: Framework[] = [
  { short: 'GDPR',       long: 'EU General Data Protection Regulation' },
  { short: 'PCI DSS',    long: 'Payment Card Industry Data Security Standard' },
  { short: 'SOC 2',      long: 'Service Organization Controls (Trust Service Criteria)' },
  { short: 'ISO 27001',  long: 'International information-security management standard' },
  { short: 'HIPAA',      long: 'US health-information security rule' },
  { short: 'OWASP',      long: 'OWASP Top 10 web-application risks' },
  { short: 'NIST',       long: 'NIST SP 800-53 security controls' },
  { short: 'CWE',        long: 'Common Weakness Enumeration' },
]

export function ComplianceStrip() {
  return (
    <section className="relative py-20 lg:py-24 px-6 sm:px-12 xl:px-20" style={{ background: '#020617' }}>
      <div className="max-w-6xl mx-auto">
        <motion.div
          className="mb-10 max-w-[680px]"
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
        >
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(139,255,62,0.7)' }}>
            Compliance &amp; standards
          </p>
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em] text-white"
            style={{ fontSize: 'clamp(1.7rem, 3.2vw, 2.5rem)' }}
          >
            Every finding mapped to
            <span className="block" style={{ color: 'rgba(255,255,255,0.55)' }}>
              the frameworks you’re measured against.
            </span>
          </h2>
          <p className="text-[14px] mt-5 max-w-[560px] leading-[1.6]" style={{ color: 'rgba(255,255,255,0.55)' }}>
            We&apos;re a scanner, not an auditor — we won&apos;t certify you. What we do
            is point at every framework your site touches and tell you, in plain
            English, where you stand against each one.
          </p>
        </motion.div>

        <div className="flex flex-wrap gap-3">
          {FRAMEWORKS.map((f, i) => (
            <motion.div
              key={f.short}
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ duration: 0.4, delay: i * 0.04 }}
              className="inline-flex items-center gap-2.5 pl-3 pr-4 py-2.5 rounded-[10px]"
              style={{
                background: 'rgba(8,12,22,0.85)',
                border: '1px solid rgba(255,255,255,0.06)',
              }}
              title={f.long}
            >
              <ShieldCheck className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'rgba(139,255,62,0.7)' }} />
              <span className="text-[13px] font-semibold text-white whitespace-nowrap">
                {f.short}
              </span>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
