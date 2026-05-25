'use client'

import Link from 'next/link'
import { Mail, Lock, ShieldAlert, Briefcase, FileText, AlertTriangle } from 'lucide-react'

const channels = [
  {
    icon: Mail,
    label: 'General support',
    email: 'support@webhoundsecurity.com',
    description: 'Account, billing, scan questions. Reply within one business day.',
    accent: '#8BFF3E',
  },
  {
    icon: Briefcase,
    label: 'Sales',
    email: 'sales@webhoundsecurity.com',
    description: 'Enterprise plans, volume pricing, custom integrations, on-prem deployment.',
    accent: '#8BFF3E',
  },
  {
    icon: Lock,
    label: 'Privacy',
    email: 'privacy@webhoundsecurity.com',
    description: 'Data subject access requests, deletion requests, DPAs, GDPR / CCPA questions.',
    accent: '#4F9CF9',
  },
  {
    icon: ShieldAlert,
    label: 'Security disclosure',
    email: 'security@webhoundsecurity.com',
    description: 'Found a vulnerability in WebHound itself? Send details here. We respond within 48 hours and credit researchers in our hall of fame.',
    accent: '#a78bfa',
  },
  {
    icon: AlertTriangle,
    label: 'Abuse reports',
    email: 'abuse@webhoundsecurity.com',
    description: 'Believe a WebHound user is scanning your systems without authorization? Email us with the affected hostname and the User-Agent / IP from your logs.',
    accent: '#f97316',
  },
  {
    icon: FileText,
    label: 'Legal',
    email: 'legal@webhoundsecurity.com',
    description: 'Subpoenas, copyright takedown notices, contract questions, regulatory inquiries.',
    accent: 'rgba(255,255,255,0.55)',
  },
]

export default function ContactPage() {
  return (
    <div className="min-h-screen bg-[#020617]">
      <div className="border-b border-[rgba(139,255,62,0.07)] bg-[#020617]">
        <div className="max-w-3xl mx-auto px-6 py-16 sm:py-20">
          <div className="inline-flex items-center gap-2 mb-6">
            <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
            <span className="text-[10px] font-bold text-[#8BFF3E] tracking-[0.22em] uppercase">
              Contact
            </span>
            <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
          </div>
          <h1 className="text-4xl sm:text-5xl font-bold text-white tracking-tight mb-4">
            Get in touch
          </h1>
          <p className="text-[rgba(255,255,255,0.55)] text-base leading-relaxed max-w-2xl">
            Pick the right inbox below — that&apos;s the fastest way to get a useful reply.
            Each channel is monitored by the team that can actually answer.
          </p>
        </div>
      </div>

      <div className="max-w-3xl mx-auto px-6 py-14 sm:py-20">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {channels.map(c => (
            <a
              key={c.email}
              href={`mailto:${c.email}`}
              className="group flex flex-col gap-3 rounded-[14px] p-5 transition-all"
              style={{
                background: 'rgba(8,12,22,0.95)',
                border: '1px solid rgba(255,255,255,0.06)',
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = `${c.accent}55` }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)' }}
            >
              <div
                className="w-9 h-9 rounded-[10px] flex items-center justify-center flex-shrink-0 transition-all group-hover:scale-105"
                style={{ background: `${c.accent}15`, border: `1px solid ${c.accent}30` }}
              >
                <c.icon className="w-4 h-4" style={{ color: c.accent }} />
              </div>
              <div>
                <p className="text-[14px] font-semibold text-white mb-1">{c.label}</p>
                <p className="text-[12px] leading-relaxed mb-3" style={{ color: 'rgba(255,255,255,0.5)' }}>
                  {c.description}
                </p>
                <p className="text-[12px] font-mono" style={{ color: c.accent }}>
                  {c.email}
                </p>
              </div>
            </a>
          ))}
        </div>

        {/* Company info */}
        <div className="mt-10 pt-8 border-t border-[rgba(255,255,255,0.06)]">
          <p className="text-[10px] uppercase tracking-[0.18em] font-bold text-[rgba(255,255,255,0.4)] mb-3">
            Company
          </p>
          <div className="text-[13px] text-[rgba(255,255,255,0.55)] leading-relaxed space-y-1">
            <p><span className="text-white font-semibold">WebHound Security</span></p>
            <p>Operated from the United States</p>
            <p>
              Postal address available on request from{' '}
              <a href="mailto:legal@webhoundsecurity.com" className="text-[#8BFF3E] hover:underline">
                legal@webhoundsecurity.com
              </a>
            </p>
          </div>
        </div>

        {/* Related */}
        <div className="mt-10 rounded-[14px] border border-[rgba(139,255,62,0.1)] px-6 py-5"
             style={{ background: 'rgba(139,255,62,0.03)' }}>
          <p className="text-[10px] uppercase tracking-[0.18em] font-bold text-[#8BFF3E] mb-3">
            Looking for…
          </p>
          <div className="flex flex-wrap gap-x-5 gap-y-2 text-[12px]">
            <Link href="/docs" className="text-[rgba(255,255,255,0.65)] hover:text-[#8BFF3E]">Documentation</Link>
            <Link href="/pricing" className="text-[rgba(255,255,255,0.65)] hover:text-[#8BFF3E]">Pricing</Link>
            <Link href="/terms" className="text-[rgba(255,255,255,0.65)] hover:text-[#8BFF3E]">Terms of Service</Link>
            <Link href="/privacy" className="text-[rgba(255,255,255,0.65)] hover:text-[#8BFF3E]">Privacy Policy</Link>
            <Link href="/acceptable-use" className="text-[rgba(255,255,255,0.65)] hover:text-[#8BFF3E]">Acceptable Use</Link>
          </div>
        </div>
      </div>
    </div>
  )
}
