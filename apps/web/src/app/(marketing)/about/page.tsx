'use client'

// WebHound — apps/web/src/app/(marketing)/about/page.tsx
// Slice 6 L4 — minimal /about page. Resolves the RI-1 audit
// finding (footer /about was 404).
//
// Rule for this page (verbatim user directive): "No corporate
// fluff. No startup buzzwords. Why exists / Who it helps / What
// problem / The mission." Four short sections, all-dark theme,
// no fabricated team page, no leadership headshots, no
// founding-date theatre. Silence > fake trust.

import Link from 'next/link'
import { ArrowRight, ScanLine, ShieldAlert, Users, Compass } from 'lucide-react'

interface Block {
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  eyebrow: string
  heading: string
  body: string
}

const BLOCKS: Block[] = [
  {
    icon: ShieldAlert,
    eyebrow: 'Why WebHound exists',
    heading: 'Small business websites are attacked daily — and nobody is watching them.',
    body: 'Enterprise security tools cost tens of thousands of dollars a year and require a security team to operate. The other end of the market is checkbox antivirus that scans for nothing real. The middle was empty. WebHound exists to fill that middle: continuous website security a small business owner can actually use.',
  },
  {
    icon: Users,
    eyebrow: 'Who it helps',
    heading: 'Owners and operators of websites that take payments, store customer data, or hold a reputation worth protecting.',
    body: 'Cafés with online ordering. Local clinics with intake forms. Consultants whose entire business runs through a single landing page. Anyone who would lose more than money if their site got compromised — but who doesn’t have a CISO on speed dial.',
  },
  {
    icon: ScanLine,
    eyebrow: 'What problem we solve',
    heading: 'Most small business sites have security issues nobody has looked at since the day they launched.',
    body: 'Missing security headers. Expired certificates nobody noticed. Forms quietly leaking data. Tracking scripts added by a marketing agency three vendors ago. WebHound scans for all of it, explains every finding in plain English, and re-checks daily so something new can’t slip in unseen.',
  },
  {
    icon: Compass,
    eyebrow: 'The mission',
    heading: 'Make continuous website security boring — for the people who can least afford a breach.',
    body: 'A scan should take two minutes. A finding should read like a checklist item, not a CVE entry. A change to your site should reach you the same day. That’s the bar. Everything we ship is measured against it.',
  },
]

export default function AboutPage() {
  return (
    <div className="min-h-screen" style={{ background: '#020617' }}>
      {/* Header */}
      <div className="border-b" style={{ borderColor: 'rgba(139,255,62,0.07)' }}>
        <div className="max-w-3xl mx-auto px-6 py-16 sm:py-20">
          <div className="inline-flex items-center gap-2 mb-6">
            <span className="w-4 h-px" style={{ background: 'rgba(139,255,62,0.4)' }} />
            <span className="text-[10px] font-bold tracking-[0.22em] uppercase" style={{ color: '#8BFF3E' }}>
              About WebHound
            </span>
          </div>
          <h1
            className="font-bold leading-[1.05] tracking-[-0.025em] text-white"
            style={{ fontSize: 'clamp(2rem, 4.4vw, 3.4rem)' }}
          >
            Continuous website security
            <span className="block" style={{ color: 'rgba(255,255,255,0.55)' }}>
              for owners, not auditors.
            </span>
          </h1>
          <p className="text-[15px] leading-[1.7] max-w-[640px] mt-7" style={{ color: 'rgba(255,255,255,0.65)' }}>
            WebHound runs the kind of scans an enterprise security team would
            run — every day, on your site — and reports what it finds in
            language you can act on without hiring anyone.
          </p>
        </div>
      </div>

      {/* Blocks */}
      <div className="max-w-3xl mx-auto px-6 py-16 sm:py-20 space-y-12">
        {BLOCKS.map(b => {
          const Icon = b.icon
          return (
            <section key={b.eyebrow}>
              <div className="flex items-center gap-3 mb-4">
                <div
                  className="w-9 h-9 rounded-[10px] flex items-center justify-center"
                  style={{ background: 'rgba(124,255,0,0.06)', border: '1px solid rgba(124,255,0,0.18)' }}
                >
                  <Icon className="w-4 h-4" style={{ color: '#7CFF00' }} />
                </div>
                <span className="text-[10px] font-bold tracking-[0.22em] uppercase" style={{ color: 'rgba(255,255,255,0.45)' }}>
                  {b.eyebrow}
                </span>
              </div>
              <h2
                className="font-bold leading-[1.2] tracking-[-0.015em] text-white mb-4"
                style={{ fontSize: 'clamp(1.4rem, 2.6vw, 1.85rem)' }}
              >
                {b.heading}
              </h2>
              <p className="text-[14.5px] leading-[1.75]" style={{ color: 'rgba(255,255,255,0.62)' }}>
                {b.body}
              </p>
            </section>
          )
        })}
      </div>

      {/* CTA */}
      <div className="border-t" style={{ borderColor: 'rgba(139,255,62,0.07)' }}>
        <div className="max-w-3xl mx-auto px-6 py-16 sm:py-20 text-center">
          <h3
            className="font-bold leading-[1.2] tracking-[-0.015em] text-white mb-6"
            style={{ fontSize: 'clamp(1.4rem, 2.6vw, 2rem)' }}
          >
            Scan your site in under two minutes.
          </h3>
          <Link href="/scan">
            <button
              className="inline-flex items-center gap-2 px-8 py-4 rounded-[10px] text-[15px] font-semibold text-[#020617] transition-all duration-200 motion-reduce:transition-none hover:shadow-[0_12px_36px_rgba(124,255,0,0.45)] hover:-translate-y-px motion-reduce:hover:translate-y-0"
              style={{ background: '#7CFF00', boxShadow: '0 6px 22px rgba(124,255,0,0.30)' }}
            >
              Start Free Scan
              <ArrowRight className="w-4 h-4" />
            </button>
          </Link>
          <p className="text-[12px] mt-4" style={{ color: 'rgba(255,255,255,0.42)' }}>
            No credit card. No signup until you save your report.
          </p>
        </div>
      </div>
    </div>
  )
}
