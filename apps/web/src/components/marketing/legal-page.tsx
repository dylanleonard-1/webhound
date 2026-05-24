'use client'

import type { ReactNode } from 'react'
import Link from 'next/link'

export interface LegalSection {
  title: string
  body: (string | ReactNode)[]
}

interface LegalPageProps {
  title: string
  subtitle?: string
  lastUpdated: string
  intro?: ReactNode
  sections: LegalSection[]
  footerNote?: ReactNode
}

/**
 * Shared layout for the long-form legal pages (Privacy, Terms, AUP,
 * Disclaimer, Data Retention, Contact). All legal docs render off this
 * template so updates to the visual treatment land in one place.
 */
export function LegalPage({
  title, subtitle, lastUpdated, intro, sections, footerNote,
}: LegalPageProps) {
  return (
    <div className="min-h-screen bg-[#020617]">
      {/* Header */}
      <div className="border-b border-[rgba(139,255,62,0.07)] bg-[#020617]">
        <div className="max-w-3xl mx-auto px-6 py-16 sm:py-20">
          <div className="inline-flex items-center gap-2 mb-6">
            <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
            <span className="text-[10px] font-bold text-[#8BFF3E] tracking-[0.22em] uppercase">
              Legal
            </span>
            <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
          </div>
          <h1 className="text-4xl sm:text-5xl font-bold text-white tracking-tight mb-4">
            {title}
          </h1>
          {subtitle && (
            <p className="text-[rgba(255,255,255,0.55)] text-base leading-relaxed mb-3 max-w-2xl">
              {subtitle}
            </p>
          )}
          <p className="text-[rgba(255,255,255,0.44)] text-base">
            Last updated: {lastUpdated}
          </p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-3xl mx-auto px-6 py-14 sm:py-20">
        {intro && (
          <div className="text-[rgba(255,255,255,0.55)] text-base leading-relaxed mb-12">
            {intro}
          </div>
        )}

        <div className="flex flex-col gap-12">
          {sections.map(s => (
            <section key={s.title}>
              <h2 className="text-xl font-bold text-white mb-4">{s.title}</h2>
              <ul className="flex flex-col gap-3">
                {s.body.map((item, i) => (
                  <li key={i} className="flex items-start gap-3">
                    <span className="w-1 h-1 rounded-full bg-[rgba(139,255,62,0.5)] mt-2 flex-shrink-0" />
                    <span className="text-[rgba(255,255,255,0.52)] text-sm leading-relaxed">
                      {item}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>

        {/* Cross-links to related legal docs */}
        <div className="mt-16 pt-8 border-t border-[rgba(255,255,255,0.06)]">
          <p className="text-[10px] uppercase tracking-[0.18em] font-bold text-[rgba(255,255,255,0.4)] mb-3">
            Related legal documents
          </p>
          <div className="flex flex-wrap gap-x-5 gap-y-2 text-[12px]">
            <LegalLink href="/terms">Terms of Service</LegalLink>
            <LegalLink href="/privacy">Privacy Policy</LegalLink>
            <LegalLink href="/acceptable-use">Acceptable Use Policy</LegalLink>
            <LegalLink href="/disclaimer">Disclaimer</LegalLink>
            <LegalLink href="/data-retention">Data Retention</LegalLink>
            <LegalLink href="/contact">Contact</LegalLink>
          </div>
        </div>

        {footerNote && (
          <div
            className="mt-10 rounded-[14px] border border-[rgba(139,255,62,0.1)] px-6 py-5"
            style={{ background: 'rgba(139,255,62,0.03)' }}
          >
            <div className="text-[rgba(255,255,255,0.45)] text-sm leading-relaxed">
              {footerNote}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function LegalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link
      href={href}
      className="text-[rgba(255,255,255,0.55)] hover:text-[#8BFF3E] transition-colors"
    >
      {children}
    </Link>
  )
}
