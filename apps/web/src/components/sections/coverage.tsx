'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { SectionContainer } from '@/components/layout/section-container'
import { GradientDivider } from '@/components/ui/gradient-divider'
import { AnimatedFadeIn } from '@/components/effects/animated-fade-in'

// ── Data ──────────────────────────────────────────────────────────────────────

const AREAS = [
  {
    glyph: 'DNS',
    title: 'DNS & Subdomain Enumeration',
    desc: 'Passive and active discovery across the full domain graph — subdomains, CNAME chains, zone configuration, and certificate records.',
    checks: [
      'Zone transfer (AXFR) exploit testing',
      'Dangling CNAME takeover detection',
      'SPF, DMARC, and DNSSEC validation',
      'Certificate transparency log enumeration',
    ],
  },
  {
    glyph: 'TLS',
    title: 'SSL / TLS Configuration',
    desc: 'Full encryption stack validation including cipher suite strength, protocol downgrade attacks, and certificate lifecycle tracking.',
    checks: [
      'TLS 1.0 / 1.1 deprecation enforcement',
      'RC4, NULL, and EXPORT cipher detection',
      'HSTS preload and max-age validation',
      'Certificate expiry and chain integrity',
    ],
  },
  {
    glyph: 'APP',
    title: 'Web Application Security',
    desc: 'Dynamic OWASP Top 10 testing across all discovered endpoints, forms, JavaScript execution paths, and input vectors.',
    checks: [
      'SQL injection and boolean-blind probing',
      'Reflected and stored XSS detection',
      'CSRF token and SameSite cookie audit',
      'CSP header analysis and bypass testing',
    ],
  },
  {
    glyph: 'API',
    title: 'APIs & Exposed Endpoints',
    desc: 'Enumerate undocumented routes, validate access control, and test for broken object-level authorization at scale.',
    checks: [
      'Unauthenticated endpoint enumeration',
      'IDOR sequential object testing',
      'CORS wildcard misconfiguration',
      'Admin panel and debug route discovery',
    ],
  },
  {
    glyph: 'CLD',
    title: 'Cloud Infrastructure Exposure',
    desc: 'Surface open cloud storage buckets, accessible metadata services, and misconfigured network boundaries.',
    checks: [
      'Open S3, GCS, and Azure blob detection',
      'Cloud metadata endpoint (SSRF) testing',
      'Exposed database and cache service ports',
      'IP reputation and blocklist correlation',
    ],
  },
  {
    glyph: 'DEP',
    title: 'Dependencies & Supply Chain',
    desc: 'Fingerprint client and server libraries against CVE feeds, advisory databases, and known supply chain compromise records.',
    checks: [
      '200+ CVE database correlation',
      'npm, PyPI, and Maven advisory matching',
      'Outdated framework and runtime detection',
      'Known malicious package flagging',
    ],
  },
]

const STATS = [
  { value: '42,000+', label: 'checks per scan' },
  { value: '200+',    label: 'CVE feeds correlated' },
  { value: '8',       label: 'analysis engine layers' },
  { value: '<2 min',  label: 'average scan time' },
]

// ── Area card ─────────────────────────────────────────────────────────────────

interface AreaCardProps {
  area: typeof AREAS[0]
  index: number
  inView: boolean
}

function AreaCard({ area, index, inView }: AreaCardProps) {
  return (
    <motion.div
      className="rounded-[16px] border border-[rgba(139,255,62,0.08)] p-5 flex flex-col gap-4 transition-colors duration-300 hover:border-[rgba(139,255,62,0.18)]"
      style={{ background: 'rgba(4,10,20,0.88)' }}
      initial={{ opacity: 0, y: 18 }}
      animate={inView ? { opacity: 1, y: 0 } : { opacity: 0, y: 18 }}
      transition={{ duration: 0.42, delay: 0.06 + index * 0.075, ease: [0.25, 0.46, 0.45, 0.94] }}
    >
      {/* Label + title */}
      <div className="flex items-start gap-3">
        <span
          className="text-[9px] font-black font-mono tracking-[0.18em] px-2 py-1 rounded-[5px] flex-shrink-0 mt-0.5"
          style={{
            color: '#8BFF3E',
            background: 'rgba(139,255,62,0.08)',
            border: '1px solid rgba(139,255,62,0.15)',
          }}
        >
          {area.glyph}
        </span>
        <span className="text-[13px] font-semibold text-white leading-snug">{area.title}</span>
      </div>

      {/* Description */}
      <p className="text-[11.5px] text-[rgba(255,255,255,0.38)] leading-relaxed">
        {area.desc}
      </p>

      {/* Checks */}
      <div className="flex flex-col gap-2 pt-1 border-t border-[rgba(139,255,62,0.06)]">
        {area.checks.map((check, i) => (
          <div key={i} className="flex items-start gap-2.5">
            <div
              className="w-3.5 h-3.5 rounded-full flex items-center justify-center flex-shrink-0 mt-[2px]"
              style={{ background: 'rgba(139,255,62,0.08)', border: '1px solid rgba(139,255,62,0.2)' }}
            >
              <div className="w-1 h-1 rounded-full bg-[#8BFF3E]" />
            </div>
            <span className="text-[11px] text-[rgba(255,255,255,0.52)] leading-snug">{check}</span>
          </div>
        ))}
      </div>
    </motion.div>
  )
}

// ── Section ───────────────────────────────────────────────────────────────────

export function Coverage() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })

  return (
    <section className="relative overflow-hidden bg-[#020617] py-28 sm:py-36">
      <GradientDivider className="absolute top-0 left-0 right-0" glow />

      {/* Subtle grid */}
      <div
        aria-hidden
        className="absolute inset-0 pointer-events-none opacity-[0.02]"
        style={{
          backgroundImage: `
            linear-gradient(rgba(139,255,62,1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(139,255,62,1) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
        }}
      />

      {/* Ambient glow */}
      <div
        aria-hidden
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none"
        style={{
          width: 900,
          height: 600,
          background: 'radial-gradient(ellipse, rgba(139,255,62,0.025) 0%, transparent 65%)',
          filter: 'blur(50px)',
        }}
      />

      <SectionContainer size="xl">
        {/* Header */}
        <div className="text-center mb-16">
          <AnimatedFadeIn delay={0.06}>
            <div className="inline-flex items-center gap-2 mb-7">
              <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
              <span className="text-[10px] font-bold text-[#8BFF3E] tracking-[0.22em] uppercase">
                Attack Surface Coverage
              </span>
              <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
            </div>
          </AnimatedFadeIn>

          <AnimatedFadeIn delay={0.14}>
            <h2
              className="font-bold leading-[0.93] tracking-[-0.025em] mb-5 mx-auto"
              style={{ fontSize: 'clamp(2.4rem, 4.5vw, 4rem)', maxWidth: 740 }}
            >
              <span className="text-white">Every Attack Vector.</span>
              {' '}
              <span
                className="text-[#8BFF3E]"
                style={{ textShadow: '0 0 48px rgba(139,255,62,0.25)' }}
              >
                Mapped.
              </span>
            </h2>
          </AnimatedFadeIn>

          <AnimatedFadeIn delay={0.22}>
            <p className="text-[rgba(255,255,255,0.44)] text-lg leading-relaxed max-w-[580px] mx-auto">
              WebHound performs complete infrastructure discovery across six attack surface domains —
              far beyond port scanning to deliver a full security posture analysis.
            </p>
          </AnimatedFadeIn>
        </div>

        {/* Cards grid */}
        <div ref={ref} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 xl:gap-5">
          {AREAS.map((area, i) => (
            <AreaCard key={i} area={area} index={i} inView={inView} />
          ))}
        </div>

        {/* Stats bar */}
        <AnimatedFadeIn delay={0.12} className="mt-12">
          <div
            className="rounded-[16px] border border-[rgba(139,255,62,0.08)] px-8 py-6 grid grid-cols-2 sm:grid-cols-4 gap-6"
            style={{ background: 'rgba(4,10,20,0.88)' }}
          >
            {STATS.map((s, i) => (
              <div key={i} className="flex flex-col items-center text-center gap-1">
                <span
                  className="text-2xl font-black font-mono text-white tracking-tight"
                  style={{ textShadow: '0 0 20px rgba(139,255,62,0.12)' }}
                >
                  {s.value}
                </span>
                <span className="text-[11px] text-[rgba(255,255,255,0.32)] leading-snug">{s.label}</span>
              </div>
            ))}
          </div>
        </AnimatedFadeIn>
      </SectionContainer>

      <GradientDivider className="absolute bottom-0 left-0 right-0" />
    </section>
  )
}
