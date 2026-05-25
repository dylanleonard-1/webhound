'use client'

import { Fragment, useEffect, useState } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import {
  ArrowRight, Check, Minus, Sparkles, Loader2, Shield, Lock, Zap,
  Eye, AlertTriangle, Clock, Activity, Globe, Code2, Server, Database,
  Search, FileCode, Calendar, MessageSquare, UserCheck, Award,
} from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { PLAN_DEFINITIONS, type PlanDefinition, type PlanTier } from '@/lib/plans'
import { useAuth } from '@/contexts/auth'
import { cn } from '@/lib/utils'
import { JsonLd } from '@/components/seo/json-ld'

// ─── Local marketing copy ──────────────────────────────────────────────
// Plan-card feature bullets here are short marketing-focused versions of
// what's in lib/plans.ts. Backend plan limits are still the source of
// truth — these strings just describe the value clearly.

const CARD_FEATURES: Record<PlanTier, string[]> = {
  free: [
    '1 limited scan',
    '1 website only',
    'Basic findings',
    'No credit card required',
  ],
  pro: [
    'Daily continuous monitoring',
    'Automated rescans — no manual clicks',
    'Quick, Standard & Deep scans',
    'All 12 security engines',
    'Email alerts on new findings',
    'PDF / CSV / SARIF / JSON exports',
    'Up to 5 websites · 50 scans/mo',
    'Full dashboard access',
  ],
  shield: [
    'Everything in Pro',
    'Up to 25 websites · 250 scans/mo',
    '6-month scan history',
    'VirusTotal threat-intel enrichment',
    '3 team seats',
    'Read-only API access',
    'Webhook alerts',
    'Higher concurrency (5 scans)',
  ],
  enterprise: [
    'Everything in Shield',
    '1-on-1 virtual security review',
    'Personal scan walkthrough',
    'Personalized recommendations',
    'Setup guidance',
    'Priority support',
    'Team / business assistance',
  ],
}

// ─── Animation presets ─────────────────────────────────────────────────

const fadeUp = {
  initial: { opacity: 0, y: 16 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, amount: 0.2 },
  transition: { duration: 0.5, ease: 'easeOut' as const },
}

// ═══════════════════════════════════════════════════════════════════════
// Page
// ═══════════════════════════════════════════════════════════════════════

export default function PricingPage() {
  const { user } = useAuth()
  const [currentTier, setCurrentTier] = useState<PlanTier | null>(null)
  const [busyTier, setBusyTier] = useState<PlanTier | null>(null)

  useEffect(() => {
    if (!user) return
    api.billing.subscription()
      .then(s => setCurrentTier(s.plan))
      .catch(() => {})
  }, [user])

  async function handleCta(plan: PlanDefinition) {
    if (plan.tier === 'free') {
      window.location.href = user ? '/dashboard' : '/register'
      return
    }
    if (!user) {
      window.location.href = `/login?next=${encodeURIComponent('/pricing')}`
      return
    }
    setBusyTier(plan.tier)
    try {
      const { url } = await api.billing.checkout({
        tier: plan.tier as 'pro' | 'shield' | 'enterprise',
      })
      window.location.href = url
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Checkout failed.'
      toast.error(msg)
    } finally {
      setBusyTier(null)
    }
  }

  return (
    <div className="min-h-screen pt-24 pb-24 px-4">
      {/* FAQ rich-result eligibility — generated from the FAQS rendered below */}
      <JsonLd
        data={{
          '@context': 'https://schema.org',
          '@type': 'FAQPage',
          mainEntity: FAQS.map(f => ({
            '@type': 'Question',
            name: f.q,
            acceptedAnswer: { '@type': 'Answer', text: f.a },
          })),
        }}
      />
      <div className="max-w-6xl mx-auto">

        <Hero />

        <PricingCards
          currentTier={currentTier}
          busyTier={busyTier}
          onCta={handleCta}
        />

        <ComparisonTable />

        <WhyMonitoring />

        <ScanEngines />

        <FindingsExamples />

        <ManagedReview onCta={handleCta} busyTier={busyTier} />

        <FAQ />

        <FinalCta />
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════
// 1 — Hero
// ═══════════════════════════════════════════════════════════════════════

function Hero() {
  return (
    <motion.div className="text-center mb-16" {...fadeUp}>
      <div className="inline-flex items-center gap-2 px-3 py-1 mb-6 rounded-full"
           style={{ background: 'rgba(139,255,62,0.06)',
                    border: '1px solid rgba(139,255,62,0.2)' }}>
        <Sparkles className="w-3 h-3" style={{ color: '#8BFF3E' }} />
        <span className="text-[11px] font-semibold uppercase tracking-wider"
              style={{ color: '#8BFF3E' }}>
          Plans &amp; pricing
        </span>
      </div>

      <h1 className="text-4xl sm:text-6xl font-bold text-white mb-5 tracking-tight">
        Find what attackers find<br />
        <span style={{ color: '#8BFF3E' }}>— before they do.</span>
      </h1>

      <p className="text-lg max-w-2xl mx-auto leading-relaxed mb-8"
         style={{ color: 'rgba(255,255,255,0.6)' }}>
        Start with one free limited scan, then upgrade to continuous
        monitoring and advanced protection.
      </p>

      {/* Trust pills */}
      <div className="flex flex-wrap items-center justify-center gap-3 mb-8 text-[11px] font-medium"
           style={{ color: 'rgba(255,255,255,0.5)' }}>
        {[
          'Cancel anytime',
          'No contracts',
          'Secure Stripe billing',
          'Founder-built',
        ].map(t => (
          <span key={t} className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full"
                style={{ background: 'rgba(255,255,255,0.03)',
                         border: '1px solid rgba(255,255,255,0.06)' }}>
            <Check className="w-3 h-3" style={{ color: '#8BFF3E' }} />
            {t}
          </span>
        ))}
      </div>

      {/* Primary CTAs */}
      <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
        <Link href="/register"
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-[10px] text-[14px] font-semibold transition-all hover:brightness-110"
              style={{ background: '#8BFF3E', color: '#020617' }}>
          Start Free Scan
          <ArrowRight className="w-4 h-4" />
        </Link>
        <a href="#plans"
           className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-[10px] text-[14px] font-semibold text-white transition-all hover:bg-white/[0.06]"
           style={{ background: 'rgba(255,255,255,0.04)',
                    border: '1px solid rgba(255,255,255,0.12)' }}>
          View Plans
        </a>
      </div>
    </motion.div>
  )
}

// ═══════════════════════════════════════════════════════════════════════
// 2 — Pricing cards
// ═══════════════════════════════════════════════════════════════════════

function PricingCards({ currentTier, busyTier, onCta }: {
  currentTier: PlanTier | null
  busyTier: PlanTier | null
  onCta: (p: PlanDefinition) => void
}) {
  const free = PLAN_DEFINITIONS.free
  const paid = ['pro', 'shield', 'enterprise']
    .map(t => PLAN_DEFINITIONS[t as PlanTier])

  return (
    <div id="plans" className="mb-24 scroll-mt-24">

      {/* Free tier — minimised CTA strip */}
      <motion.button
        {...fadeUp}
        type="button"
        onClick={() => onCta(free)}
        className="w-full flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 rounded-[12px] px-5 py-4 mb-6 transition-all text-left hover:border-white/15"
        style={{
          background: 'rgba(255,255,255,0.025)',
          border: '1px solid rgba(255,255,255,0.08)',
        }}
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
               style={{ background: 'rgba(255,255,255,0.04)',
                        border: '1px solid rgba(255,255,255,0.08)' }}>
            <Zap className="w-4 h-4 text-white/60" />
          </div>
          <div>
            <div className="text-sm font-semibold text-white">
              Free Scan — $0
            </div>
            <div className="text-xs mt-0.5" style={{ color: 'rgba(255,255,255,0.5)' }}>
              1 limited scan · 1 website · basic findings · no card required
            </div>
          </div>
        </div>
        <div className="flex items-center gap-1.5 text-[13px] font-semibold ml-[52px] sm:ml-0"
             style={{ color: '#8BFF3E' }}>
          {currentTier === 'free' ? 'You’re on Free' : 'Start Free Scan'}
          <ArrowRight className="w-3.5 h-3.5" />
        </div>
      </motion.button>

      {/* Paid tiers */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {paid.map((plan, i) => {
          const isCurrent = currentTier === plan.tier
          const isPopular = plan.isPopular
          const bullets = CARD_FEATURES[plan.tier]

          return (
            <motion.div
              key={plan.tier}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.15 }}
              transition={{ duration: 0.45, delay: i * 0.08, ease: 'easeOut' }}
              whileHover={{ y: -4 }}
              className={cn(
                'relative flex flex-col rounded-[16px] p-7',
                isPopular && 'md:-mt-3 md:mb-3',
              )}
              style={{
                background: isPopular
                  ? 'linear-gradient(180deg, rgba(139,255,62,0.06) 0%, rgba(8,12,22,0.95) 50%)'
                  : 'rgba(8,12,22,0.95)',
                border: isPopular
                  ? '1px solid rgba(139,255,62,0.4)'
                  : '1px solid rgba(255,255,255,0.07)',
                boxShadow: isPopular
                  ? '0 0 36px rgba(139,255,62,0.15)' : undefined,
              }}
            >
              {/* Top row */}
              <div className="flex items-center justify-between mb-5 h-5">
                <span className="text-[10px] font-bold uppercase tracking-[0.15em]"
                      style={{ color: isPopular ? '#8BFF3E' : 'rgba(255,255,255,0.4)' }}>
                  {plan.name}
                </span>
                {isPopular && (
                  <span className="px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider"
                        style={{ background: '#8BFF3E', color: '#020617' }}>
                    Most popular
                  </span>
                )}
                {isCurrent && !isPopular && (
                  <span className="px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider"
                        style={{ background: '#4F9CF9', color: '#020617' }}>
                    Current
                  </span>
                )}
              </div>

              {/* Price */}
              <div className="mb-2">
                <div className="flex items-baseline gap-1.5">
                  <span className="text-[44px] font-bold text-white leading-none tracking-tight font-mono">
                    ${plan.priceUsdMonthly}
                  </span>
                  <span className="text-[14px]" style={{ color: 'rgba(255,255,255,0.45)' }}>
                    /mo
                  </span>
                </div>
              </div>
              <p className="text-[13px] mb-6 leading-relaxed"
                 style={{ color: 'rgba(255,255,255,0.55)' }}>
                {plan.tagline}
              </p>

              {/* CTA */}
              <button
                type="button"
                onClick={() => onCta(plan)}
                disabled={isCurrent || busyTier === plan.tier}
                className="w-full flex items-center justify-center gap-1.5 py-3 rounded-[10px] text-[13px] font-semibold transition-all mb-6 disabled:opacity-50 disabled:cursor-not-allowed hover:brightness-110"
                style={
                  isPopular
                    ? { background: '#8BFF3E', color: '#020617' }
                    : { background: 'rgba(255,255,255,0.04)',
                        color: '#fff',
                        border: '1px solid rgba(255,255,255,0.1)' }
                }
              >
                {busyTier === plan.tier ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : isCurrent ? (
                  'Current plan'
                ) : (
                  <>
                    {plan.ctaLabel}
                    <ArrowRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>

              {/* Bullets */}
              <ul className="space-y-2.5 flex-1">
                {bullets.map(b => (
                  <li key={b}
                      className="flex items-start gap-2 text-[12.5px] leading-snug">
                    <Check className="w-3.5 h-3.5 flex-shrink-0 mt-0.5"
                           style={{ color: '#8BFF3E' }} />
                    <span style={{ color: 'rgba(255,255,255,0.82)' }}>{b}</span>
                  </li>
                ))}
              </ul>
            </motion.div>
          )
        })}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════
// 3 — Feature comparison table
// ═══════════════════════════════════════════════════════════════════════

type Cell = boolean | string

const COMPARE: { category: string; rows: { label: string; cells: [Cell, Cell, Cell, Cell] }[] }[] = [
  {
    category: 'Monitoring',
    rows: [
      { label: 'One-time scan',          cells: [true, true, true, true] },
      { label: 'Continuous monitoring',  cells: [false, true, true, true] },
      { label: 'Automated rescans',      cells: [false, true, true, true] },
      { label: 'Scan frequency',         cells: ['Manual', 'Daily', 'Daily', 'Daily'] },
      { label: 'Websites monitored',     cells: ['1', '5', '25', '200'] },
    ],
  },
  {
    category: 'Detection',
    rows: [
      { label: 'SSL / TLS checks',                cells: [true, true, true, true] },
      { label: 'Security headers',                cells: [true, true, true, true] },
      { label: 'DNS analysis',                    cells: [false, true, true, true] },
      { label: 'Technology fingerprinting',       cells: [true, true, true, true] },
      { label: 'Deep crawl (Deep profile)',       cells: [false, true, true, true] },
      { label: 'Third-party domain analysis',     cells: [false, true, true, true] },
      { label: 'Malicious domain detection',      cells: [false, false, true, true] },
      { label: 'Risk scoring',                    cells: [true, true, true, true] },
    ],
  },
  {
    category: 'Reporting',
    rows: [
      { label: 'Dashboard access',         cells: [true, true, true, true] },
      { label: 'Email alerts',             cells: [false, true, true, true] },
      { label: 'Scan history',             cells: ['7 days', '30 days', '180 days', '1 year'] },
      { label: 'PDF reports',              cells: [false, true, true, true] },
      { label: 'Remediation guidance',     cells: ['Basic', 'Standard', 'Enhanced', 'Personalized'] },
      { label: 'Executive summaries',      cells: [false, false, true, true] },
    ],
  },
  {
    category: 'Support',
    rows: [
      { label: 'Priority support',                  cells: [false, false, true, true] },
      { label: 'Virtual review meeting',            cells: [false, false, false, true] },
      { label: 'Personalized recommendations',      cells: [false, false, false, true] },
    ],
  },
  {
    category: 'Team features',
    rows: [
      { label: 'Team accounts',           cells: [false, false, '3 seats', '15 seats'] },
      { label: 'Multi-site management',   cells: [false, true, true, true] },
    ],
  },
]

const TIER_HEADERS: { label: string; sub: string; pop?: boolean }[] = [
  { label: 'Free',                       sub: '$0' },
  { label: 'Pro',                        sub: '$29 / mo' },
  { label: 'Shield',                     sub: '$79 / mo', pop: true },
  { label: 'Managed Review',             sub: '$129 / mo' },
]

function ComparisonTable() {
  return (
    <motion.section className="mb-24" {...fadeUp}>
      <SectionHeading
        eyebrow="Compare plans"
        title="Side-by-side feature comparison"
        body="What you get at every tier. Hover any row to highlight."
      />

      {/* Desktop / tablet */}
      <div className="hidden md:block overflow-hidden rounded-[16px]"
           style={{
             background: 'rgba(8,12,22,0.6)',
             border: '1px solid rgba(255,255,255,0.07)',
           }}>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
              <th className="text-left px-5 py-4 text-[11px] font-bold uppercase tracking-wider"
                  style={{ color: 'rgba(255,255,255,0.35)' }}>
                Feature
              </th>
              {TIER_HEADERS.map(h => (
                <th key={h.label} className="px-4 py-4 text-center">
                  <div className="text-[12px] font-bold"
                       style={{ color: h.pop ? '#8BFF3E' : 'rgba(255,255,255,0.85)' }}>
                    {h.label}
                  </div>
                  <div className="text-[10px] font-mono mt-0.5"
                       style={{ color: 'rgba(255,255,255,0.4)' }}>
                    {h.sub}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {COMPARE.map(group => (
              <Fragment key={group.category}>
                <tr>
                  <td colSpan={5}
                      className="px-5 pt-6 pb-2 text-[10px] font-bold uppercase tracking-[0.15em]"
                      style={{ color: '#8BFF3E' }}>
                    {group.category}
                  </td>
                </tr>
                {group.rows.map(row => (
                  <tr key={row.label}
                      className="group transition-colors hover:bg-white/[0.015]"
                      style={{ borderTop: '1px solid rgba(255,255,255,0.04)' }}>
                    <td className="px-5 py-3 text-[12.5px]"
                        style={{ color: 'rgba(255,255,255,0.82)' }}>
                      {row.label}
                    </td>
                    {row.cells.map((c, i) => (
                      <td key={i} className="px-4 py-3 text-center">
                        <CellRender value={c} highlight={i === 2} />
                      </td>
                    ))}
                  </tr>
                ))}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>

      {/* Mobile — stacked per tier */}
      <div className="md:hidden space-y-4">
        {TIER_HEADERS.map((h, idx) => (
          <details key={h.label}
                   className="rounded-[12px] overflow-hidden"
                   style={{
                     background: 'rgba(8,12,22,0.6)',
                     border: h.pop
                       ? '1px solid rgba(139,255,62,0.3)'
                       : '1px solid rgba(255,255,255,0.07)',
                   }}>
            <summary className="px-4 py-3 cursor-pointer list-none flex items-center justify-between">
              <div>
                <div className="text-[13px] font-bold"
                     style={{ color: h.pop ? '#8BFF3E' : '#fff' }}>
                  {h.label}
                </div>
                <div className="text-[11px]"
                     style={{ color: 'rgba(255,255,255,0.45)' }}>
                  {h.sub}
                </div>
              </div>
              <ArrowRight className="w-4 h-4"
                          style={{ color: 'rgba(255,255,255,0.4)' }} />
            </summary>
            <div className="px-4 pb-4 pt-1">
              {COMPARE.map(group => (
                <div key={group.category} className="mt-4">
                  <div className="text-[9px] font-bold uppercase tracking-[0.15em] mb-2"
                       style={{ color: '#8BFF3E' }}>
                    {group.category}
                  </div>
                  <ul className="space-y-1.5">
                    {group.rows.map(r => (
                      <li key={r.label}
                          className="flex items-center justify-between text-[12px]">
                        <span style={{ color: 'rgba(255,255,255,0.78)' }}>{r.label}</span>
                        <CellRender value={r.cells[idx]} highlight={false} />
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </details>
        ))}
      </div>
    </motion.section>
  )
}

function CellRender({ value, highlight }: { value: Cell; highlight: boolean }) {
  if (value === true) {
    return <Check className="w-4 h-4 mx-auto"
                  style={{ color: highlight ? '#8BFF3E' : '#8BFF3E' }} />
  }
  if (value === false) {
    return <Minus className="w-4 h-4 mx-auto"
                  style={{ color: 'rgba(255,255,255,0.2)' }} />
  }
  return (
    <span className="text-[11.5px] font-mono"
          style={{ color: highlight ? '#8BFF3E' : 'rgba(255,255,255,0.78)' }}>
      {value}
    </span>
  )
}

// ═══════════════════════════════════════════════════════════════════════
// 4 — Why continuous monitoring matters
// ═══════════════════════════════════════════════════════════════════════

const MONITORING_RISKS = [
  { icon: Lock,         title: 'SSL expiration',
    body: 'Certificates fail silently when they expire — visitors see a scary browser warning.' },
  { icon: Eye,          title: 'Exposed admin panels',
    body: 'A misconfigured rebuild can re-expose /admin or /wp-admin to the internet overnight.' },
  { icon: Globe,        title: 'Suspicious external domains',
    body: 'A newly added third-party script can quietly send user data to unknown destinations.' },
  { icon: Code2,        title: 'Outdated technologies',
    body: 'Old jQuery, WordPress plugins, and CMS versions are the easiest CVEs to weaponize.' },
  { icon: Shield,       title: 'Weak security headers',
    body: 'Missing CSP, HSTS, or X-Frame-Options invites clickjacking and content injection.' },
  { icon: Server,       title: 'DNS risks',
    body: 'Dangling subdomains, missing SPF/DMARC, or stale records become takeover paths.' },
]

function WhyMonitoring() {
  return (
    <motion.section className="mb-24" {...fadeUp}>
      <SectionHeading
        eyebrow="Why monitoring?"
        title="Websites change. So do threats."
        body="Most vulnerabilities appear after plugin updates, expired certificates, third-party script changes, or server misconfigurations. WebHound continuously monitors so you catch them before attackers do."
      />

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {MONITORING_RISKS.map((r, i) => (
          <motion.div
            key={r.title}
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.2 }}
            transition={{ duration: 0.4, delay: i * 0.05 }}
            whileHover={{ y: -3, boxShadow: '0 0 24px rgba(139,255,62,0.18)' }}
            className="rounded-[14px] p-5 transition-all"
            style={{
              background: 'rgba(8,12,22,0.6)',
              border: '1px solid rgba(255,255,255,0.07)',
            }}
          >
            <div className="w-10 h-10 rounded-lg flex items-center justify-center mb-3"
                 style={{ background: 'rgba(139,255,62,0.08)',
                          border: '1px solid rgba(139,255,62,0.18)' }}>
              <r.icon className="w-4 h-4" style={{ color: '#8BFF3E' }} />
            </div>
            <h3 className="text-[14px] font-bold text-white mb-1.5">{r.title}</h3>
            <p className="text-[12px] leading-relaxed"
               style={{ color: 'rgba(255,255,255,0.55)' }}>
              {r.body}
            </p>
          </motion.div>
        ))}
      </div>
    </motion.section>
  )
}

// ═══════════════════════════════════════════════════════════════════════
// 5 — What WebHound scans
// ═══════════════════════════════════════════════════════════════════════

const ENGINES = [
  { icon: Lock,     title: 'SSL / TLS analysis',
    body: 'Cipher strength, certificate chain, expiry, and protocol downgrades.' },
  { icon: Shield,   title: 'Security headers',
    body: 'CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and friends.' },
  { icon: Server,   title: 'DNS inspection',
    body: 'Records, MX/SPF/DMARC, dangling subdomains, and resolution paths.' },
  { icon: Code2,    title: 'Technology fingerprinting',
    body: 'CMS, framework, server, JS libraries, and version detection.' },
  { icon: FileCode, title: 'Third-party script analysis',
    body: 'Every external JavaScript loaded — where it comes from and what it does.' },
  { icon: Globe,    title: 'External domain checks',
    body: 'Reputation lookups on every external host your site contacts.' },
  { icon: Database, title: 'Misconfiguration detection',
    body: 'Exposed admin paths, leaked .env files, open CORS, weak cookies.' },
  { icon: Search,   title: 'Threat intelligence lookups',
    body: 'Cross-reference findings against VirusTotal and known-bad feeds.' },
]

function ScanEngines() {
  return (
    <motion.section className="mb-24" {...fadeUp}>
      <SectionHeading
        eyebrow="The engine"
        title="What happens during a WebHound scan?"
        body="A single scan runs multiple specialized engines in parallel — each one looking for a different category of risk."
      />

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {ENGINES.map((e, i) => (
          <motion.div
            key={e.title}
            initial={{ opacity: 0, y: 12 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.15 }}
            transition={{ duration: 0.35, delay: i * 0.04 }}
            whileHover={{
              y: -3,
              borderColor: 'rgba(139,255,62,0.35)',
              boxShadow: '0 0 24px rgba(139,255,62,0.15)',
            }}
            className="rounded-[12px] p-4 transition-all"
            style={{
              background: 'rgba(8,12,22,0.6)',
              border: '1px solid rgba(255,255,255,0.07)',
            }}
          >
            <e.icon className="w-4 h-4 mb-2" style={{ color: '#8BFF3E' }} />
            <h4 className="text-[13px] font-semibold text-white mb-1">{e.title}</h4>
            <p className="text-[11.5px] leading-relaxed"
               style={{ color: 'rgba(255,255,255,0.5)' }}>
              {e.body}
            </p>
          </motion.div>
        ))}
      </div>
    </motion.section>
  )
}

// ═══════════════════════════════════════════════════════════════════════
// 6 — Real findings examples
// ═══════════════════════════════════════════════════════════════════════

type Severity = 'critical' | 'high' | 'medium' | 'low'

const FINDINGS: { severity: Severity; title: string; body: string }[] = [
  { severity: 'critical', title: 'Expired TLS certificate',
    body: 'Site is serving an expired certificate — visitors will see a browser warning.' },
  { severity: 'high', title: 'Exposed admin portal',
    body: '/admin is reachable from the internet without rate limiting or IP allowlisting.' },
  { severity: 'high', title: 'Suspicious third-party JavaScript',
    body: 'Script loaded from a domain flagged in threat-intel for malvertising activity.' },
  { severity: 'medium', title: 'Missing Content Security Policy',
    body: 'No CSP header — site is vulnerable to inline script injection and clickjacking.' },
  { severity: 'medium', title: 'Weak cookie security flags',
    body: 'Session cookie missing Secure and HttpOnly flags — exposed to MITM and XSS.' },
  { severity: 'low', title: 'Outdated framework detected',
    body: 'jQuery 1.x detected — known to contain XSS prototype pollution vulnerabilities.' },
]

const SEV_STYLE: Record<Severity, { label: string; bg: string; color: string }> = {
  critical: { label: 'Critical', bg: 'rgba(239,68,68,0.12)',  color: '#ef4444' },
  high:     { label: 'High',     bg: 'rgba(249,115,22,0.12)', color: '#f97316' },
  medium:   { label: 'Medium',   bg: 'rgba(234,179,8,0.12)',  color: '#eab308' },
  low:      { label: 'Low',      bg: 'rgba(139,255,62,0.10)', color: '#8BFF3E' },
}

function FindingsExamples() {
  return (
    <motion.section className="mb-24" {...fadeUp}>
      <SectionHeading
        eyebrow="Sample findings"
        title="What an actual WebHound finding looks like"
        body="Plain-English explanations with severity, evidence, and a remediation path. Examples below — not from a real customer."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {FINDINGS.map((f, i) => {
          const s = SEV_STYLE[f.severity]
          return (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.15 }}
              transition={{ duration: 0.35, delay: i * 0.04 }}
              whileHover={{ y: -3 }}
              className="rounded-[14px] p-5 transition-all"
              style={{
                background: 'rgba(8,12,22,0.6)',
                border: '1px solid rgba(255,255,255,0.07)',
              }}
            >
              <div className="flex items-center justify-between mb-3">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
                      style={{ background: s.bg, color: s.color }}>
                  {s.label}
                </span>
                <span className="text-[9.5px] font-mono uppercase tracking-wider"
                      style={{ color: 'rgba(255,255,255,0.3)' }}>
                  Example finding
                </span>
              </div>
              <div className="flex items-start gap-2 mb-2">
                <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5"
                               style={{ color: s.color }} />
                <h4 className="text-[14px] font-semibold text-white">{f.title}</h4>
              </div>
              <p className="text-[12px] leading-relaxed"
                 style={{ color: 'rgba(255,255,255,0.6)' }}>
                {f.body}
              </p>
            </motion.div>
          )
        })}
      </div>
    </motion.section>
  )
}

// ═══════════════════════════════════════════════════════════════════════
// 7 — Managed Security Review
// ═══════════════════════════════════════════════════════════════════════

function ManagedReview({ onCta, busyTier }: {
  onCta: (p: PlanDefinition) => void
  busyTier: PlanTier | null
}) {
  const plan = PLAN_DEFINITIONS.enterprise
  return (
    <motion.section className="mb-24" {...fadeUp}>
      <div
        className="relative rounded-[20px] p-8 sm:p-12 overflow-hidden"
        style={{
          background: 'linear-gradient(135deg, rgba(139,255,62,0.08) 0%, rgba(8,12,22,0.95) 60%)',
          border: '1px solid rgba(139,255,62,0.25)',
          boxShadow: '0 0 60px rgba(139,255,62,0.08)',
        }}
      >
        {/* Decorative glow */}
        <div className="absolute -top-32 -right-32 w-64 h-64 rounded-full pointer-events-none"
             style={{ background: 'radial-gradient(circle, rgba(139,255,62,0.18) 0%, transparent 70%)' }} />

        <div className="relative grid grid-cols-1 lg:grid-cols-5 gap-8 items-center">
          {/* Left — copy */}
          <div className="lg:col-span-3">
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 mb-4 rounded-full"
                 style={{ background: 'rgba(139,255,62,0.1)',
                          border: '1px solid rgba(139,255,62,0.25)' }}>
              <Award className="w-3 h-3" style={{ color: '#8BFF3E' }} />
              <span className="text-[10px] font-bold uppercase tracking-wider"
                    style={{ color: '#8BFF3E' }}>
                Managed Security Review · $129/mo
              </span>
            </div>

            <h3 className="text-3xl sm:text-4xl font-bold text-white tracking-tight mb-3">
              Human guidance when you need it.
            </h3>
            <p className="text-[15px] leading-relaxed mb-6"
               style={{ color: 'rgba(255,255,255,0.65)' }}>
              The scan is the easy part. Knowing which findings actually
              matter and how to fix them in your stack is harder. The
              Managed plan adds a real person — the WebHound founder — to
              that loop.
            </p>

            <ul className="space-y-2.5 mb-6">
              {[
                { icon: Calendar,       text: 'Scheduled 1-on-1 virtual security review' },
                { icon: MessageSquare,  text: 'Live walkthrough of your scan results' },
                { icon: UserCheck,      text: 'Help prioritizing what to fix first' },
                { icon: Activity,       text: 'Remediation guidance tailored to your stack' },
                { icon: Clock,          text: 'Priority support — replies in hours, not days' },
              ].map(i => (
                <li key={i.text}
                    className="flex items-start gap-2.5 text-[13.5px]"
                    style={{ color: 'rgba(255,255,255,0.85)' }}>
                  <i.icon className="w-4 h-4 flex-shrink-0 mt-0.5"
                          style={{ color: '#8BFF3E' }} />
                  {i.text}
                </li>
              ))}
            </ul>

            <button
              type="button"
              onClick={() => onCta(plan)}
              disabled={busyTier === 'enterprise'}
              className="inline-flex items-center gap-2 px-6 py-3 rounded-[10px] text-[14px] font-semibold transition-all hover:brightness-110 disabled:opacity-50"
              style={{ background: '#8BFF3E', color: '#020617' }}
            >
              {busyTier === 'enterprise' ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <>Get Managed Review <ArrowRight className="w-4 h-4" /></>
              )}
            </button>
          </div>

          {/* Right — meeting visual */}
          <div className="lg:col-span-2">
            <div className="rounded-[14px] p-5"
                 style={{
                   background: 'rgba(8,12,22,0.7)',
                   border: '1px solid rgba(255,255,255,0.08)',
                 }}>
              <div className="flex items-center gap-2 mb-4">
                <Calendar className="w-4 h-4" style={{ color: '#8BFF3E' }} />
                <span className="text-[11px] font-bold uppercase tracking-wider"
                      style={{ color: 'rgba(255,255,255,0.5)' }}>
                  Sample review agenda
                </span>
              </div>
              <ul className="space-y-3 text-[12.5px]">
                {[
                  { time: '0:00', text: 'Welcome + overview of latest scan' },
                  { time: '0:05', text: 'Walk through critical & high findings' },
                  { time: '0:20', text: 'Prioritization — what to fix this week' },
                  { time: '0:30', text: 'Stack-specific remediation steps' },
                  { time: '0:45', text: 'Q&A and monitoring config tuning' },
                ].map(item => (
                  <li key={item.time}
                      className="flex items-start gap-3 pb-3"
                      style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <span className="font-mono text-[11px] flex-shrink-0 mt-0.5"
                          style={{ color: 'rgba(139,255,62,0.7)' }}>
                      {item.time}
                    </span>
                    <span style={{ color: 'rgba(255,255,255,0.78)' }}>{item.text}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </motion.section>
  )
}

// ═══════════════════════════════════════════════════════════════════════
// 8 — FAQ
// ═══════════════════════════════════════════════════════════════════════

const FAQS = [
  {
    q: 'What does the free scan include?',
    a: 'One limited scan on one website. You see headline findings — severity, category, and a short explanation — but advanced engines (third-party analysis, threat-intel lookups, deep crawl) and continuous monitoring are off.',
  },
  {
    q: 'What is continuous monitoring?',
    a: 'Instead of one snapshot, WebHound rescans your site on a schedule — daily on every paid plan. When something new shows up — a new finding, a regression, an expired cert — we tell you.',
  },
  {
    q: 'Can I cancel anytime?',
    a: 'Yes. One click in the billing portal. No retention call, no contract. You keep access until the end of the period you already paid for.',
  },
  {
    q: 'Does WebHound fix vulnerabilities for me?',
    a: 'No — WebHound identifies risks and provides remediation guidance. Fixes happen in your codebase, your DNS, and your server config. On the Managed Review plan we walk through exactly what to change and why.',
  },
  {
    q: 'What is included in the virtual security review?',
    a: 'A scheduled 1-on-1 session where we walk through your latest scan, prioritize findings, and give you stack-specific remediation steps. Typically 30–60 minutes, billed monthly as part of the $129 plan.',
  },
  {
    q: 'How often are websites rescanned?',
    a: 'Free is manual only. Every paid plan — Pro, Shield, and Managed Review — rescans daily. You can also kick off ad-hoc scans anytime up to your monthly limit.',
  },
  {
    q: 'What types of risks can WebHound detect?',
    a: 'SSL/TLS misconfigurations, missing security headers, DNS risks (dangling subdomains, missing SPF/DMARC), outdated technologies with known CVEs, suspicious third-party scripts, exposed admin paths, weak cookie flags, and more — across the 12 specialized engines.',
  },
]

function FAQ() {
  return (
    <motion.section className="mb-24" {...fadeUp}>
      <SectionHeading
        eyebrow="FAQ"
        title="Common questions"
        body="If we missed yours, email support@webhoundsecurity.com."
      />
      <div className="max-w-3xl mx-auto space-y-2">
        {FAQS.map(f => (
          <details key={f.q}
                   className="group rounded-[10px] px-5 py-4 transition-colors"
                   style={{
                     background: 'rgba(255,255,255,0.02)',
                     border: '1px solid rgba(255,255,255,0.06)',
                   }}>
            <summary className="text-[13.5px] font-semibold text-white cursor-pointer list-none flex items-center justify-between gap-3">
              <span>{f.q}</span>
              <ArrowRight className="w-3.5 h-3.5 flex-shrink-0 transition-transform group-open:rotate-90"
                          style={{ color: 'rgba(255,255,255,0.4)' }} />
            </summary>
            <p className="text-[13px] mt-3 leading-relaxed"
               style={{ color: 'rgba(255,255,255,0.6)' }}>
              {f.a}
            </p>
          </details>
        ))}
      </div>
    </motion.section>
  )
}

// ═══════════════════════════════════════════════════════════════════════
// 9 — Final CTA
// ═══════════════════════════════════════════════════════════════════════

function FinalCta() {
  return (
    <motion.section className="text-center" {...fadeUp}>
      <div className="rounded-[20px] py-12 px-6"
           style={{
             background: 'linear-gradient(180deg, rgba(139,255,62,0.05) 0%, rgba(8,12,22,0.95) 100%)',
             border: '1px solid rgba(139,255,62,0.18)',
           }}>
        <h2 className="text-3xl sm:text-4xl font-bold text-white tracking-tight mb-3">
          Start monitoring your website today.
        </h2>
        <p className="text-[15px] mb-7 max-w-xl mx-auto"
           style={{ color: 'rgba(255,255,255,0.55)' }}>
          One free scan to see what we find. Upgrade only when you want
          continuous monitoring.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-6">
          <Link href="/register"
                className="inline-flex items-center justify-center gap-2 px-7 py-3.5 rounded-[10px] text-[14px] font-semibold transition-all hover:brightness-110"
                style={{ background: '#8BFF3E', color: '#020617' }}>
            Run Free Scan
            <ArrowRight className="w-4 h-4" />
          </Link>
          <a href="#plans"
             className="inline-flex items-center justify-center gap-2 px-7 py-3.5 rounded-[10px] text-[14px] font-semibold text-white transition-all hover:bg-white/[0.06]"
             style={{ background: 'rgba(255,255,255,0.04)',
                      border: '1px solid rgba(255,255,255,0.12)' }}>
            Compare Plans
          </a>
        </div>
        <p className="text-[11.5px] max-w-xl mx-auto leading-relaxed"
           style={{ color: 'rgba(255,255,255,0.35)' }}>
          WebHound helps identify risks and provide remediation guidance,
          but no security platform can guarantee complete protection.
        </p>
      </div>
    </motion.section>
  )
}

// ═══════════════════════════════════════════════════════════════════════
// Shared bits
// ═══════════════════════════════════════════════════════════════════════

function SectionHeading({ eyebrow, title, body }: {
  eyebrow: string; title: string; body?: string
}) {
  return (
    <div className="text-center max-w-2xl mx-auto mb-10">
      <div className="text-[10px] font-bold uppercase tracking-[0.2em] mb-3"
           style={{ color: '#8BFF3E' }}>
        {eyebrow}
      </div>
      <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight mb-3">
        {title}
      </h2>
      {body && (
        <p className="text-[14px] leading-relaxed"
           style={{ color: 'rgba(255,255,255,0.55)' }}>
          {body}
        </p>
      )}
    </div>
  )
}
