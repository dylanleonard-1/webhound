'use client'

import { useState, useRef } from 'react'
import { motion, AnimatePresence, useInView } from 'framer-motion'
import Link from 'next/link'
import {
  CheckCircle, ArrowRight, Minus, Shield,
  Calendar, Activity, Globe, FileText,
  Bell, Phone, Users, AlertTriangle, Plus,
} from 'lucide-react'

// ── Data ─────────────────────────────────────────────────────────────────────

interface Plan {
  name: string; price: string; period: string | null; badge: string | null
  tagline: string; bestFor: string; cta: string; href: string
  highlight: boolean; accent: 'default' | 'green' | 'blue'
  features: { text: string; note?: string }[]
}

const PLANS: Plan[] = [
  { name: 'Free Scan', price: '$0', period: null, badge: null, tagline: 'Try WebHound', bestFor: 'One-time security check', cta: 'Start Free Scan', href: '/register', highlight: false, accent: 'default', features: [{ text: '1 passive scan' }, { text: 'Basic risk score' }, { text: 'Limited findings preview' }, { text: 'Basic report preview' }, { text: 'No scheduled monitoring' }] },
  { name: 'Basic Monitoring', price: '$29', period: '/month', badge: null, tagline: 'Continuous protection', bestFor: 'Small business websites', cta: 'Join Waitlist', href: '/register', highlight: false, accent: 'default', features: [{ text: '1 monitored website' }, { text: 'Weekly passive scans' }, { text: 'Grouped findings' }, { text: 'Risk score history' }, { text: 'WADE baseline monitoring' }, { text: 'CSV & Markdown export' }, { text: 'Email alerts', note: 'Roadmap' }] },
  { name: 'Pro Monitoring', price: '$79', period: '/month', badge: 'Recommended', tagline: 'Full monitoring power', bestFor: 'Agencies and growing businesses', cta: 'Join Waitlist', href: '/register', highlight: true, accent: 'green', features: [{ text: 'Up to 5 monitored websites' }, { text: 'Weekly + on-demand scans' }, { text: 'Deep scan profile' }, { text: 'WADE anomaly history' }, { text: 'External domain tracking' }, { text: 'SARIF, CSV & Markdown export' }, { text: 'PDF reports', note: 'Roadmap' }, { text: 'Priority alerting' }] },
  { name: 'Managed', price: 'From $199', period: '/month', badge: 'White-glove', tagline: 'Help fixing issues too', bestFor: 'Non-technical business owners', cta: 'Contact Us', href: '/register', highlight: false, accent: 'blue', features: [{ text: 'Everything in Pro' }, { text: 'Monthly video review call' }, { text: 'Guided remediation support' }, { text: 'Configuration guidance' }, { text: 'Plugin & app risk review' }, { text: 'Plain-English explanations' }, { text: 'Custom site count' }] },
]

type Cell = 'yes' | 'no' | string
interface TableRow { label: string; free: Cell; basic: Cell; pro: Cell; managed: Cell }

const TABLE_ROWS: TableRow[] = [
  { label: 'Passive scan',             free: 'yes',    basic: 'yes',          pro: 'yes',          managed: 'yes' },
  { label: 'Scheduled monitoring',     free: 'no',     basic: 'Weekly',       pro: 'Weekly + daily', managed: 'Weekly + daily' },
  { label: 'WADE baseline comparison', free: 'no',     basic: 'yes',          pro: 'yes',          managed: 'yes' },
  { label: 'Monitored websites',       free: '1 scan', basic: '1',            pro: 'Up to 5',      managed: 'Custom' },
  { label: 'Grouped findings',         free: 'Limited',basic: 'yes',          pro: 'yes',          managed: 'yes' },
  { label: 'Engine diagnostics',       free: 'Limited',basic: 'yes',          pro: 'yes',          managed: 'yes' },
  { label: 'CSV / Markdown export',    free: 'no',     basic: 'yes',          pro: 'yes',          managed: 'yes' },
  { label: 'SARIF export',             free: 'no',     basic: 'no',           pro: 'yes',          managed: 'yes' },
  { label: 'PDF reports',              free: 'no',     basic: 'no',           pro: 'Roadmap',      managed: 'Roadmap' },
  { label: 'Alerts',                   free: 'no',     basic: 'Roadmap',      pro: 'Priority',     managed: 'yes' },
  { label: 'Human fix guidance',       free: 'no',     basic: 'no',           pro: 'no',           managed: 'yes' },
  { label: 'Video review call',        free: 'no',     basic: 'no',           pro: 'no',           managed: 'Monthly' },
]

const FAQS = [
  { q: 'Is WebHound a penetration test?', a: 'No. WebHound is a passive security monitoring tool. It reads publicly accessible content and checks response headers, certificates, cookies, and loaded scripts — exactly as a browser would. It does not exploit vulnerabilities, brute-force credentials, or perform destructive testing. For critical infrastructure, complement WebHound with professional penetration testing.' },
  { q: 'Do I need to own the website I scan?', a: "Yes. By using WebHound you confirm you own or are authorized to scan every website you add. Scanning websites you don't own or aren't authorized to test is a violation of our terms of service and may be illegal." },
  { q: 'Is scanning safe for my live website?', a: "Yes. WebHound's scanner is read-only. It fetches publicly accessible page content and resources without submitting forms, executing JavaScript on your server, or modifying anything on your site. Scheduled scans are rate-limited and safe to run continuously against production." },
  { q: 'What is WADE?', a: 'WADE stands for Website Anomaly Detection Engine. It creates a behavioral fingerprint of your website on the first scan, then compares each subsequent scan against that baseline. WADE flags meaningful changes — new third-party scripts, form action changes, header regressions, and structural DOM shifts — while filtering out CDN drift and minor variances.' },
  { q: 'Can you fix the issues for me?', a: 'The Managed plan includes guided remediation support, configuration guidance, and a monthly review call where we walk through findings together and help you understand what to prioritize. We do not directly modify your website, server configuration, or codebase — that remains the responsibility of you or your development team.' },
  { q: 'When will payments launch?', a: 'WebHound is currently in early access. Payments are not yet active. Joining the waitlist on any paid plan registers your interest and will notify you when billing opens. Early access pricing is subject to change.' },
  { q: 'Can web agencies monitor client websites?', a: 'Yes. Pro and Managed plans support multiple websites, making them suitable for agencies monitoring client sites. You must have authorization from each client to scan their websites. Client-specific reporting and multi-account features are on the roadmap.' },
]

// ── Animation helpers ─────────────────────────────────────────────────────────

function FadeUp({ children, delay = 0, className = '' }: { children: React.ReactNode; delay?: number; className?: string }) {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  return (
    <motion.div ref={ref} className={className}
      initial={{ opacity: 0, y: 24 }} animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.5, delay, ease: [0.25, 0.46, 0.45, 0.94] }}>
      {children}
    </motion.div>
  )
}

const staggerContainer = { hidden: {}, show: { transition: { staggerChildren: 0.08 } } }
const staggerItem = { hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0, transition: { duration: 0.45 } } }

// ── Sub-components ────────────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2 text-[11px] font-semibold text-accent-green uppercase tracking-widest mb-4">
      <span className="w-4 h-px bg-accent-green/50" />
      {children}
      <span className="w-4 h-px bg-accent-green/50" />
    </span>
  )
}

function TableCell({ value, isHighlight }: { value: Cell; isHighlight: boolean }) {
  const base = `text-xs px-4 py-3 text-center ${isHighlight ? 'bg-accent-green/[0.03]' : ''}`
  if (value === 'yes') return <td className={base}><CheckCircle className="w-4 h-4 text-accent-green mx-auto" /></td>
  if (value === 'no') return <td className={base}><Minus className="w-4 h-4 text-gray-700 mx-auto" /></td>
  return (
    <td className={`${base} ${value === 'Roadmap' ? 'text-yellow-500/70' : isHighlight ? 'text-gray-200 font-medium' : 'text-gray-400'}`}>
      {value}
    </td>
  )
}

function PlanCard({ plan, index }: { plan: Plan; index: number }) {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })
  return (
    <motion.div ref={ref}
      initial={{ opacity: 0, y: 32 }} animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.5, delay: index * 0.1, ease: [0.25, 0.46, 0.45, 0.94] }}
      whileHover={{ y: -4 }} className={`rounded-2xl border p-6 flex flex-col relative overflow-hidden ${
        plan.accent === 'green' ? 'border-accent-green/30 bg-accent-green/[0.04]'
        : plan.accent === 'blue' ? 'border-accent-blue/20 bg-accent-blue/[0.03]'
        : 'border-white/[0.07] bg-[#111827]'}`}>
      {plan.highlight && (
        <div className="absolute top-0 left-0 right-0 h-[2px] overflow-hidden">
          <motion.div className="h-full bg-gradient-to-r from-transparent via-accent-green to-transparent w-1/2"
            animate={{ x: ['-100%', '300%'] }} transition={{ duration: 2.5, repeat: Infinity, ease: 'linear' }} />
        </div>
      )}
      <div className="mb-5">
        <div className="flex items-start justify-between gap-3 mb-1.5">
          <p className={`text-[10px] font-semibold uppercase tracking-widest ${
            plan.accent === 'green' ? 'text-accent-green/70' : plan.accent === 'blue' ? 'text-accent-blue/70' : 'text-gray-600'}`}>
            {plan.tagline}
          </p>
          {plan.badge && (
            <motion.span animate={plan.highlight ? { opacity: [1, 0.6, 1] } : {}}
              transition={{ duration: 2, repeat: Infinity }}
              className={`text-[9px] font-semibold uppercase tracking-widest px-1.5 py-0.5 rounded border flex-shrink-0 ${
                plan.accent === 'green' ? 'bg-accent-green/20 text-accent-green border-accent-green/25'
                : 'bg-accent-blue/15 text-accent-blue border-accent-blue/20'}`}>
              {plan.badge}
            </motion.span>
          )}
        </div>
        <h2 className="text-base font-semibold text-white mb-3">{plan.name}</h2>
        <div className="flex items-baseline gap-1">
          <span className="text-3xl font-bold text-white">{plan.price}</span>
          {plan.period && <span className="text-sm text-gray-500">{plan.period}</span>}
        </div>
        <p className="text-[11px] text-gray-600 mt-1.5">Best for: {plan.bestFor}</p>
      </div>
      <motion.ul className="space-y-2 flex-1 mb-6" variants={staggerContainer} initial="hidden" animate={inView ? 'show' : 'hidden'}>
        {plan.features.map(f => (
          <motion.li key={f.text} variants={staggerItem} className="flex items-start gap-2 text-xs">
            <CheckCircle className={`w-3.5 h-3.5 flex-shrink-0 mt-0.5 ${
              plan.accent === 'green' ? 'text-accent-green' : plan.accent === 'blue' ? 'text-accent-blue' : 'text-gray-500'}`} />
            <span className="text-gray-300">{f.text}{f.note && <span className="ml-1 text-[9px] font-mono text-yellow-500/70">({f.note})</span>}</span>
          </motion.li>
        ))}
      </motion.ul>
      <Link href={plan.href} className={`inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-semibold transition-colors ${
        plan.accent === 'green' ? 'bg-accent-green text-app-bg hover:bg-accent-green-dim'
        : plan.accent === 'blue' ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/20 hover:bg-accent-blue/20'
        : 'border border-white/[0.12] text-gray-300 hover:border-white/20 hover:text-white'}`}>
        {plan.cta}<ArrowRight className="w-3.5 h-3.5" />
      </Link>
    </motion.div>
  )
}

function FaqItem({ q, a, isOpen, onToggle, index }: { q: string; a: string; isOpen: boolean; onToggle: () => void; index: number }) {
  return (
    <FadeUp delay={index * 0.05}>
      <div className="rounded-xl border border-white/[0.07] bg-[#111827] hover:border-white/[0.12] transition-colors overflow-hidden">
        <button onClick={onToggle} className="w-full text-left px-6 py-5 flex items-center justify-between gap-4">
          <h3 className="text-sm font-semibold text-white">{q}</h3>
          <motion.div animate={{ rotate: isOpen ? 45 : 0 }} transition={{ duration: 0.2 }} className="flex-shrink-0">
            <Plus className="w-4 h-4 text-accent-green" />
          </motion.div>
        </button>
        <AnimatePresence initial={false}>
          {isOpen && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.3, ease: [0.25, 0.46, 0.45, 0.94] }}
              className="overflow-hidden">
              <p className="text-xs text-gray-500 leading-relaxed px-6 pb-5 border-t border-white/[0.05]">{a}</p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </FadeUp>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function PricingPage() {
  const [openFaq, setOpenFaq] = useState<number | null>(null)
  const tableRef = useRef(null)
  const tableInView = useInView(tableRef, { once: true, margin: '-60px' })

  return (
    <div className="bg-[#0B0F19]">

      {/* ── Hero ──────────────────────────────────────────────────────────── */}
      <section className="relative pt-10 pb-20 px-5 text-center overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[700px] h-[500px] bg-accent-green/[0.06] rounded-full blur-3xl pointer-events-none" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[400px] h-[300px] bg-accent-blue/[0.04] rounded-full blur-3xl pointer-events-none" />

        <div className="relative max-w-3xl mx-auto mt-4">
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-yellow-500/30 bg-yellow-500/[0.06] mb-6">
            <AlertTriangle className="w-3 h-3 text-yellow-500" />
            <span className="text-xs font-semibold text-yellow-500/90 tracking-wide">Early access · Payments not yet active</span>
          </motion.div>

          <motion.h1 initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.55, delay: 0.1 }}
            className="text-4xl sm:text-5xl font-semibold text-white tracking-tight leading-[1.1] mb-5">
            Simple website security monitoring{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-accent-green to-accent-blue">
              for businesses that can't afford to miss a compromise.
            </span>
          </motion.h1>

          <motion.p initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.2 }}
            className="text-base sm:text-lg text-gray-400 leading-relaxed mb-8 max-w-2xl mx-auto">
            Start with a free passive scan, then monitor your website continuously with WADE-powered
            change detection, grouped findings, professional reports, and optional help fixing issues.
          </motion.p>

          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.3 }}
            className="flex flex-col sm:flex-row justify-center gap-3">
            <Link href="/dashboard" className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors">
              Start Free Scan<ArrowRight className="w-4 h-4" />
            </Link>
            <a href="#compare" className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors">
              Compare Plans
            </a>
          </motion.div>
        </div>
      </section>

      {/* ── Plan teaser strip ──────────────────────────────────────────────── */}
      <section className="py-8 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <div className="grid grid-cols-3 gap-4">
            {[
              { label: 'Free Scan',  metric: '$0',    desc: 'One-time passive scan with basic findings preview and risk score.' },
              { label: 'Monitored', metric: '$29–79', desc: 'Weekly automated scans, WADE comparison, grouped findings & exports.' },
              { label: 'Managed',   metric: '$199+',  desc: 'Everything + monthly review call and guided remediation support.' },
            ].map(({ label, metric, desc }, i) => (
              <FadeUp key={label} delay={i * 0.08}>
                <div className="rounded-xl border border-white/[0.07] bg-[#111827] p-4 text-center">
                  <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-widest mb-1">{label}</p>
                  <p className="text-xl font-bold text-white mb-1">{metric}</p>
                  <p className="text-[10px] text-gray-500 leading-relaxed">{desc}</p>
                </div>
              </FadeUp>
            ))}
          </div>
        </div>
      </section>

      {/* ── Pricing cards ─────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-6xl mx-auto">
          <FadeUp>
            <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/[0.04] px-5 py-3 flex items-center gap-3 mb-8 max-w-2xl mx-auto text-center justify-center">
              <AlertTriangle className="w-3.5 h-3.5 text-yellow-500 flex-shrink-0" />
              <p className="text-xs text-yellow-500/80">Early access pricing — subject to change after beta. Payments are not active yet. Register to join the waitlist.</p>
            </div>
          </FadeUp>
          <div className="grid sm:grid-cols-2 xl:grid-cols-4 gap-5">
            {PLANS.map((plan, i) => <PlanCard key={plan.name} plan={plan} index={i} />)}
          </div>
        </div>
      </section>

      {/* ── Comparison table ──────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]" id="compare">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <FadeUp><SectionLabel>Compare Plans</SectionLabel></FadeUp>
            <FadeUp delay={0.1}><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">What's included in each plan</h2></FadeUp>
          </div>
          <FadeUp delay={0.15}>
            <div className="overflow-x-auto rounded-xl border border-white/[0.07]">
              <table className="w-full min-w-[600px]">
                <thead className="sticky top-0 z-10">
                  <tr className="border-b border-white/[0.06] bg-[#0D1520]">
                    <th className="text-left px-5 py-3.5 text-[10px] font-semibold text-gray-500 uppercase tracking-widest w-1/3">Feature</th>
                    {[{ label: 'Free', highlight: false }, { label: 'Basic', highlight: false }, { label: 'Pro', highlight: true }, { label: 'Managed', highlight: false }].map(col => (
                      <th key={col.label} className={`text-center px-4 py-3.5 text-[10px] font-semibold uppercase tracking-widest ${col.highlight ? 'text-accent-green bg-accent-green/[0.05]' : 'text-gray-500'}`}>{col.label}</th>
                    ))}
                  </tr>
                </thead>
                <motion.tbody ref={tableRef} className="bg-[#111827] divide-y divide-white/[0.04]"
                  variants={staggerContainer} initial="hidden" animate={tableInView ? 'show' : 'hidden'}>
                  {TABLE_ROWS.map(row => (
                    <motion.tr key={row.label} variants={staggerItem} className="hover:bg-white/[0.015] transition-colors">
                      <td className="px-5 py-3 text-xs text-gray-400">{row.label}</td>
                      <TableCell value={row.free} isHighlight={false} />
                      <TableCell value={row.basic} isHighlight={false} />
                      <TableCell value={row.pro} isHighlight={true} />
                      <TableCell value={row.managed} isHighlight={false} />
                    </motion.tr>
                  ))}
                </motion.tbody>
              </table>
            </div>
          </FadeUp>
          <FadeUp delay={0.2}>
            <p className="text-xs text-gray-600 text-center mt-4">Rows marked <span className="text-yellow-500/70">Roadmap</span> are planned but not yet available.</p>
          </FadeUp>
        </div>
      </section>

      {/* ── Why paid monitoring ───────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <FadeUp><SectionLabel>Why Monitor Continuously</SectionLabel></FadeUp>
            <FadeUp delay={0.1}><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">One scan shows today. Monitoring catches what changes.</h2></FadeUp>
          </div>
          <motion.div className="grid sm:grid-cols-2 gap-5" variants={staggerContainer} initial="hidden" whileInView="show" viewport={{ once: true, margin: '-60px' }}>
            {[
              { icon: Calendar, title: 'Websites change between visits', desc: 'Plugin updates, CDN changes, and CMS upgrades happen silently. A weekly scan means you know within days, not months.' },
              { icon: Activity, title: 'WADE spots suspicious drift', desc: "WADE's baseline comparison catches new third-party scripts, changed form targets, and structural DOM shifts that a point-in-time scan misses entirely." },
              { icon: Globe, title: 'Third-party scripts update without notice', desc: 'Analytics, widgets, and ad SDKs push new versions that may introduce privacy issues, security gaps, or unexpected external connections.' },
              { icon: Shield, title: 'Security regressions are easy to miss', desc: 'A deploy that accidentally removes a CSP header or changes a cookie attribute is invisible without before/after comparison.' },
            ].map(({ icon: Icon, title, desc }) => (
              <motion.div key={title} variants={staggerItem} whileHover={{ y: -3, scale: 1.01 }} transition={{ duration: 0.2 }}
                className="flex gap-4 rounded-xl border border-white/[0.07] bg-[#111827] px-5 py-5">
                <div className="w-9 h-9 rounded-lg bg-accent-green/10 flex items-center justify-center flex-shrink-0">
                  <Icon className="w-4 h-4 text-accent-green" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white mb-1">{title}</h3>
                  <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
                </div>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── Managed service ───────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <FadeUp>
              <div>
                <SectionLabel>Managed Plan</SectionLabel>
                <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Help understanding — and addressing — what WebHound finds</h2>
                <p className="text-gray-400 leading-relaxed mb-5 text-sm sm:text-base">For non-technical business owners who want more than a report — a monthly review call where we walk through findings together, explain what matters, and give practical next steps.</p>
                <div className="space-y-3">
                  {[
                    { icon: Phone, text: 'Monthly video call to review current findings and priorities' },
                    { icon: FileText, text: 'Guided remediation support — we explain what to ask your developer' },
                    { icon: Shield, text: 'Configuration guidance for headers, DNS, cookies, and common CMS settings' },
                    { icon: Users, text: 'Plugin and app risk review based on detected third-party scripts' },
                    { icon: Bell, text: 'Plain-English explanations of every high and critical finding' },
                  ].map(({ icon: Icon, text }) => (
                    <div key={text} className="flex items-start gap-3">
                      <div className="w-7 h-7 rounded-lg bg-accent-blue/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                        <Icon className="w-3.5 h-3.5 text-accent-blue" />
                      </div>
                      <p className="text-sm text-gray-300 leading-relaxed">{text}</p>
                    </div>
                  ))}
                </div>
                <div className="mt-6 rounded-xl border border-yellow-500/15 bg-yellow-500/[0.03] p-4">
                  <p className="text-xs text-yellow-500/70 leading-relaxed">The Managed plan provides guided review and remediation support. We do not directly modify your website, server, or codebase — implementation responsibility remains with you or your development team.</p>
                </div>
              </div>
            </FadeUp>

            <FadeUp delay={0.15}>
              <motion.div className="rounded-2xl border border-accent-blue/20 bg-[#111827] p-7"
                animate={{ boxShadow: ['0 0 0 0 rgba(79,156,249,0)', '0 0 24px 2px rgba(79,156,249,0.08)', '0 0 0 0 rgba(79,156,249,0)'] }}
                transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}>
                <div className="flex items-center gap-3 mb-6">
                  <div className="w-10 h-10 rounded-xl bg-accent-blue/10 flex items-center justify-center">
                    <Phone className="w-5 h-5 text-accent-blue" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-white">Managed Plan</p>
                    <p className="text-xs text-gray-500">From $199/month · Custom pricing available</p>
                  </div>
                </div>
                <p className="text-sm text-gray-400 leading-relaxed mb-6">Ideal for business owners who want to stay informed about their website security without needing to understand technical details themselves.</p>
                <ul className="space-y-2 mb-6">
                  {['WordPress, Shopify, and custom site owners', 'Businesses in regulated industries', 'Local businesses with e-commerce', 'Non-technical founders with live products'].map(item => (
                    <li key={item} className="flex items-center gap-2 text-xs text-gray-400">
                      <CheckCircle className="w-3.5 h-3.5 text-accent-blue flex-shrink-0" />{item}
                    </li>
                  ))}
                </ul>
                <Link href="/dashboard" className="inline-flex w-full items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-accent-blue/15 text-accent-blue border border-accent-blue/20 font-semibold text-sm hover:bg-accent-blue/20 transition-colors">
                  Contact Us<ArrowRight className="w-4 h-4" />
                </Link>
              </motion.div>
            </FadeUp>
          </div>
        </div>
      </section>

      {/* ── FAQ ───────────────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-12">
            <FadeUp><SectionLabel>FAQ</SectionLabel></FadeUp>
            <FadeUp delay={0.1}><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Common questions</h2></FadeUp>
          </div>
          <div className="space-y-3">
            {FAQS.map(({ q, a }, i) => (
              <FaqItem key={q} q={q} a={a} index={i} isOpen={openFaq === i} onToggle={() => setOpenFaq(openFaq === i ? null : i)} />
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ──────────────────────────────────────────────────────────── */}
      <section className="py-24 px-5 border-t border-white/[0.05]">
        <div className="max-w-2xl mx-auto text-center">
          <FadeUp>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/25 bg-accent-green/[0.06] mb-6">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
              <span className="text-xs font-semibold text-accent-green tracking-wide">Free to start · No card required</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Start with a free scan. Upgrade when you're ready to monitor continuously.</h2>
            <p className="text-gray-400 mb-8 text-sm sm:text-base leading-relaxed max-w-lg mx-auto">One scan is free, always. Paid monitoring plans are on the roadmap — register now to join the waitlist and lock in early access pricing.</p>
            <div className="flex flex-col sm:flex-row justify-center gap-3">
              <Link href="/dashboard" className="inline-flex items-center justify-center gap-2 px-8 py-3.5 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors">
                Start Free Scan<ArrowRight className="w-4 h-4" />
              </Link>
              <a href="#compare" className="inline-flex items-center justify-center px-8 py-3.5 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors">
                Compare Plans
              </a>
            </div>
            <p className="text-xs text-gray-600 mt-6">Early access pricing · No payment required to get started · Pricing subject to change after beta</p>
          </FadeUp>
        </div>
      </section>

    </div>
  )
}
