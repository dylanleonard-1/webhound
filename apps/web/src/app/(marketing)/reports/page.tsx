'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import type { LucideIcon } from 'lucide-react'
import Link from 'next/link'
import {
  FileText, Download, Code2, LayoutDashboard, Braces,
  ArrowRight, CheckCircle, AlertTriangle, Shield,
  BarChart2, Layers, Globe, Activity, Search, Cpu,
  Briefcase, TrendingDown, ClipboardCheck, Star,
  XCircle, BookOpen, User, Code, Eye,
} from 'lucide-react'

// ── Data ─────────────────────────────────────────────────────────────────────

const REPORT_CONTENTS = [
  { icon: BarChart2,     label: 'Risk score',           desc: 'Composite score from 0–100 based on severity-weighted findings.' },
  { icon: Layers,        label: 'Grouped findings',     desc: 'Issues organized by engine, category, and fix priority — not a flat list.' },
  { icon: AlertTriangle, label: 'Affected URLs',        desc: 'Exact pages where each issue was detected, with scan evidence.' },
  { icon: BookOpen,      label: 'Remediation guidance', desc: 'Plain-English fix steps for every finding, with code examples where applicable.' },
  { icon: Cpu,           label: 'Engine diagnostics',   desc: 'Per-engine timing, finding counts, and status from all 12 scan engines.' },
  { icon: Globe,         label: 'External domain map',  desc: 'Every third-party domain your site contacted, categorized by type.' },
  { icon: Activity,      label: 'WADE anomaly summary', desc: 'Behavioral baseline comparison, anomaly score, and change highlights.' },
  { icon: Search,        label: 'Scan metadata',        desc: 'Timestamp, profile used, pages crawled, and scan duration.' },
]

interface ReportFormat {
  icon: LucideIcon; label: string; ext: string; audience: string
  reason: string; when: string; live: boolean
}

const FORMATS: ReportFormat[] = [
  { icon: LayoutDashboard, label: 'Dashboard View', ext: 'Interactive', audience: 'Everyone', reason: 'Full interactive results with expandable findings, filtering, and WADE analysis.', when: 'Default — available immediately after every scan.', live: true },
  { icon: Code2,           label: 'SARIF',          ext: '.sarif',      audience: 'Security engineers & CI pipelines', reason: 'Industry-standard Static Analysis Results Interchange Format.', when: 'Integrating with GitHub Code Scanning, Azure DevOps, or security toolchains.', live: true },
  { icon: Download,        label: 'CSV',            ext: '.csv',        audience: 'Project managers & analysts', reason: 'Tabular export for spreadsheets, custom pivot analysis, and ticket creation.', when: 'Creating tickets in Jira, Linear, or Notion from scan findings.', live: true },
  { icon: FileText,        label: 'Markdown',       ext: '.md',         audience: 'Developers & technical leads', reason: 'Human-readable report ready to paste into wikis, PR descriptions, or emails.', when: 'Sharing findings in GitHub, Notion, Confluence, or Slack.', live: true },
  { icon: Braces,          label: 'JSON Export',    ext: '.json',       audience: 'Developers building integrations', reason: 'Raw structured scan result for custom tooling, dashboards, or data pipelines.', when: 'Building automated workflows or feeding results into your own systems.', live: false },
]

const BIZ_FINDINGS = [
  { title: 'Plain-English summaries',  desc: 'Every finding is explained in business-friendly language — not just the CVE ID or header name.' },
  { title: '"Why this matters"',       desc: 'Each issue includes a clear explanation of the real-world risk it creates for your users and site.' },
  { title: '"How to fix" guidance',    desc: 'Concrete remediation steps, with code examples where applicable, so developers can act immediately.' },
  { title: 'Affected pages listed',   desc: 'See exactly which URLs triggered each finding — no manual cross-referencing needed.' },
  { title: 'Confidence and evidence', desc: 'Each finding shows confidence level and the evidence that triggered it, so you can judge severity yourself.' },
  { title: 'Fix-priority ordering',   desc: 'Findings are ranked by severity and impact so teams know what to address first.' },
]

const DEV_ITEMS = [
  { title: 'Engine diagnostics',    desc: 'Per-engine timing, status, and finding count — so you know exactly what ran and what it found.' },
  { title: 'Raw evidence preview',  desc: 'See the extracted artifacts (headers, script URLs, form targets) that triggered each finding.' },
  { title: 'Finding IDs',           desc: 'Every finding has a stable ID for referencing across scans, exports, and internal ticket systems.' },
  { title: 'SARIF & CSV export',    desc: 'Export in formats compatible with GitHub Code Scanning, Azure DevOps, Jira, and Linear.' },
  { title: 'Grouped by engine',     desc: 'Results are structured by scan engine — easy to filter to the categories you care about.' },
  { title: 'CI pipeline ready',     desc: 'SARIF output is designed for automated security gates in CI/CD workflows.' },
]

const AGENCY_ITEMS = [
  { icon: FileText,       title: 'Client-ready reports',        desc: 'Export and share scan results in Markdown or CSV. Clear enough to hand directly to a client or stakeholder.' },
  { icon: TrendingDown,   title: 'Track security improvements', desc: 'Run monthly scans and compare risk scores over time to show documented security progress.' },
  { icon: ClipboardCheck, title: 'Monitoring documentation',    desc: 'Evidence that your agency is actively monitoring client sites — useful for SLA reporting and account reviews.' },
  { icon: Star,           title: 'Professional deliverables',   desc: 'Position WebHound reports as a premium deliverable — a regular security audit clients expect and value.' },
]

const SAFETY_POINTS = [
  { ok: true,  text: 'Reports are based on passive, read-only scan data.' },
  { ok: true,  text: 'Findings indicate areas for review — not confirmed exploitable vulnerabilities.' },
  { ok: true,  text: 'False positives and false negatives are possible in any automated scan.' },
  { ok: false, text: 'WebHound reports are not a substitute for professional penetration testing.' },
  { ok: false, text: 'No exploitation, brute-force, or destructive testing is performed.' },
  { ok: false, text: "Reports should not be generated for sites you don't own or aren't authorized to test." },
]

const PERSONAS = [
  {
    icon: User, role: 'Business Owner', color: 'text-accent-green', bg: 'bg-accent-green/10',
    desc: 'Plain-English summaries — no jargon required.',
    points: ['Risk score in plain English', '"Why it matters" for every finding', 'Priority-ordered action list'],
  },
  {
    icon: Code, role: 'Developer', color: 'text-accent-blue', bg: 'bg-accent-blue/10',
    desc: 'SARIF export and CI-ready structured data.',
    points: ['SARIF for GitHub Code Scanning', 'Engine diagnostics & raw evidence', 'Finding IDs for ticket tracking'],
  },
  {
    icon: Eye, role: 'Security Auditor', color: 'text-purple-400', bg: 'bg-purple-500/10',
    desc: 'Grouped findings with evidence and confidence scores.',
    points: ['Grouped by engine & category', 'Confidence level per finding', 'WADE anomaly timeline'],
  },
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

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2 text-[11px] font-semibold text-accent-green uppercase tracking-widest mb-4">
      <span className="w-4 h-px bg-accent-green/50" />
      {children}
      <span className="w-4 h-px bg-accent-green/50" />
    </span>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ReportsPage() {
  const engineRef = useRef(null)
  const engineInView = useInView(engineRef, { once: true, margin: '-60px' })

  return (
    <div className="bg-[#0B0F19]">

      {/* ── Hero ──────────────────────────────────────────────────────────── */}
      <section className="relative pt-10 pb-20 px-5 text-center overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[700px] h-[500px] bg-accent-green/[0.055] rounded-full blur-3xl pointer-events-none" />
        <div className="absolute top-10 left-1/2 -translate-x-1/2 w-[400px] h-[250px] bg-accent-blue/[0.04] rounded-full blur-3xl pointer-events-none" />

        {/* Floating format chips */}
        {[
          { label: 'SARIF', x: '-36%', delay: 0,   duration: 4.3 },
          { label: 'CSV',   x: '-18%', delay: 0.9, duration: 3.8 },
          { label: 'MD',    x: '18%',  delay: 0.5, duration: 4.6 },
          { label: 'JSON',  x: '36%',  delay: 1.3, duration: 4.1 },
        ].map(({ label, x, delay, duration }) => (
          <motion.div key={label}
            style={{ position: 'absolute', top: '44px', left: '50%', translateX: x }}
            animate={{ y: [0, -10, 0] }} transition={{ duration, delay, repeat: Infinity, ease: 'easeInOut' }}
            className="px-2.5 py-1 rounded-full border border-accent-green/20 bg-accent-green/[0.06] text-xs font-mono text-accent-green/70 pointer-events-none">
            {label}
          </motion.div>
        ))}

        <div className="relative max-w-3xl mx-auto mt-12">
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/25 bg-accent-green/[0.06] mb-6">
            <FileText className="w-3.5 h-3.5 text-accent-green" />
            <span className="text-xs font-semibold text-accent-green tracking-wide">Professional Security Reports</span>
          </motion.div>

          <motion.h1 initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.55, delay: 0.1 }}
            className="text-4xl sm:text-5xl font-semibold text-white tracking-tight leading-[1.1] mb-5">
            Reports your team can{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-accent-green to-accent-blue">
              actually understand.
            </span>
          </motion.h1>

          <motion.p initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.2 }}
            className="text-base sm:text-lg text-gray-400 leading-relaxed mb-8 max-w-2xl mx-auto">
            WebHound turns passive scan data into grouped findings, severity summaries,
            remediation guidance, engine diagnostics, WADE anomaly summaries, and exportable
            reports for business owners, developers, and agencies.
          </motion.p>

          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.3 }}
            className="flex flex-col sm:flex-row justify-center gap-3">
            <Link href="/dashboard" className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors">
              View Sample Report<ArrowRight className="w-4 h-4" />
            </Link>
            <Link href="/dashboard" className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors">
              Start Free Scan
            </Link>
          </motion.div>
        </div>
      </section>

      {/* ── Report overview ───────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <FadeUp><SectionLabel>What's Included</SectionLabel></FadeUp>
            <FadeUp delay={0.1}><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Every scan generates a complete report</h2></FadeUp>
            <FadeUp delay={0.15}><p className="text-gray-400 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">No incomplete summaries or hidden details. Every section of a WebHound report is designed to give you the full picture.</p></FadeUp>
          </div>
          <motion.div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4" variants={staggerContainer} initial="hidden" whileInView="show" viewport={{ once: true, margin: '-60px' }}>
            {REPORT_CONTENTS.map(({ icon: Icon, label, desc }) => (
              <motion.div key={label} variants={staggerItem} whileHover={{ y: -3, scale: 1.01 }} transition={{ duration: 0.2 }}
                className="rounded-xl border border-white/[0.07] bg-[#111827] p-5 hover:border-accent-green/20 transition-colors group cursor-default">
                <div className="w-9 h-9 rounded-lg bg-accent-green/10 flex items-center justify-center mb-3 group-hover:bg-accent-green/20 transition-colors">
                  <Icon className="w-4 h-4 text-accent-green" />
                </div>
                <h3 className="text-sm font-semibold text-white mb-1.5">{label}</h3>
                <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── Format cards ──────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <FadeUp><SectionLabel>Export Formats</SectionLabel></FadeUp>
            <FadeUp delay={0.1}><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Choose the format that fits your workflow</h2></FadeUp>
            <FadeUp delay={0.15}><p className="text-gray-400 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">Dashboard view is always available. Export to SARIF, CSV, or Markdown whenever you need a deliverable.</p></FadeUp>
          </div>
          <motion.div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5" variants={staggerContainer} initial="hidden" whileInView="show" viewport={{ once: true, margin: '-60px' }}>
            {FORMATS.map(({ icon: Icon, label, ext, audience, reason, when, live }) => (
              <motion.div key={label} variants={staggerItem} whileHover={{ y: -4, boxShadow: live ? '0 8px 32px rgba(139,255,62,0.07)' : '0 8px 24px rgba(0,0,0,0.3)' }}
                transition={{ duration: 0.2 }}
                className={`rounded-xl border p-6 flex flex-col ${live ? 'border-white/[0.07] bg-[#111827]' : 'border-white/[0.05] bg-[#0F1520]'}`}>
                <div className="flex items-start justify-between mb-4">
                  <div className="w-10 h-10 rounded-xl bg-accent-green/10 flex items-center justify-center">
                    <Icon className="w-5 h-5 text-accent-green" />
                  </div>
                  <div className="text-right">
                    {live
                      ? <motion.span animate={{ opacity: [1, 0.5, 1] }} transition={{ duration: 2, repeat: Infinity }}
                          className="text-[9px] font-semibold uppercase tracking-widest px-1.5 py-0.5 rounded border bg-accent-green/15 text-accent-green border-accent-green/20">Live</motion.span>
                      : <span className="text-[9px] font-semibold uppercase tracking-widest px-1.5 py-0.5 rounded border bg-white/[0.04] text-gray-500 border-white/[0.07]">Planned</span>
                    }
                  </div>
                </div>
                <div className="flex items-baseline gap-2 mb-1">
                  <h3 className="text-sm font-semibold text-white">{label}</h3>
                  <span className="text-[10px] font-mono text-gray-600">{ext}</span>
                </div>
                <p className="text-[10px] text-accent-green/60 font-semibold uppercase tracking-widest mb-3">{audience}</p>
                <p className="text-xs text-gray-400 leading-relaxed mb-3 flex-1">{reason}</p>
                <div className="border-t border-white/[0.05] pt-3">
                  <p className="text-[10px] text-gray-600 leading-relaxed"><span className="text-gray-500">Best for: </span>{when}</p>
                </div>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── Business-friendly findings ────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <div className="grid lg:grid-cols-2 gap-14 items-start">
            <FadeUp>
              <div>
                <SectionLabel>Business-Friendly</SectionLabel>
                <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Findings anyone can act on</h2>
                <p className="text-gray-400 leading-relaxed mb-6 text-sm sm:text-base">WebHound doesn't hand you a wall of CVE numbers and HTTP response codes. Every finding is explained in language that makes sense whether you're a business owner, a developer, or a project manager.</p>
                <ul className="space-y-3.5">
                  {BIZ_FINDINGS.map(({ title, desc }) => (
                    <li key={title} className="flex items-start gap-3">
                      <CheckCircle className="w-4 h-4 text-accent-green flex-shrink-0 mt-0.5" />
                      <div>
                        <span className="text-sm font-semibold text-white">{title}</span>
                        <p className="text-xs text-gray-500 leading-relaxed mt-0.5">{desc}</p>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            </FadeUp>

            {/* Sample finding card */}
            <FadeUp delay={0.15}>
              <div className="rounded-2xl border border-white/[0.08] bg-[#111827] overflow-hidden">
                <div className="px-5 py-3.5 border-b border-white/[0.06] bg-[#0D1520] flex items-center justify-between">
                  <span className="text-[10px] font-mono text-gray-500">Finding · Security Headers</span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400 border border-orange-500/25 font-mono">HIGH</span>
                </div>
                <div className="p-5 space-y-4">
                  <div>
                    <h4 className="text-sm font-semibold text-white mb-1">Missing Content-Security-Policy header</h4>
                    <p className="text-[10px] text-gray-600 font-mono">CSP_HEADER_MISSING · Confidence 96%</p>
                  </div>
                  <FadeUp delay={0.25}>
                    <div className="rounded-lg bg-[#0B0F19] border border-white/[0.05] p-3 space-y-2">
                      <div>
                        <p className="text-[9px] font-semibold text-accent-green/60 uppercase tracking-widest mb-1">Why it matters</p>
                        <p className="text-xs text-gray-400 leading-relaxed">Without CSP, browsers allow any inline script to execute on your pages, making your site vulnerable to cross-site scripting (XSS) attacks where malicious code could steal user data or hijack sessions.</p>
                      </div>
                      <FadeUp delay={0.35}>
                        <div>
                          <p className="text-[9px] font-semibold text-accent-green/60 uppercase tracking-widest mb-1">How to fix</p>
                          <p className="text-xs text-gray-400 leading-relaxed">Add a <code className="text-accent-green/80 text-[10px]">Content-Security-Policy</code> response header to your web server or CDN. Start with a report-only policy to understand your site's script requirements before enforcing.</p>
                        </div>
                      </FadeUp>
                    </div>
                  </FadeUp>
                  <div>
                    <p className="text-[9px] font-semibold text-gray-600 uppercase tracking-widest mb-1.5">Affected pages</p>
                    <div className="flex flex-wrap gap-1.5">
                      {['example.com', 'example.com/login', 'example.com/checkout'].map(url => (
                        <span key={url} className="text-[9px] font-mono text-gray-500 px-2 py-0.5 rounded bg-white/[0.04] border border-white/[0.06]">{url}</span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </FadeUp>
          </div>
        </div>
      </section>

      {/* ── Developer/security section ────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <div className="grid lg:grid-cols-2 gap-14 items-start">
            {/* Engine diagnostics mock */}
            <FadeUp className="order-2 lg:order-1">
              <div className="rounded-2xl border border-white/[0.08] bg-[#111827] overflow-hidden">
                <div className="px-5 py-3.5 border-b border-white/[0.06] bg-[#0D1520]">
                  <span className="text-[10px] font-mono text-gray-500">Engine Diagnostics · example.com · 2m 14s</span>
                </div>
                <motion.div ref={engineRef} className="p-4 space-y-1.5" variants={staggerContainer} initial="hidden" animate={engineInView ? 'show' : 'hidden'}>
                  {[
                    { name: 'Security Headers',    findings: 3, time: '0.4s' },
                    { name: 'CSP Analysis',        findings: 1, time: '0.2s' },
                    { name: 'TLS Checker',         findings: 0, time: '1.1s' },
                    { name: 'Cookie Scanner',      findings: 2, time: '0.3s' },
                    { name: 'JavaScript Analyzer', findings: 4, time: '8.2s' },
                    { name: 'Third-Party Domains', findings: 2, time: '0.9s' },
                    { name: 'Secret Scanner',      findings: 0, time: '5.3s' },
                    { name: 'WADE Baseline',       findings: 1, time: '0.6s' },
                  ].map(e => (
                    <motion.div key={e.name} variants={staggerItem}
                      className="grid grid-cols-[1fr_auto_auto_auto] gap-3 items-center rounded-lg bg-[#0B0F19] px-3 py-2">
                      <span className="text-[10px] text-gray-400 truncate">{e.name}</span>
                      <span className={`text-[9px] font-mono ${e.findings > 0 ? 'text-yellow-400' : 'text-gray-600'}`}>
                        {e.findings} {e.findings === 1 ? 'finding' : 'findings'}
                      </span>
                      <span className="text-[9px] font-mono text-gray-600">{e.time}</span>
                      <div className="w-1.5 h-1.5 rounded-full bg-accent-green flex-shrink-0" />
                    </motion.div>
                  ))}
                </motion.div>
                <div className="px-4 py-2.5 border-t border-white/[0.06] bg-[#0D1520] flex gap-3">
                  {['SARIF', 'CSV', 'MD'].map(f => (
                    <span key={f} className="text-[9px] font-mono text-accent-green/70 hover:text-accent-green cursor-pointer transition-colors hover:underline">↓ {f}</span>
                  ))}
                </div>
              </div>
            </FadeUp>

            <FadeUp delay={0.15} className="order-1 lg:order-2">
              <div>
                <SectionLabel>For Developers</SectionLabel>
                <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Built for technical teams too</h2>
                <p className="text-gray-400 leading-relaxed mb-6 text-sm sm:text-base">WebHound gives developers and security engineers the structured data they need to act on findings, integrate with existing tooling, and build security into release workflows.</p>
                <ul className="space-y-3.5">
                  {DEV_ITEMS.map(({ title, desc }) => (
                    <li key={title} className="flex items-start gap-3">
                      <CheckCircle className="w-4 h-4 text-accent-green flex-shrink-0 mt-0.5" />
                      <div>
                        <span className="text-sm font-semibold text-white">{title}</span>
                        <p className="text-xs text-gray-500 leading-relaxed mt-0.5">{desc}</p>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            </FadeUp>
          </div>
        </div>
      </section>

      {/* ── Before/After ──────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <FadeUp><SectionLabel>Before vs After</SectionLabel></FadeUp>
            <FadeUp delay={0.1}><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Raw findings vs WebHound reports</h2></FadeUp>
            <FadeUp delay={0.15}><p className="text-gray-400 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">Security data is only useful if people can act on it.</p></FadeUp>
          </div>

          <div className="relative grid sm:grid-cols-2 gap-5 items-start">
            {/* Before */}
            <motion.div initial={{ opacity: 0, x: -40 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true, margin: '-60px' }}
              transition={{ duration: 0.55, ease: [0.25, 0.46, 0.45, 0.94] }}
              className="rounded-2xl border border-red-500/15 bg-red-500/[0.02] overflow-hidden">
              <div className="px-5 py-3 border-b border-red-500/10 bg-[#0D1520] flex items-center gap-2">
                <XCircle className="w-3.5 h-3.5 text-red-400/70" />
                <span className="text-[10px] font-semibold text-red-400/70 uppercase tracking-widest">Without WebHound</span>
              </div>
              <div className="p-5 space-y-2 font-mono">
                {[
                  'HTTP/1.1 200 OK → Missing header: Content-Security-Policy',
                  'ssl_check: HSTS not in response headers',
                  'js_lint: eval() detected at offset 4821 in main.bundle.js',
                  'cookie: session_id → flags: [] (expected: HttpOnly, Secure)',
                  'dns: SPF record not found for domain',
                  'WARNING: Unknown domain script.example.io contacted',
                  '... 14 more raw findings',
                ].map((line, i) => (
                  <div key={i} className="text-[10px] text-gray-600 leading-relaxed border-l-2 border-red-500/10 pl-3">{line}</div>
                ))}
                <p className="text-[10px] text-gray-700 pt-2 italic">No grouping. No priority. No fix steps. No export.</p>
              </div>
            </motion.div>

            {/* VS badge */}
            <motion.div initial={{ opacity: 0, scale: 0.4 }} whileInView={{ opacity: 1, scale: 1 }} viewport={{ once: true, margin: '-60px' }}
              transition={{ duration: 0.4, delay: 0.5 }}
              className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-10 hidden sm:flex w-8 h-8 rounded-full bg-[#0B0F19] border border-white/[0.12] items-center justify-center">
              <span className="text-[9px] font-bold text-gray-500">VS</span>
            </motion.div>

            {/* After */}
            <motion.div initial={{ opacity: 0, x: 40 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true, margin: '-60px' }}
              transition={{ duration: 0.55, delay: 0.15, ease: [0.25, 0.46, 0.45, 0.94] }}
              className="rounded-2xl border border-accent-green/15 bg-accent-green/[0.02] overflow-hidden">
              <div className="px-5 py-3 border-b border-accent-green/10 bg-[#0D1520] flex items-center gap-2">
                <CheckCircle className="w-3.5 h-3.5 text-accent-green" />
                <span className="text-[10px] font-semibold text-accent-green uppercase tracking-widest">WebHound Report</span>
              </div>
              <motion.div className="p-5 space-y-3" variants={staggerContainer} initial="hidden" whileInView="show" viewport={{ once: true, margin: '-60px' }}>
                {[
                  { sev: 'HIGH',   color: 'text-orange-400 bg-orange-500/10 border-orange-500/25', category: 'Security Headers',    count: 3, fix: 'Add CSP, HSTS, and X-Frame-Options to your server config.' },
                  { sev: 'MEDIUM', color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/25', category: 'Cookie Security',       count: 2, fix: 'Set Secure and HttpOnly on session_id and auth cookies.' },
                  { sev: 'MEDIUM', color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/25', category: 'Third-Party Domains',   count: 1, fix: 'Review script.example.io — not in your known-good baseline.' },
                  { sev: 'LOW',    color: 'text-blue-400 bg-blue-500/10 border-blue-500/25',       category: 'DNS / Email Auth',      count: 1, fix: 'Add SPF record to prevent email spoofing from your domain.' },
                ].map(({ sev, color, category, count, fix }) => (
                  <motion.div key={category} variants={staggerItem} className="rounded-xl border border-white/[0.06] bg-[#111827] p-3">
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border font-semibold ${color}`}>{sev}</span>
                      <span className="text-xs font-semibold text-white">{category}</span>
                      <span className="text-[9px] text-gray-600 ml-auto">{count} {count === 1 ? 'issue' : 'issues'}</span>
                    </div>
                    <p className="text-[10px] text-gray-500 leading-relaxed">{fix}</p>
                  </motion.div>
                ))}
                <div className="flex gap-2 pt-1">
                  {['SARIF', 'CSV', 'MD'].map(f => (
                    <span key={f} className="text-[9px] font-mono text-accent-green/80 px-2 py-1 rounded bg-accent-green/10 border border-accent-green/15">↓ {f}</span>
                  ))}
                </div>
              </motion.div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ── Who reads WebHound reports ─────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <FadeUp><SectionLabel>Made For Everyone</SectionLabel></FadeUp>
            <FadeUp delay={0.1}><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Who reads WebHound reports</h2></FadeUp>
            <FadeUp delay={0.15}><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">Every role gets what they need — no translation required.</p></FadeUp>
          </div>
          <motion.div className="grid sm:grid-cols-3 gap-5" variants={staggerContainer} initial="hidden" whileInView="show" viewport={{ once: true, margin: '-60px' }}>
            {PERSONAS.map(({ icon: Icon, role, color, bg, desc, points }) => (
              <motion.div key={role} variants={staggerItem} whileHover={{ y: -3 }} transition={{ duration: 0.2 }}
                className="rounded-xl border border-white/[0.07] bg-[#111827] p-6">
                <div className={`w-10 h-10 rounded-xl ${bg} flex items-center justify-center mb-3`}>
                  <Icon className={`w-5 h-5 ${color}`} />
                </div>
                <h3 className={`text-sm font-semibold mb-1 ${color}`}>{role}</h3>
                <p className="text-xs text-gray-500 mb-3 leading-relaxed">{desc}</p>
                <ul className="space-y-1.5">
                  {points.map(p => (
                    <li key={p} className="flex items-start gap-2 text-xs text-gray-400">
                      <CheckCircle className={`w-3 h-3 flex-shrink-0 mt-0.5 ${color}`} />{p}
                    </li>
                  ))}
                </ul>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── Agency value ──────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <FadeUp><SectionLabel>For Agencies</SectionLabel></FadeUp>
            <FadeUp delay={0.1}><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Turn monitoring into a client deliverable</h2></FadeUp>
            <FadeUp delay={0.15}><p className="text-gray-400 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">Web agencies and freelancers can use WebHound reports as a professional monthly security deliverable — something clients can see and understand.</p></FadeUp>
          </div>
          <motion.div className="grid sm:grid-cols-2 gap-5" variants={staggerContainer} initial="hidden" whileInView="show" viewport={{ once: true, margin: '-60px' }}>
            {AGENCY_ITEMS.map(({ icon: Icon, title, desc }) => (
              <motion.div key={title} variants={staggerItem} whileHover={{ y: -3 }} transition={{ duration: 0.2 }}
                className="rounded-xl border border-white/[0.07] bg-[#111827] p-6 flex gap-4">
                <div className="w-10 h-10 rounded-xl bg-accent-green/10 flex items-center justify-center flex-shrink-0">
                  <Icon className="w-5 h-5 text-accent-green" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white mb-1.5">{title}</h3>
                  <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
                </div>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── Safety/disclaimer ─────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <FadeUp>
            <div className="rounded-2xl border border-white/[0.08] bg-[#111827] overflow-hidden">
              <div className="px-6 py-4 border-b border-white/[0.06] bg-[#0D1520] flex items-center gap-3">
                <Shield className="w-4 h-4 text-accent-green" />
                <span className="text-sm font-semibold text-white">Report Scope & Limitations</span>
              </div>
              <div className="p-6 grid sm:grid-cols-2 gap-3">
                {SAFETY_POINTS.map(({ ok, text }) => (
                  <div key={text} className="flex items-start gap-2.5">
                    {ok ? <CheckCircle className="w-4 h-4 text-accent-green flex-shrink-0 mt-0.5" />
                        : <AlertTriangle className="w-4 h-4 text-yellow-500/70 flex-shrink-0 mt-0.5" />}
                    <p className="text-xs text-gray-400 leading-relaxed">{text}</p>
                  </div>
                ))}
              </div>
              <div className="px-6 py-3.5 bg-[#0D1520] border-t border-white/[0.06]">
                <p className="text-xs text-gray-600 text-center">WebHound is a passive security monitoring tool, not a penetration testing service. For critical infrastructure, supplement WebHound with professional security assessment.</p>
              </div>
            </div>
          </FadeUp>
        </div>
      </section>

      {/* ── CTA ──────────────────────────────────────────────────────────── */}
      <section className="py-24 px-5 border-t border-white/[0.05]">
        <div className="max-w-2xl mx-auto text-center">
          <FadeUp>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/25 bg-accent-green/[0.06] mb-6">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
              <span className="text-xs font-semibold text-accent-green tracking-wide">Free to start</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Generate your first WebHound report.</h2>
            <p className="text-gray-400 mb-8 text-sm sm:text-base leading-relaxed max-w-lg mx-auto">Scan your website for free, get a full grouped report, and export in any format. No credit card. No installation.</p>
            <div className="flex flex-col sm:flex-row justify-center gap-3">
              <Link href="/dashboard" className="inline-flex items-center justify-center gap-2 px-8 py-3.5 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors">
                Start Free Scan<ArrowRight className="w-4 h-4" />
              </Link>
              <Link href="/features" className="inline-flex items-center justify-center px-8 py-3.5 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors">
                View All Features
              </Link>
            </div>
            <div className="flex flex-wrap justify-center gap-x-6 gap-y-2 mt-8">
              {['Passive scanning', 'Grouped findings', 'Remediation guidance', 'SARIF · CSV · Markdown'].map(t => (
                <div key={t} className="flex items-center gap-1.5 text-xs text-gray-600">
                  <CheckCircle className="w-3 h-3 text-gray-700 flex-shrink-0" />{t}
                </div>
              ))}
            </div>
          </FadeUp>
        </div>
      </section>

    </div>
  )
}
