'use client'

import { useRef, useState, useEffect } from 'react'
import Link from 'next/link'
import { motion, useInView, AnimatePresence } from 'framer-motion'
import {
  Shield, ShieldCheck, Lock, Globe, Eye, Code2, Search, Key,
  ClipboardList, Cpu, Activity, GitCompare, Server,
  ArrowRight, CheckCircle, XCircle, Zap,
  ScanLine, PlusCircle, Layers, BarChart2,
  Download, FileText, AlertTriangle,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

// ── Data ──────────────────────────────────────────────────────────────────────

interface ScanProfile {
  name: string; badge: string; useCase: string; depth: string; speed: string; note: string; highlight: boolean
}
const SCAN_PROFILES: ScanProfile[] = [
  { name: 'Quick', badge: 'Surface check', useCase: 'Fast sanity check before a deploy or after a change.', depth: '~5 pages', speed: '< 30 seconds', note: 'Homepage + key assets only.', highlight: false },
  { name: 'Standard', badge: 'Recommended', useCase: 'Full site scan for most use cases. Best balance of coverage and speed.', depth: '~25 pages', speed: '1–3 minutes', note: 'All engines active. Covers navigation links, forms, scripts, and assets.', highlight: true },
  { name: 'Deep', badge: 'Full audit', useCase: 'Pre-launch or quarterly security review. Maximum crawl depth.', depth: '~100 pages', speed: '5–10 minutes', note: 'Extended crawl with enhanced secret and path detection.', highlight: false },
  { name: 'Monitor', badge: 'WADE mode', useCase: 'Scheduled recurring scans that compare against a behavioral baseline.', depth: 'Configurable', speed: 'Background', note: 'WADE generates anomaly scores and alerts on meaningful changes.', highlight: false },
]

interface Engine { icon: LucideIcon; title: string; desc: string; detects: string }
const ENGINES: Engine[] = [
  { icon: Shield, title: 'Security Headers', desc: 'Analyzes HTTP response headers for browser-enforced security controls.', detects: 'Missing HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.' },
  { icon: ShieldCheck, title: 'CSP Analysis', desc: 'Deep inspection of Content-Security-Policy directives for unsafe patterns.', detects: 'unsafe-inline, unsafe-eval, wildcard sources, missing directives, report-uri misconfig.' },
  { icon: Lock, title: 'TLS Checker', desc: "Validates your site's certificate, cipher configuration, and HTTPS enforcement.", detects: 'Expired certs, weak ciphers, missing HSTS, non-HTTPS redirect chains.' },
  { icon: Server, title: 'DNS Checker', desc: 'Checks email authentication and DNS security records for your domain.', detects: 'Missing or invalid SPF, DKIM, DMARC, DNSSEC, and dangling DNS entries.' },
  { icon: Eye, title: 'Cookie Scanner', desc: 'Audits every cookie set by your site and flags missing security attributes.', detects: 'Cookies without Secure, HttpOnly, or SameSite. Session cookies accessible to JavaScript.' },
  { icon: Code2, title: 'JavaScript Analyzer', desc: 'Inspects inline scripts and loaded files for risky patterns without executing code.', detects: 'eval(), document.write, obfuscation, hardcoded credentials, dangerous DOM sinks.' },
  { icon: Globe, title: 'Third-Party Domains', desc: 'Maps every external source your site contacts and categorizes what they are.', detects: 'Unknown script domains, cross-domain iframes, external form actions, fetch/XHR destinations.' },
  { icon: Search, title: 'Sensitive Paths', desc: 'Probes common paths that are frequently left publicly accessible by accident.', detects: '.env, admin panels, phpinfo(), backup files, git metadata, debug endpoints.' },
  { icon: Key, title: 'Secret Scanner', desc: "Scans page source and loaded scripts for credential patterns that shouldn't be public.", detects: 'API keys, AWS credentials, JWT tokens, private keys, and common secret formats.' },
  { icon: ClipboardList, title: 'Form Risk', desc: 'Audits HTML forms for security issues including insecure submission targets.', detects: 'HTTP form actions, cross-domain POST targets, missing CSRF indicators.' },
  { icon: Cpu, title: 'Technology Detection', desc: 'Identifies frameworks, CMS platforms, and libraries in use on the page.', detects: 'Known outdated versions, exposed version strings, CMS-specific vulnerability indicators.' },
  { icon: GitCompare, title: 'WADE Baseline', desc: 'Compares the current scan against the established behavioral baseline.', detects: 'New external domains, new scripts, DOM structure shifts, new form targets, anomaly score.' },
]

const FLOW_STEPS = [
  { icon: PlusCircle, step: 1, title: 'Add your website', desc: 'Enter the URL. No DNS records, no server config, no agent installation needed.' },
  { icon: Layers, step: 2, title: 'Choose a scan profile', desc: 'Quick for fast checks, Standard for full coverage, Deep for audits, Monitor for WADE recurring scans.' },
  { icon: ScanLine, step: 3, title: 'Scanner crawls safely', desc: 'WebHound fetches linked pages and resources — read-only, never modifying anything it touches.' },
  { icon: Cpu, step: 4, title: 'Engines analyze the evidence', desc: 'All 12 engines run in parallel against the collected artifacts — headers, scripts, forms, cookies, DNS.' },
  { icon: BarChart2, step: 5, title: 'Findings are grouped', desc: 'Results are organized by engine, severity, and fix priority. Every finding includes context and guidance.' },
  { icon: FileText, step: 6, title: 'Reports and monitoring are generated', desc: 'Download SARIF, CSV, or Markdown. If WADE has a baseline, anomaly scores are computed automatically.' },
]

const SAFETY_POINTS = [
  { ok: true, text: 'Reads publicly accessible page content — exactly as a browser would' },
  { ok: true, text: 'Checks response headers, certificates, and DNS records' },
  { ok: true, text: 'Scans static HTML and loaded script files for patterns' },
  { ok: true, text: 'Safe to run continuously against live production sites' },
  { ok: false, text: 'Does not exploit vulnerabilities or probe for attack vectors' },
  { ok: false, text: 'Does not brute-force credentials or login endpoints' },
  { ok: false, text: 'Does not submit forms or execute JavaScript on your site' },
  { ok: false, text: 'Does not run load tests, fuzzing, or destructive operations' },
]

const LIVE_STATS = [
  { value: 12, suffix: '', label: 'Engines' },
  { value: 42000, suffix: '+', label: 'Checks' },
  { value: 3, suffix: ' min', label: 'Max Scan Time' },
  { value: 0, suffix: '', label: 'Passive Only', static: true },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function FadeUp({ children, delay = 0 }: { children: React.ReactNode; delay?: number }) {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  return (
    <motion.div ref={ref} initial={{ opacity: 0, y: 24 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.5, delay, ease: [0.25, 0.46, 0.45, 0.94] }}>
      {children}
    </motion.div>
  )
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2 text-[11px] font-semibold text-accent-green uppercase tracking-widest mb-4">
      <span className="w-4 h-px bg-accent-green/50" />
      {children}
      <span className="w-4 h-px bg-accent-green/50" />
    </span>
  )
}

function useCountUp(target: number, inView: boolean, duration = 1.2) {
  const [val, setVal] = useState(0)
  useEffect(() => {
    if (!inView) return
    let start: number | null = null
    const step = (ts: number) => {
      if (!start) start = ts
      const p = Math.min((ts - start) / (duration * 1000), 1)
      setVal(Math.floor(p * target))
      if (p < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [inView, target, duration])
  return val
}

// ── Terminal typing effect ────────────────────────────────────────────────────

function TerminalHero() {
  const url = 'https://example.com'
  const [typed, setTyped] = useState('')
  const [scanning, setScanning] = useState(false)
  const [done, setDone] = useState(false)

  useEffect(() => {
    let i = 0
    const t = setInterval(() => {
      i++
      setTyped(url.slice(0, i))
      if (i >= url.length) {
        clearInterval(t)
        setTimeout(() => setScanning(true), 400)
        setTimeout(() => { setScanning(false); setDone(true) }, 2800)
      }
    }, 55)
    return () => clearInterval(t)
  }, [])

  return (
    <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6, duration: 0.5 }}
      className="mx-auto max-w-md rounded-xl border border-white/[0.08] bg-[#0D1520] overflow-hidden mt-8 mb-4 text-left">
      <div className="flex items-center gap-1.5 px-3 py-2 border-b border-white/[0.06]">
        {['#f87171','#fbbf24','#4ade80'].map(c => <span key={c} className="w-2.5 h-2.5 rounded-full" style={{ background: c }} />)}
        <span className="text-[10px] text-gray-600 ml-1 font-mono">webhound — scanner</span>
      </div>
      <div className="px-4 py-3 font-mono text-xs">
        <div className="flex items-center gap-2 mb-1.5">
          <span className="text-accent-green/60">$</span>
          <span className="text-gray-300">webhound scan </span>
          <span className="text-accent-green">{typed}</span>
          <span className="w-[2px] h-3.5 bg-accent-green animate-pulse" />
        </div>
        <AnimatePresence>
          {scanning && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="flex items-center gap-2 text-yellow-400/80">
              <motion.span animate={{ opacity: [1, 0.3, 1] }} transition={{ repeat: Infinity, duration: 0.8 }}>●</motion.span>
              <span>SCANNING... passive mode active</span>
            </motion.div>
          )}
          {done && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-0.5">
              <div className="text-accent-green">✓ Crawled 24 pages · 12 engines complete</div>
              <div className="text-gray-500">Risk score: <span className="text-yellow-400">42 (Medium)</span> · 9 findings</div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  )
}

// ── Stat counter bar ──────────────────────────────────────────────────────────

function StatBar() {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true })
  const engines = useCountUp(12, inView, 0.8)
  const checks = useCountUp(42000, inView, 1.4)
  return (
    <div ref={ref} className="border-y border-white/[0.05] py-10 px-5">
      <div className="max-w-4xl mx-auto grid grid-cols-2 sm:grid-cols-4 gap-6 text-center">
        {[
          { val: engines, suffix: '', label: 'Engines' },
          { val: checks, suffix: '+', label: 'Checks' },
          { val: '< 3', suffix: ' min', label: 'Max Scan Time' },
          { val: '100%', suffix: '', label: 'Passive Only' },
        ].map(({ val, suffix, label }) => (
          <motion.div key={label} initial={{ opacity: 0, y: 12 }} animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.5 }}>
            <div className="text-2xl font-bold font-mono text-accent-green">
              {val.toLocaleString()}{suffix}
            </div>
            <div className="text-xs text-gray-500 mt-1">{label}</div>
          </motion.div>
        ))}
      </div>
    </div>
  )
}

// ── Animated risk circle ──────────────────────────────────────────────────────

function RiskCircle() {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true })
  const pct = useCountUp(42, inView, 1.2)
  const circ = 2 * Math.PI * 22
  return (
    <div ref={ref} className="flex items-center gap-4">
      <div className="relative w-14 h-14 flex items-center justify-center flex-shrink-0">
        <svg className="absolute inset-0 w-full h-full -rotate-90" viewBox="0 0 56 56">
          <circle cx="28" cy="28" r="22" stroke="#1F2937" strokeWidth="5" fill="none" />
          <circle cx="28" cy="28" r="22" stroke="#EAB308" strokeWidth="5" fill="none"
            strokeDasharray={`${circ * (pct / 100)} ${circ * (1 - pct / 100)}`}
            strokeLinecap="round" />
        </svg>
        <span className="text-base font-bold font-mono text-yellow-400">{pct}</span>
      </div>
      <div>
        <p className="text-sm font-semibold text-yellow-400">Medium Risk</p>
        <p className="text-[10px] text-gray-500 mt-0.5">Some gaps found. Worth fixing.</p>
      </div>
    </div>
  )
}

// ── Grid variants ─────────────────────────────────────────────────────────────

const container = { hidden: {}, show: { transition: { staggerChildren: 0.06 } } }
const gridItem = { hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0, transition: { duration: 0.45 } } }

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ScannerPage() {
  const [activeProfile, setActiveProfile] = useState(1)
  const enginesRef = useRef(null)
  const enginesInView = useInView(enginesRef, { once: true, margin: '-60px' })
  const resultsRef = useRef(null)
  const resultsInView = useInView(resultsRef, { once: true, margin: '-60px' })
  const safetyRef = useRef(null)
  const safetyInView = useInView(safetyRef, { once: true, margin: '-60px' })

  return (
    <div className="bg-[#0B0F19]">

      {/* ── Hero ──────────────────────────────────────────────────────────── */}
      <section className="relative pt-10 pb-10 px-5 text-center overflow-hidden">
        <motion.div className="absolute top-0 left-1/2 -translate-x-1/2 w-[700px] h-[400px] bg-accent-green/[0.05] rounded-full blur-3xl pointer-events-none"
          animate={{ opacity: [0.4, 0.7, 0.4] }} transition={{ repeat: Infinity, duration: 4, ease: 'easeInOut' }} />
        <div className="relative max-w-3xl mx-auto">
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/25 bg-accent-green/[0.06] mb-6">
            <Shield className="w-3.5 h-3.5 text-accent-green" />
            <span className="text-xs font-semibold text-accent-green tracking-wide">Passive · Safe · Authorized</span>
          </motion.div>

          <motion.h1 initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15, duration: 0.55 }}
            className="text-4xl sm:text-5xl font-semibold text-white tracking-tight leading-[1.1] mb-5">
            A passive website scanner{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-accent-green to-accent-blue">
              built for real-world monitoring.
            </span>
          </motion.h1>

          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3, duration: 0.5 }}
            className="text-base sm:text-lg text-gray-400 leading-relaxed mb-8 max-w-2xl mx-auto">
            WebHound checks your website for security weaknesses, risky scripts, exposed paths, weak
            browser protections, cookie issues, TLS/DNS problems, and suspicious changes — without
            exploit attempts or destructive testing.
          </motion.p>

          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.4, duration: 0.5 }}
            className="flex flex-col sm:flex-row justify-center gap-3 mb-4">
            <Link href="/dashboard"
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors">
              Start Free Scan <ArrowRight className="w-4 h-4" />
            </Link>
            <Link href="/reports"
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors">
              View Sample Report
            </Link>
          </motion.div>

          <TerminalHero />

          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.7, duration: 0.5 }}
            className="flex flex-wrap justify-center gap-x-8 gap-y-2">
            {[{ icon: Zap, text: 'Results in under 3 minutes' }, { icon: Shield, text: 'Never modifies your site' }, { icon: CheckCircle, text: 'Authorized targets only' }]
              .map(({ icon: Icon, text }) => (
                <div key={text} className="flex items-center gap-2 text-xs text-gray-500">
                  <Icon className="w-3.5 h-3.5 text-gray-600 flex-shrink-0" />{text}
                </div>
              ))}
          </motion.div>
        </div>
      </section>

      {/* ── Live stat bar ─────────────────────────────────────────────────── */}
      <StatBar />

      {/* ── Scan profiles ─────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <FadeUp>
            <div className="text-center mb-12">
              <SectionLabel>Scan Profiles</SectionLabel>
              <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Choose the right scan for the job</h2>
              <p className="text-gray-400 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">
                From quick pre-deploy checks to fully scheduled WADE monitoring — every scan is passive and safe.
              </p>
            </div>
          </FadeUp>

          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {SCAN_PROFILES.map((p, i) => {
              const isActive = activeProfile === i
              return (
                <motion.div key={p.name} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }} transition={{ delay: i * 0.08, duration: 0.45 }}
                  onClick={() => setActiveProfile(i)}
                  whileHover={{ y: -3, transition: { duration: 0.2 } }}
                  className="rounded-xl border p-5 flex flex-col cursor-pointer transition-all duration-200"
                  style={{
                    borderColor: isActive ? 'rgba(139,255,62,0.35)' : 'rgba(255,255,255,0.07)',
                    background: isActive ? 'rgba(139,255,62,0.06)' : '#111827',
                    opacity: !isActive && activeProfile !== -1 ? 0.7 : 1,
                    boxShadow: isActive ? '0 0 20px rgba(139,255,62,0.08)' : 'none',
                  }}>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-base font-semibold text-white">{p.name}</span>
                    <span className={`text-[9px] font-semibold uppercase tracking-widest px-1.5 py-0.5 rounded ${isActive || p.highlight ? 'bg-accent-green/20 text-accent-green' : 'bg-white/[0.06] text-gray-500'}`}>
                      {p.badge}
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed mb-4 flex-1">{p.useCase}</p>
                  <div className="space-y-1.5 border-t border-white/[0.05] pt-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-gray-600">Depth</span>
                      <span className="text-[10px] text-gray-300 font-mono">{p.depth}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-gray-600">Speed</span>
                      <span className="text-[10px] text-gray-300 font-mono">{p.speed}</span>
                    </div>
                  </div>
                  <AnimatePresence>
                    {isActive && (
                      <motion.p initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                        className="text-[10px] text-accent-green/70 leading-relaxed mt-3 border-t border-accent-green/10 pt-2">
                        {p.note}
                      </motion.p>
                    )}
                  </AnimatePresence>
                </motion.div>
              )
            })}
          </div>
        </div>
      </section>

      {/* ── Engine grid ───────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-6xl mx-auto">
          <FadeUp>
            <div className="text-center mb-12">
              <SectionLabel>Scan Engines</SectionLabel>
              <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">12 engines. Every scan.</h2>
              <p className="text-gray-400 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">
                Each engine runs in parallel, analyzing a specific slice of your site's security posture.
              </p>
            </div>
          </FadeUp>

          <motion.div ref={enginesRef} variants={container} initial="hidden" animate={enginesInView ? 'show' : 'hidden'}
            className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {ENGINES.map(({ icon: Icon, title, desc, detects }) => (
              <motion.div key={title} variants={gridItem}
                whileHover={{ y: -3, transition: { duration: 0.2 } }}
                className="rounded-xl border bg-[#111827] p-5 group transition-all duration-200"
                style={{ borderColor: 'rgba(255,255,255,0.07)' }}
                onHoverStart={e => { (e.currentTarget as HTMLElement).style.borderColor = 'rgba(139,255,62,0.25)' }}
                onHoverEnd={e => { (e.currentTarget as HTMLElement).style.borderColor = 'rgba(255,255,255,0.07)' }}>
                <div className="flex items-start gap-3 mb-3">
                  <div className="w-8 h-8 rounded-lg bg-accent-green/10 flex items-center justify-center flex-shrink-0 group-hover:bg-accent-green/15 transition-colors">
                    <Icon className="w-3.5 h-3.5 text-accent-green" />
                  </div>
                  <h3 className="text-sm font-semibold text-white leading-tight pt-1">{title}</h3>
                </div>
                <p className="text-xs text-gray-400 leading-relaxed mb-2.5">{desc}</p>
                <div className="rounded-lg bg-[#0B0F19] border border-white/[0.05] px-2.5 py-2">
                  <p className="text-[10px] text-gray-600 font-mono leading-relaxed">
                    <span className="text-accent-green/50">Detects: </span>{detects}
                  </p>
                </div>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── Passive safety ────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <FadeUp>
            <div className="text-center mb-12">
              <SectionLabel>Safety Model</SectionLabel>
              <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">What we do — and what we never do</h2>
              <p className="text-gray-400 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">
                WebHound's scanner is designed to be safe on any live site at any time.
              </p>
            </div>
          </FadeUp>

          <div ref={safetyRef} className="rounded-2xl border border-white/[0.08] bg-[#111827] overflow-hidden">
            <div className="grid sm:grid-cols-2">
              <div className="p-6 border-b sm:border-b-0 sm:border-r border-white/[0.06]">
                <div className="flex items-center gap-2 mb-5">
                  <div className="w-6 h-6 rounded-full bg-accent-green/15 flex items-center justify-center">
                    <CheckCircle className="w-3.5 h-3.5 text-accent-green" />
                  </div>
                  <span className="text-sm font-semibold text-white">What WebHound does</span>
                </div>
                <ul className="space-y-3">
                  {SAFETY_POINTS.filter(p => p.ok).map((p, i) => (
                    <motion.li key={p.text} initial={{ opacity: 0, x: -12 }}
                      animate={safetyInView ? { opacity: 1, x: 0 } : {}}
                      transition={{ delay: i * 0.1, duration: 0.4 }}
                      className="flex items-start gap-2.5">
                      <motion.div animate={safetyInView ? { scale: [0, 1.2, 1] } : {}} transition={{ delay: i * 0.1 + 0.2 }}>
                        <CheckCircle className="w-3.5 h-3.5 text-accent-green flex-shrink-0 mt-0.5" />
                      </motion.div>
                      <span className="text-xs text-gray-300 leading-relaxed">{p.text}</span>
                    </motion.li>
                  ))}
                </ul>
              </div>
              <div className="p-6">
                <div className="flex items-center gap-2 mb-5">
                  <div className="w-6 h-6 rounded-full bg-red-500/10 flex items-center justify-center">
                    <XCircle className="w-3.5 h-3.5 text-red-400" />
                  </div>
                  <span className="text-sm font-semibold text-white">What WebHound never does</span>
                </div>
                <ul className="space-y-3">
                  {SAFETY_POINTS.filter(p => !p.ok).map((p, i) => (
                    <motion.li key={p.text} initial={{ opacity: 0, x: 12 }}
                      animate={safetyInView ? { opacity: 1, x: 0 } : {}}
                      transition={{ delay: i * 0.1 + 0.05, duration: 0.4 }}
                      className="flex items-start gap-2.5">
                      <motion.div animate={safetyInView ? { scale: [0, 1.2, 1] } : {}} transition={{ delay: i * 0.1 + 0.25 }}>
                        <XCircle className="w-3.5 h-3.5 text-red-400/70 flex-shrink-0 mt-0.5" />
                      </motion.div>
                      <span className="text-xs text-gray-400 leading-relaxed">{p.text}</span>
                    </motion.li>
                  ))}
                </ul>
              </div>
            </div>
            <div className="px-6 py-3.5 bg-[#0D1520] border-t border-white/[0.06] text-center">
              <p className="text-xs text-gray-600">By using WebHound you confirm you own or are authorized to scan every target you add. Unauthorized scanning is a violation of our terms and may be illegal.</p>
            </div>
          </div>
        </div>
      </section>

      {/* ── Scan flow ─────────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <FadeUp>
            <div className="text-center mb-12">
              <SectionLabel>How It Works</SectionLabel>
              <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">From URL to report in minutes</h2>
              <p className="text-gray-400 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">No configuration, no agents, no infrastructure changes.</p>
            </div>
          </FadeUp>
          <div className="space-y-3">
            {FLOW_STEPS.map(({ icon: Icon, step, title, desc }) => (
              <FadeUp key={step} delay={step * 0.08}>
                <motion.div whileHover={{ x: 4, transition: { duration: 0.2 } }}
                  className="flex gap-5 rounded-xl border border-white/[0.07] bg-[#111827] px-6 py-5 hover:border-accent-green/15 transition-colors">
                  <div className="flex-shrink-0">
                    <motion.div className="w-12 h-12 rounded-xl bg-accent-green/10 border border-accent-green/15 flex items-center justify-center"
                      whileInView={{ boxShadow: ['0 0 0px rgba(139,255,62,0)', '0 0 16px rgba(139,255,62,0.2)', '0 0 0px rgba(139,255,62,0)'] }}
                      viewport={{ once: true }} transition={{ delay: step * 0.1, duration: 0.8 }}>
                      <Icon className="w-5 h-5 text-accent-green" />
                    </motion.div>
                  </div>
                  <div className="flex-1 min-w-0 py-1">
                    <div className="text-[10px] font-mono text-accent-green/50 uppercase tracking-widest mb-1">Step {step}</div>
                    <h3 className="text-sm font-semibold text-white mb-1">{title}</h3>
                    <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
                  </div>
                </motion.div>
              </FadeUp>
            ))}
          </div>
        </div>
      </section>

      {/* ── Results preview ───────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <FadeUp>
            <div className="text-center mb-12">
              <SectionLabel>Results</SectionLabel>
              <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">What you see after a scan</h2>
              <p className="text-gray-400 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">Every scan produces structured, actionable results — not a wall of raw data.</p>
            </div>
          </FadeUp>
          <motion.div ref={resultsRef} variants={container} initial="hidden" animate={resultsInView ? 'show' : 'hidden'}
            className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <motion.div variants={gridItem} className="rounded-xl border border-white/[0.07] bg-[#111827] p-5">
              <p className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-3">Risk Score</p>
              <RiskCircle />
            </motion.div>
            <motion.div variants={gridItem} className="rounded-xl border border-white/[0.07] bg-[#111827] p-5">
              <p className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-3">Findings by Severity</p>
              <div className="space-y-2">
                {[{ label: 'HIGH', count: 1, bar: 'w-1/5', c: 'bg-orange-500 text-orange-400' }, { label: 'MEDIUM', count: 3, bar: 'w-3/5', c: 'bg-yellow-500 text-yellow-400' }, { label: 'LOW', count: 5, bar: 'w-full', c: 'bg-blue-500 text-blue-400' }]
                  .map(({ label, count, bar, c }) => (
                    <div key={label} className="flex items-center gap-2.5">
                      <span className={`text-[9px] font-mono w-12 ${c.split(' ')[1]}`}>{label}</span>
                      <div className="flex-1 h-1.5 rounded-full bg-white/[0.05]">
                        <div className={`h-full rounded-full ${c.split(' ')[0]} opacity-60 ${bar}`} />
                      </div>
                      <span className="text-[10px] text-gray-400 font-mono w-3">{count}</span>
                    </div>
                  ))}
              </div>
            </motion.div>
            <motion.div variants={gridItem} className="rounded-xl border border-white/[0.07] bg-[#111827] p-5">
              <p className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-3">Engine Status</p>
              <div className="space-y-1.5">
                {[{ e: 'Security Headers', ok: true }, { e: 'CSP Analysis', ok: true }, { e: 'TLS Checker', ok: true }, { e: 'JavaScript Analyzer', ok: true }, { e: 'WADE Baseline', ok: true }]
                  .map(({ e, ok }) => (
                    <div key={e} className="flex items-center gap-2">
                      <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${ok ? 'bg-accent-green' : 'bg-red-400'}`} />
                      <span className="text-[10px] text-gray-400 truncate">{e}</span>
                    </div>
                  ))}
              </div>
            </motion.div>
            <motion.div variants={gridItem} className="rounded-xl border border-white/[0.07] bg-[#111827] p-5">
              <p className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-3">External Domains</p>
              <div className="space-y-1.5">
                {[{ d: 'cdn.jsdelivr.net', c: 'CDN' }, { d: 'analytics.google.com', c: 'Analytics' }, { d: 'unknown-tracker.io', c: 'Unknown' }]
                  .map(({ d, c }) => (
                    <div key={d} className="flex items-center gap-2 text-[10px]">
                      <span className="text-gray-400 font-mono truncate flex-1">{d}</span>
                      <span className={`px-1 py-0.5 rounded text-[8px] font-medium ${c === 'Unknown' ? 'bg-yellow-500/10 text-yellow-400' : 'bg-blue-500/10 text-blue-400'}`}>{c}</span>
                    </div>
                  ))}
              </div>
            </motion.div>
            <motion.div variants={gridItem} className="rounded-xl border border-white/[0.07] bg-[#111827] p-5">
              <p className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-3">Recommended Fixes</p>
              <div className="space-y-2">
                {['Add Content-Security-Policy header', 'Set Secure + HttpOnly on session cookies', 'Configure SPF record for your domain']
                  .map(fix => (
                    <div key={fix} className="flex items-start gap-2">
                      <AlertTriangle className="w-3 h-3 text-yellow-500/70 flex-shrink-0 mt-0.5" />
                      <span className="text-[10px] text-gray-400 leading-relaxed">{fix}</span>
                    </div>
                  ))}
              </div>
            </motion.div>
            <motion.div variants={gridItem} className="rounded-xl border border-accent-green/15 bg-accent-green/[0.03] p-5 flex flex-col justify-between">
              <div>
                <p className="text-[9px] font-mono text-accent-green/60 uppercase tracking-widest mb-3">Export Report</p>
                <p className="text-xs text-gray-400 leading-relaxed mb-4">Download your full scan report in any format for your team, clients, or auditors.</p>
              </div>
              <div className="space-y-2">
                {[{ label: 'SARIF', sub: 'GitHub / Azure DevOps' }, { label: 'CSV', sub: 'Spreadsheet / tickets' }, { label: 'Markdown', sub: 'Wiki / PR-ready' }]
                  .map(({ label, sub }) => (
                    <div key={label} className="flex items-center gap-2.5 rounded-lg bg-[#111827] border border-white/[0.05] px-2.5 py-1.5">
                      <Download className="w-3 h-3 text-accent-green flex-shrink-0" />
                      <span className="text-[10px] font-semibold text-white">{label}</span>
                      <span className="text-[9px] text-gray-600 ml-auto">{sub}</span>
                    </div>
                  ))}
              </div>
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* ── CTA ──────────────────────────────────────────────────────────── */}
      <section className="py-24 px-5 border-t border-white/[0.05] relative overflow-hidden">
        {/* Scanline animation */}
        <motion.div className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-accent-green/30 to-transparent pointer-events-none"
          animate={{ top: ['0%', '100%'] }} transition={{ repeat: Infinity, duration: 3.5, ease: 'linear', repeatDelay: 1.5 }} />
        <div className="max-w-2xl mx-auto text-center relative z-10">
          <FadeUp>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/25 bg-accent-green/[0.06] mb-6">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
              <span className="text-xs font-semibold text-accent-green tracking-wide">Free to start</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Run your first passive website scan.</h2>
            <p className="text-gray-400 mb-8 text-sm sm:text-base leading-relaxed max-w-lg mx-auto">No credit card. No installation. Scan only sites you own or are authorized to test.</p>
            <div className="flex flex-col sm:flex-row justify-center gap-3">
              <Link href="/dashboard"
                className="inline-flex items-center justify-center gap-2 px-8 py-3.5 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors">
                Start Free Scan <ArrowRight className="w-4 h-4" />
              </Link>
              <Link href="/features"
                className="inline-flex items-center justify-center px-8 py-3.5 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors">
                View All Features
              </Link>
            </div>
            <div className="flex flex-wrap justify-center gap-x-6 gap-y-2 mt-8">
              {['Passive scanning', 'No exploitation', 'No installation', 'Authorized targets only'].map(t => (
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
