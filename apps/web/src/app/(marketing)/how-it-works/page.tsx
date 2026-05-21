'use client'

import { useRef, useEffect, useState } from 'react'
import Link from 'next/link'
import { motion, useInView } from 'framer-motion'
import {
  Search, Globe, Shield, Bug, Code2, Settings, Activity, Bell,
  ArrowRight, CheckCircle, ChevronRight,
} from 'lucide-react'

// ── Data ──────────────────────────────────────────────────────────────────────

const LAYERS = [
  { num: '01', icon: Search, title: 'Reconnaissance', desc: 'Passive discovery of every public asset — subdomains, open ports, linked pages, and exposed paths — without touching anything that should be private.', checks: '1,240+', color: '#7CFF00' },
  { num: '02', icon: Globe, title: 'DNS & Infrastructure', desc: 'DNS record auditing, hosting chain analysis, SPF/DKIM/DMARC validation, and DNSSEC presence to prevent email spoofing and subdomain takeover.', checks: '890+', color: '#00e5ff' },
  { num: '03', icon: Shield, title: 'SSL / TLS Analysis', desc: 'Certificate validity, cipher suite strength, protocol version support, and HSTS preload status — ensuring your encryption is both current and correctly configured.', checks: '640+', color: '#a78bfa' },
  { num: '04', icon: Bug, title: 'Vulnerability Scanning', desc: 'Cross-referenced against 18,400+ CVE signatures to detect known exploits in detected frameworks, libraries, and server software.', checks: '18,400+', color: '#f87171' },
  { num: '05', icon: Code2, title: 'Web App Scanning', desc: 'Dynamic OWASP Top 10 testing covering SQL injection, reflected XSS, CSRF, IDOR, and broken authentication patterns across all discovered endpoints.', checks: '9,200+', color: '#fb923c' },
  { num: '06', icon: Settings, title: 'Configuration Review', desc: 'Security response headers, CORS policy, cookie flags, and server-level hardening — the misconfigurations that turn minor bugs into critical breaches.', checks: '2,100+', color: '#fbbf24' },
  { num: '07', icon: Activity, title: 'Threat Intelligence', desc: 'IP and domain reputation checked against global blocklists, PhishTank, and known breach datasets to surface infrastructure that has already been flagged.', checks: '6,800+', color: '#22d3ee' },
  { num: '08', icon: Bell, title: 'Monitoring & Alerts', desc: 'Continuous post-scan surveillance using WADE behavioral baselines. New scripts, domain additions, and structural DOM changes trigger instant alerts.', checks: '3,400+', color: '#8BFF3E' },
]

const HOW_STEPS = [
  { step: 1, title: 'Add your website', desc: 'Enter your URL. No installation, no DNS changes, no server credentials. We only access what a browser would.' },
  { step: 2, title: 'All eight engines run in parallel', desc: 'WebHound fires all eight security layers simultaneously. A full scan completes in under 3 minutes for most sites.' },
  { step: 3, title: 'Findings are grouped and ranked', desc: 'Results are organized by engine category, severity, and fix priority — not a raw alert dump. Every finding links to the affected URL.' },
  { step: 4, title: 'Act on plain-English guidance', desc: 'Each finding includes what was detected, why it matters, the CVSS score where applicable, and a concrete remediation path.' },
  { step: 5, title: 'WADE sets your behavioral baseline', desc: 'After the first scan, WADE fingerprints your site. Subsequent scans compare against that baseline and alert you only when something meaningful changes.' },
  { step: 6, title: 'Export and share', desc: 'Download findings as SARIF (GitHub/CI), CSV (ticketing), or Markdown (wikis, PRs, client reports) — whatever format your workflow needs.' },
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

function useCountUp(target: number, inView: boolean, duration = 1.4) {
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

// ── Hero counter ──────────────────────────────────────────────────────────────

function HeroCounter() {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true })
  const count = useCountUp(42000, inView, 1.6)
  return (
    <span ref={ref} className="text-transparent bg-clip-text bg-gradient-to-r from-accent-green to-accent-blue">
      {count.toLocaleString()}+ checks.
    </span>
  )
}

// ── Layer color dots pipeline ─────────────────────────────────────────────────

function ScanPipeline() {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true })
  return (
    <div ref={ref} className="py-12 px-5 border-t border-white/[0.05]">
      <div className="max-w-5xl mx-auto">
        <FadeUp>
          <p className="text-center text-[11px] font-semibold text-gray-600 uppercase tracking-widest mb-6">Scan Pipeline</p>
        </FadeUp>
        <div className="flex items-center justify-center gap-0 overflow-x-auto pb-2">
          {LAYERS.map(({ num, color, title }, i) => (
            <div key={num} className="flex items-center">
              <div className="flex flex-col items-center gap-2 px-1">
                <motion.div
                  className="w-8 h-8 rounded-full flex items-center justify-center text-[9px] font-black font-mono border-2 relative"
                  style={{ borderColor: color, background: color + '15', color }}
                  initial={{ opacity: 0, scale: 0.5 }}
                  animate={inView ? { opacity: 1, scale: 1 } : {}}
                  transition={{ delay: i * 0.1, duration: 0.4, ease: 'backOut' }}>
                  {num}
                  {/* Pulsing ring */}
                  <motion.span className="absolute inset-0 rounded-full"
                    style={{ border: `2px solid ${color}` }}
                    animate={inView ? { scale: [1, 1.6, 1], opacity: [0.6, 0, 0.6] } : {}}
                    transition={{ delay: i * 0.1 + 0.3, duration: 2, repeat: Infinity, repeatDelay: i * 0.15 }} />
                </motion.div>
                <motion.span className="text-[8px] text-gray-600 text-center w-12 leading-tight hidden sm:block"
                  initial={{ opacity: 0 }} animate={inView ? { opacity: 1 } : {}} transition={{ delay: i * 0.1 + 0.2 }}>
                  {title.split(' ')[0]}
                </motion.span>
              </div>
              {i < LAYERS.length - 1 && (
                <motion.div className="h-px flex-shrink-0 w-4 sm:w-6"
                  style={{ background: `linear-gradient(to right, ${LAYERS[i].color}50, ${LAYERS[i + 1].color}50)` }}
                  initial={{ scaleX: 0 }} animate={inView ? { scaleX: 1 } : {}}
                  transition={{ delay: i * 0.1 + 0.15, duration: 0.3 }} />
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Animated spine line ───────────────────────────────────────────────────────

function SpineLine({ inView }: { inView: boolean }) {
  return (
    <div className="absolute left-5 top-0 bottom-0 w-px hidden sm:block overflow-hidden">
      <motion.div className="w-full bg-gradient-to-b from-accent-green/40 via-accent-green/15 to-transparent"
        initial={{ height: 0 }} animate={inView ? { height: '100%' } : {}}
        transition={{ duration: 1.2, ease: 'easeOut' }} />
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function HowItWorksPage() {
  const layersRef = useRef(null)
  const layersInView = useInView(layersRef, { once: true, margin: '-60px' })
  const stepsRef = useRef(null)
  const stepsInView = useInView(stepsRef, { once: true, margin: '-60px' })

  return (
    <div className="bg-[#0B0F19]">

      {/* ── Hero ────────────────────────────────────────────────────────────── */}
      <section className="relative pt-10 pb-20 px-5 text-center overflow-hidden">
        <motion.div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[420px] bg-accent-green/[0.04] rounded-full blur-3xl pointer-events-none"
          animate={{ opacity: [0.4, 0.7, 0.4] }} transition={{ repeat: Infinity, duration: 5, ease: 'easeInOut' }} />

        <div className="relative max-w-3xl mx-auto">
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-accent-green/25 bg-accent-green/[0.06] mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
            <span className="text-xs font-semibold text-accent-green tracking-wide">8-Layer Security Engine</span>
          </motion.div>

          <motion.h1 initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15, duration: 0.55 }}
            className="text-4xl sm:text-5xl font-semibold text-white tracking-tight leading-[1.1] mb-5">
            <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>One scan. </motion.span>
            <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.35 }}>Eight layers.</motion.span>
            <br />
            <HeroCounter />
          </motion.h1>

          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.45, duration: 0.5 }}
            className="text-base sm:text-lg text-gray-400 leading-relaxed mb-8 max-w-2xl mx-auto">
            WebHound runs eight parallel security engines against every public surface of your website.
            Here's exactly what each layer checks, and why it matters.
          </motion.p>

          {/* Layer color dots */}
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.55, duration: 0.5 }}
            className="flex items-center justify-center gap-2 mb-8 flex-wrap">
            {LAYERS.map(({ num, color }, i) => (
              <motion.div key={num}
                className="w-2.5 h-2.5 rounded-full"
                style={{ background: color }}
                animate={{ opacity: [0.4, 1, 0.4], scale: [0.8, 1.1, 0.8] }}
                transition={{ delay: i * 0.15, repeat: Infinity, duration: 1.8, ease: 'easeInOut' }} />
            ))}
          </motion.div>

          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.6, duration: 0.5 }}
            className="flex flex-col sm:flex-row justify-center gap-3">
            <Link href="/dashboard"
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors">
              Start Scanning <ArrowRight className="w-4 h-4" />
            </Link>
            <Link href="/features"
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors">
              View All Features <ChevronRight className="w-4 h-4" />
            </Link>
          </motion.div>
        </div>
      </section>

      {/* ── 8 Layers ──────────────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <FadeUp>
            <div className="text-center mb-14">
              <SectionLabel>The Eight Layers</SectionLabel>
              <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">What each engine checks</h2>
              <p className="text-gray-400 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">
                All eight engines run in parallel on every scan. No black boxes — here's the full breakdown.
              </p>
            </div>
          </FadeUp>

          <motion.div ref={layersRef} className="grid sm:grid-cols-2 gap-4"
            initial="hidden" animate={layersInView ? 'show' : 'hidden'}
            variants={{ hidden: {}, show: { transition: { staggerChildren: 0.08 } } }}>
            {LAYERS.map(({ num, icon: Icon, title, desc, checks, color }) => (
              <motion.div key={num}
                variants={{ hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0, transition: { duration: 0.45 } } }}
                className="rounded-xl border bg-[#111827] p-6 flex gap-4 group relative overflow-hidden"
                style={{ borderColor: 'rgba(255,255,255,0.07)' }}
                onHoverStart={e => { (e.currentTarget as HTMLElement).style.borderColor = color + '55' }}
                onHoverEnd={e => { (e.currentTarget as HTMLElement).style.borderColor = 'rgba(255,255,255,0.07)' }}
                whileHover={{ y: -2, transition: { duration: 0.2 } }}>
                {/* Scan sweep on hover */}
                <motion.div className="absolute inset-y-0 w-12 pointer-events-none opacity-0 group-hover:opacity-100"
                  style={{ background: `linear-gradient(to right, transparent, ${color}15, transparent)` }}
                  animate={{ x: ['-100%', '600%'] }}
                  transition={{ duration: 1.2, repeat: Infinity, ease: 'linear', repeatDelay: 0.5 }} />

                <div className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0 transition-all duration-200"
                  style={{ background: color + '18', border: `1px solid ${color}28` }}>
                  <Icon className="w-5 h-5" style={{ color }} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="text-[10px] font-black font-mono tracking-wider" style={{ color: color + '80' }}>{num}</span>
                    <h3 className="text-sm font-semibold text-white">{title}</h3>
                  </div>
                  <p className="text-xs text-gray-500 leading-relaxed mb-3">{desc}</p>
                  <motion.div
                    whileInView={{ scale: [1, 1.05, 1] }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.3, duration: 0.5 }}
                    className="inline-block">
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded"
                      style={{ color, background: color + '12' }}>
                      {checks} checks
                    </span>
                  </motion.div>
                </div>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── Scan pipeline diagram ──────────────────────────────────────────────── */}
      <ScanPipeline />

      {/* ── Step-by-step flow ─────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-3xl mx-auto">
          <FadeUp>
            <div className="text-center mb-14">
              <SectionLabel>The Workflow</SectionLabel>
              <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">From URL to action in minutes</h2>
            </div>
          </FadeUp>

          <div ref={stepsRef} className="relative">
            <SpineLine inView={stepsInView} />
            <div className="flex flex-col gap-4">
              {HOW_STEPS.map(({ step, title, desc }) => (
                <motion.div key={step}
                  initial={{ opacity: 0, x: -24 }}
                  animate={stepsInView ? { opacity: 1, x: 0 } : {}}
                  transition={{ delay: step * 0.12, duration: 0.5, ease: [0.25, 0.46, 0.45, 0.94] }}
                  className="flex gap-5 rounded-xl border border-white/[0.07] bg-[#111827] px-6 py-5 hover:border-accent-green/15 transition-colors">
                  <motion.div className="w-10 h-10 rounded-xl bg-accent-green/10 border border-accent-green/15 flex items-center justify-center flex-shrink-0"
                    animate={stepsInView ? { boxShadow: ['0 0 0px rgba(139,255,62,0)', '0 0 14px rgba(139,255,62,0.25)', '0 0 0px rgba(139,255,62,0)'] } : {}}
                    transition={{ delay: step * 0.12 + 0.3, duration: 0.7 }}>
                    <span className="text-xs font-black text-accent-green font-mono">{String(step).padStart(2, '0')}</span>
                  </motion.div>
                  <div className="flex-1 py-0.5">
                    <h3 className="text-sm font-semibold text-white mb-1">{title}</h3>
                    <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── Safety callout ────────────────────────────────────────────────────── */}
      <section className="py-16 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <FadeUp>
            <div className="rounded-2xl border border-white/[0.07] bg-[#111827] p-8 sm:p-10 relative overflow-hidden"
              style={{ borderLeft: '3px solid rgba(139,255,62,0.4)' }}>
              {/* Green glow accent */}
              <div className="absolute left-0 top-0 bottom-0 w-24 bg-gradient-to-r from-accent-green/[0.04] to-transparent pointer-events-none" />
              <div className="flex flex-col sm:flex-row gap-6 items-start relative z-10">
                <div className="relative flex-shrink-0">
                  <motion.div className="w-12 h-12 rounded-xl bg-accent-green/10 border border-accent-green/15 flex items-center justify-center"
                    animate={{ boxShadow: ['0 0 0px rgba(139,255,62,0.1)', '0 0 20px rgba(139,255,62,0.25)', '0 0 0px rgba(139,255,62,0.1)'] }}
                    transition={{ repeat: Infinity, duration: 2.5, ease: 'easeInOut' }}>
                    <Shield className="w-5 h-5 text-accent-green" />
                  </motion.div>
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-white mb-2">Passive scanning only — always safe to run</h2>
                  <p className="text-sm text-gray-400 leading-relaxed mb-4">
                    Every WebHound engine is read-only. We fetch content exactly as a browser would — no credentials, no injection attempts, no fuzzing, no load testing.
                    Safe to run continuously against live production without risk of downtime or data modification.
                  </p>
                  <div className="flex flex-wrap gap-3">
                    {['No exploitation', 'No auth required', 'No destructive testing', 'Passive read-only'].map(t => (
                      <div key={t} className="flex items-center gap-1.5 text-xs text-gray-500">
                        <CheckCircle className="w-3 h-3 text-accent-green flex-shrink-0" />{t}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </FadeUp>
        </div>
      </section>

      {/* ── CTA ──────────────────────────────────────────────────────────────── */}
      <section className="py-24 px-5 border-t border-white/[0.05] relative overflow-hidden">
        <motion.div className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-accent-green/25 to-transparent pointer-events-none"
          animate={{ top: ['0%', '100%'] }} transition={{ repeat: Infinity, duration: 4, ease: 'linear', repeatDelay: 2 }} />
        <div className="max-w-2xl mx-auto text-center relative z-10">
          <FadeUp>
            <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">See all eight layers in action.</h2>
            <p className="text-gray-400 mb-8 text-sm sm:text-base leading-relaxed max-w-lg mx-auto">
              Add your website and run a full scan in under 3 minutes. No installation, no credit card.
            </p>
            <div className="flex flex-col sm:flex-row justify-center gap-3">
              <Link href="/dashboard"
                className="inline-flex items-center justify-center gap-2 px-8 py-3.5 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors">
                Start Free Scan <ArrowRight className="w-4 h-4" />
              </Link>
              <Link href="/pricing"
                className="inline-flex items-center justify-center px-8 py-3.5 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors">
                View Pricing
              </Link>
            </div>
          </FadeUp>
        </div>
      </section>

    </div>
  )
}
