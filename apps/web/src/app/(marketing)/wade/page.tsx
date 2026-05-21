'use client'
import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import Link from 'next/link'
import { Activity, GitCompare, Bell, Shield, Eye, Globe, Code2, Lock, Search, ClipboardList, BarChart3, ArrowRight, CheckCircle, AlertTriangle, Fingerprint, Radar, Cpu } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

const WADE_CONCEPTS = [
  { icon: Fingerprint, title: 'Behavioral Fingerprinting', desc: 'On first scan, WADE captures a comprehensive snapshot: every script, external domain, form, header, cookie, and structural DOM signature.' },
  { icon: GitCompare, title: 'Scan-over-Scan Comparison', desc: 'Each subsequent scan is compared against the stored baseline. WADE looks for what appeared, disappeared, or changed.' },
  { icon: Radar, title: 'Anomaly Scoring', desc: 'Changes are scored for significance. CDN cache drift, minor text changes, and version bumps are filtered out from genuine security signals.' },
  { icon: Bell, title: 'Confidence-Scored Alerts', desc: 'Only changes that cross the confidence threshold generate findings — new script domains, modified form targets, structural DOM shifts.' },
]
interface TE { week: string; label: string; title: string; desc: string; status: 'baseline'|'normal'|'warning'|'alert' }
const TIMELINE: TE[] = [
  { week:'W1', label:'Baseline created', title:'First scan — fingerprint established', desc:'WADE records scripts, external domains, forms, headers, and DOM structure. This becomes your known-good baseline.', status:'baseline' },
  { week:'W2', label:'Clean scan', title:'Regular scan — no changes detected', desc:'Site matches baseline. Anomaly score remains low. Minor CDN cache variations are filtered automatically.', status:'normal' },
  { week:'W3', label:'New script domain', title:'External script from unfamiliar domain appears', desc:'A new JavaScript file loaded from a domain not present in the baseline. WADE logs the domain and raises a LOW confidence finding.', status:'warning' },
  { week:'W4', label:'Form change', title:'Checkout form action URL changed', desc:'The payment form now posts to a different endpoint than the baseline recorded. WADE flags this as a MEDIUM severity anomaly.', status:'warning' },
  { week:'W5', label:'WADE alert', title:'Multiple anomalies — security review triggered', desc:'Combined anomaly score exceeds threshold. New inline script hash, changed form target, and an unfamiliar domain together warrant immediate review.', status:'alert' },
]
const WADE_WATCHES: { icon: LucideIcon; title: string; desc: string }[] = [
  { icon: Globe, title: 'New third-party domains', desc: 'Domains not present in your baseline that your site now contacts for scripts, fonts, or API calls.' },
  { icon: Code2, title: 'External script changes', desc: 'Script files loaded from external CDNs or domains that changed path, version, or source entirely.' },
  { icon: Cpu, title: 'Inline script hash changes', desc: 'Inline <script> blocks whose content changed between scans — a common indicator of injection attacks.' },
  { icon: ClipboardList, title: 'Form and action changes', desc: 'HTML form action URLs that changed destination — especially relevant for checkout and login forms.' },
  { icon: Shield, title: 'Security header regressions', desc: 'Headers that were present in baseline scans but have disappeared or weakened in recent scans.' },
  { icon: Eye, title: 'Cookie flag regressions', desc: 'Cookies that lost their Secure, HttpOnly, or SameSite attributes between scans.' },
  { icon: Activity, title: 'Page status changes', desc: 'Pages that changed HTTP status codes — especially previously private paths becoming public.' },
  { icon: Search, title: 'Sensitive path changes', desc: 'Newly discovered sensitive paths or previously probed paths that changed their response behavior.' },
]
const WHY_ITEMS = [
  { icon: Lock, title: 'Payment skimmers', desc: 'JavaScript card skimmers are injected scripts on checkout pages that blend into existing content — invisible without baseline comparison.' },
  { icon: Code2, title: 'Injected JavaScript', desc: "Malicious scripts added after deployment don't appear in a previous scan. Only WADE's comparison surfaces them." },
  { icon: AlertTriangle, title: 'Supply chain compromises', desc: 'A plugin update or third-party SDK change can introduce malicious code that runs on your site without your knowledge.' },
  { icon: Shield, title: 'Accidental security regressions', desc: 'Deploys that silently remove CSP headers, weaken cookie flags, or expose debug endpoints are caught on the next comparison scan.' },
]
const COMPARISON_ROWS = [
  { label: 'Approach', scanner: 'Point-in-time snapshot', wade: 'Continuous baseline comparison' },
  { label: 'Memory', scanner: 'Each scan is independent', wade: 'Remembers all previous scans' },
  { label: 'Change detection', scanner: 'Not designed for this', wade: 'Core capability — new scripts, domains, forms' },
  { label: 'Alert type', scanner: 'Static vulnerability findings', wade: 'Only flags meaningful new changes' },
  { label: 'Anomaly scoring', scanner: 'None', wade: 'Confidence-weighted per-change score' },
  { label: 'Noise reduction', scanner: 'Same findings every scan', wade: 'Filters CDN drift and minor variance' },
  { label: 'Recurring monitoring', scanner: 'Usually manual re-runs', wade: 'Scheduled, automated, always comparing' },
]
const FUTURE_ITEMS = [
  "Smarter anomaly classification that learns from your site's normal change patterns over time.",
  "Adaptive confidence thresholds that adjust to your site's deployment cadence and traffic.",
  'Targeted deeper checks triggered automatically when high-risk anomalies are detected.',
  'Historical behavior trends and anomaly score charts across your entire scan history.',
  'AI-assisted finding explanations that describe why a specific change should concern you.',
]
const TS: Record<TE['status'], { badge: string; border: string; dot: string }> = {
  baseline: { dot:'bg-accent-green', badge:'bg-accent-green/15 text-accent-green border-accent-green/20', border:'border-accent-green/15' },
  normal:   { dot:'bg-gray-500',     badge:'bg-white/[0.05] text-gray-400 border-white/[0.08]',           border:'border-white/[0.07]' },
  warning:  { dot:'bg-yellow-400',   badge:'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',        border:'border-yellow-500/15' },
  alert:    { dot:'bg-orange-400',   badge:'bg-orange-500/10 text-orange-400 border-orange-500/20',        border:'border-orange-500/20' },
}

// ── helpers ───────────────────────────────────────────────────────────────────
function FadeUp({ children, delay=0 }: { children: React.ReactNode; delay?: number }) {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  return <motion.div ref={ref} initial={{ opacity:0, y:24 }} animate={inView?{opacity:1,y:0}:{}} transition={{ duration:0.5, delay, ease:[0.25,0.46,0.45,0.94] }}>{children}</motion.div>
}
const SC = { hidden:{}, show:{ transition:{ staggerChildren:0.08 } } }
const SI = { hidden:{ opacity:0, y:20 }, show:{ opacity:1, y:0, transition:{ duration:0.45 } } }
const SL = ({ children }: { children: React.ReactNode }) => (
  <span className="inline-flex items-center gap-2 text-[11px] font-semibold text-accent-green uppercase tracking-widest mb-4">
    <span className="w-4 h-px bg-accent-green/50" />{children}<span className="w-4 h-px bg-accent-green/50" />
  </span>
)

function AnimatedHeadline() {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true })
  const words = ['WADE','learns','what','normal','looks','like']
  return (
    <h1 ref={ref} className="text-4xl sm:text-5xl font-semibold text-white tracking-tight leading-[1.1] mb-5">
      {words.map((w,i) => (
        <motion.span key={w} className={i===3?'text-transparent bg-clip-text bg-gradient-to-r from-accent-green to-accent-blue':''} initial={{ opacity:0, y:12 }} animate={inView?{opacity:1,y:0}:{}} transition={{ duration:0.4, delay:i*0.07 }}>{w}{' '}</motion.span>
      ))}
      <motion.span className="text-gray-400" initial={{ opacity:0 }} animate={inView?{opacity:1}:{}} transition={{ delay:0.5 }}>— then watches for suspicious change.</motion.span>
    </h1>
  )
}

function TimelineEntry({ event, index }: { event: TE; index: number }) {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })
  const s = TS[event.status]
  const dotColor = event.status==='baseline'?'border-accent-green/40':event.status==='alert'?'border-orange-400/40':event.status==='warning'?'border-yellow-400/30':'border-white/[0.10]'
  const textColor = event.status==='baseline'?'text-accent-green':event.status==='alert'?'text-orange-400':event.status==='warning'?'text-yellow-400':'text-gray-500'
  return (
    <div ref={ref} className="flex gap-5">
      <div className="flex flex-col items-center flex-shrink-0 pt-3.5">
        <motion.div initial={{ scale:0 }} animate={inView?{scale:1}:{}} transition={{ duration:0.35, delay:index*0.12, type:'spring', stiffness:220 }}
          className={`w-11 h-11 rounded-full border-2 flex items-center justify-center text-[10px] font-black font-mono z-10 bg-[#0B0F19] ${dotColor}`}>
          <span className={textColor}>{event.week}</span>
        </motion.div>
      </div>
      <motion.div initial={{ opacity:0, x:20 }} animate={inView?{opacity:1,x:0}:{}} transition={{ duration:0.4, delay:index*0.12+0.1 }}
        className={`flex-1 rounded-xl border bg-[#111827] p-5 mb-1 ${s.border} ${event.status==='alert'?'shadow-[0_0_20px_rgba(251,146,60,0.15)]':''}`}
        style={event.status==='alert'?{animation:'alertPulse 2.5s ease-in-out infinite'}:{}}>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold text-white">{event.title}</h3>
          <span className={`text-[9px] font-semibold uppercase tracking-widest px-2 py-0.5 rounded-full border ${s.badge}`}>{event.label}</span>
        </div>
        <p className="text-xs text-gray-500 leading-relaxed">{event.desc}</p>
      </motion.div>
    </div>
  )
}

// ── page ──────────────────────────────────────────────────────────────────────
export default function WadePage() {
  const tlRef = useRef(null)
  const tlInView = useInView(tlRef, { once: true, margin: '-100px' })
  return (
    <div className="bg-[#0B0F19]">
      <style>{`@keyframes alertPulse{0%,100%{box-shadow:0 0 20px rgba(251,146,60,.12)}50%{box-shadow:0 0 32px rgba(251,146,60,.22)}}`}</style>

      {/* Hero */}
      <section className="relative pt-10 pb-20 px-5 text-center overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/4 w-[520px] h-[520px] pointer-events-none">
          {[1,1.4,1.9,2.5].map((s,i) => (
            <motion.div key={i} className="absolute inset-0 rounded-full border border-accent-green/[0.07]" style={{ transform:`scale(${s})` }}
              animate={{ scale:[s,s*1.04,s], opacity:[0.5,1,0.5] }} transition={{ duration:3+i*0.8, repeat:Infinity, delay:i*0.5, ease:'easeInOut' }} />
          ))}
          <div className="absolute inset-0 m-auto w-32 h-32 rounded-full bg-accent-green/[0.06] blur-2xl" />
        </div>
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[500px] bg-accent-green/[0.04] rounded-full blur-3xl pointer-events-none" />
        <div className="relative max-w-3xl mx-auto">
          <motion.div initial={{ opacity:0,y:-10 }} animate={{ opacity:1,y:0 }} transition={{ duration:0.5 }}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/30 bg-accent-green/[0.07] mb-6">
            <Activity className="w-3.5 h-3.5 text-accent-green animate-pulse" />
            <span className="text-xs font-semibold text-accent-green tracking-wide">Website Anomaly Detection Engine</span>
          </motion.div>
          <AnimatedHeadline />
          <motion.p initial={{ opacity:0 }} animate={{ opacity:1 }} transition={{ delay:0.55, duration:0.5 }}
            className="text-base sm:text-lg text-gray-400 leading-relaxed mb-8 max-w-2xl mx-auto">
            WADE fingerprints your website over time and helps identify new scripts, changed code, unfamiliar domains, form changes, header regressions, and suspicious drift from your known-good baseline.
          </motion.p>
          <motion.div initial={{ opacity:0,y:12 }} animate={{ opacity:1,y:0 }} transition={{ delay:0.65 }} className="flex flex-col sm:flex-row justify-center gap-3 mb-10">
            <Link href="/dashboard" className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors">Start Monitoring <ArrowRight className="w-4 h-4" /></Link>
            <a href="#how-it-works" className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors">See How WADE Works</a>
          </motion.div>
          <motion.div initial={{ opacity:0,y:16 }} animate={{ opacity:1,y:0 }} transition={{ delay:0.8 }} className="flex flex-wrap justify-center gap-3">
            {[{dot:'bg-accent-green',l:'Week 1 · Baseline set'},{dot:'bg-accent-blue',l:'Week 2 · Drift detected'},{dot:'bg-yellow-400',l:'Week 3 · Alert triggered'},{dot:'bg-orange-400',l:'Week 4 · Threat confirmed'}].map(({dot,l},i) => (
              <motion.div key={l} className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.04] border border-white/[0.07]" initial={{ opacity:0,scale:0.9 }} animate={{ opacity:1,scale:1 }} transition={{ delay:0.85+i*0.06 }}>
                <span className={`w-1.5 h-1.5 rounded-full ${dot}`} /><span className="text-[11px] text-gray-400 font-medium">{l}</span>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Scanner vs WADE */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <FadeUp><div className="text-center mb-10"><SL>The Difference</SL><h2 className="text-2xl sm:text-3xl font-semibold text-white tracking-tight">The difference between a scanner and WADE</h2></div></FadeUp>
          <div className="grid sm:grid-cols-3 gap-4 items-center">
            <FadeUp delay={0.1}>
              <div className="rounded-xl border border-white/[0.06] bg-[#111827] p-5">
                <p className="text-[10px] font-mono text-gray-600 uppercase tracking-widest mb-3">Before WADE</p>
                <div className="space-y-2">
                  {['scripts: 14 found','domains: unknown','forms: 2 found','headers: 6 found'].map(l => (
                    <div key={l} className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-[#0B0F19] border border-white/[0.05]">
                      <span className="w-1.5 h-1.5 rounded-full bg-gray-600" /><span className="text-[10px] text-gray-600 font-mono">{l}</span>
                    </div>
                  ))}
                </div>
                <p className="text-[9px] text-gray-700 mt-3">No memory. No comparison. No history.</p>
              </div>
            </FadeUp>
            <FadeUp delay={0.2}><div className="text-center py-4"><ArrowRight className="w-6 h-6 text-accent-green mx-auto rotate-90 sm:rotate-0" /><p className="text-[10px] text-accent-green/60 font-mono mt-2 uppercase tracking-widest">WADE added</p></div></FadeUp>
            <FadeUp delay={0.3}>
              <div className="rounded-xl border border-accent-green/20 bg-accent-green/[0.04] p-5">
                <p className="text-[10px] font-mono text-accent-green/60 uppercase tracking-widest mb-3">With WADE</p>
                <div className="space-y-2">
                  {[{t:'scripts: 14 → 15 found',c:'text-yellow-400',d:'bg-yellow-400'},{t:'domains: ↑ new script detected',c:'text-orange-400',d:'bg-orange-400'},{t:'forms: action URL changed',c:'text-red-400',d:'bg-red-400'},{t:'headers: CSP missing',c:'text-yellow-400',d:'bg-yellow-400'}].map(({t,c,d}) => (
                    <div key={t} className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-[#0B0F19] border border-accent-green/10">
                      <span className={`w-1.5 h-1.5 rounded-full ${d} flex-shrink-0`} /><span className={`text-[10px] font-mono ${c}`}>{t}</span>
                    </div>
                  ))}
                </div>
                <p className="text-[9px] text-accent-green/60 mt-3">Baseline compared. Drift caught. Alert raised.</p>
              </div>
            </FadeUp>
          </div>
        </div>
      </section>

      {/* What WADE Is */}
      <section className="py-20 px-5 border-t border-white/[0.05]" id="how-it-works">
        <div className="max-w-5xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>What WADE Is</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Security intelligence that remembers</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">WADE isn't a one-time scan result. It's a layer that builds understanding of your site over time and alerts on meaningful deviations.</p></div></FadeUp>
          <motion.div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-5" variants={SC} initial="hidden" whileInView="show" viewport={{ once:true, margin:'-60px' }}>
            {WADE_CONCEPTS.map(({ icon: Icon, title, desc }) => (
              <motion.div key={title} variants={SI}><motion.div whileHover={{ y:-3 }} transition={{ duration:0.2 }} className="rounded-xl border border-white/[0.07] bg-[#111827] p-6 h-full">
                <div className="w-10 h-10 rounded-lg bg-accent-green/10 flex items-center justify-center mb-4"><Icon className="w-4 h-4 text-accent-green" /></div>
                <h3 className="text-sm font-semibold text-white mb-2">{title}</h3><p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
              </motion.div></motion.div>
            ))}
          </motion.div>
          <FadeUp delay={0.3}><div className="mt-5 rounded-xl border border-accent-green/15 bg-accent-green/[0.04] p-5 text-center"><p className="text-sm font-medium text-white mb-1">WADE requires at least 2 scans to detect anomalies.</p><p className="text-xs text-gray-500">The first scan establishes the baseline. Every subsequent scan compares against it.</p></div></FadeUp>
        </div>
      </section>

      {/* Timeline */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-3xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>How It Evolves</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">From baseline to alert</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">See how WADE builds awareness over time and surfaces changes that matter.</p></div></FadeUp>
          <div className="relative" ref={tlRef}>
            <motion.div className="absolute left-[22px] top-6 w-px bg-gradient-to-b from-accent-green/40 via-accent-green/20 to-orange-400/30 origin-top pointer-events-none"
              initial={{ scaleY:0, height:0 }} animate={tlInView?{ scaleY:1, height:'calc(100% - 24px)' }:{}} transition={{ duration:1.2, ease:'easeInOut' }} />
            <div className="space-y-4">{TIMELINE.map((e,i) => <TimelineEntry key={e.week} event={e} index={i} />)}</div>
          </div>
        </div>
      </section>

      {/* What WADE watches */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>Coverage</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">What WADE watches between scans</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">Eight categories of change that WADE compares across every scan pair.</p></div></FadeUp>
          <motion.div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4" variants={SC} initial="hidden" whileInView="show" viewport={{ once:true, margin:'-60px' }}>
            {WADE_WATCHES.map(({ icon: Icon, title, desc }) => (
              <motion.div key={title} variants={SI}><motion.div whileHover={{ y:-3 }} transition={{ duration:0.2 }} className="rounded-xl border border-white/[0.07] bg-[#111827] p-5 h-full group">
                <div className="w-9 h-9 rounded-lg bg-accent-green/10 flex items-center justify-center mb-3 group-hover:bg-accent-green/15 transition-colors"><Icon className="w-4 h-4 text-accent-green" /></div>
                <h3 className="text-sm font-semibold text-white mb-1.5">{title}</h3><p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
              </motion.div></motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Why it matters */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>Why It Matters</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">The threats that only change detection catches</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">Most attacks on live websites don't come from zero-days — they come from changes introduced silently after your last security review.</p></div></FadeUp>
          <motion.div className="grid sm:grid-cols-2 gap-4" variants={SC} initial="hidden" whileInView="show" viewport={{ once:true, margin:'-60px' }}>
            {WHY_ITEMS.map(({ icon: Icon, title, desc }) => (
              <motion.div key={title} variants={SI}><motion.div whileHover={{ scale:1.01 }} transition={{ duration:0.2 }} className="flex gap-4 rounded-xl border border-white/[0.06] bg-[#111827] px-5 py-4">
                <motion.div whileHover={{ scale:1.1 }} className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/15 flex items-center justify-center flex-shrink-0 mt-0.5"><Icon className="w-3.5 h-3.5 text-red-400/80" /></motion.div>
                <div><p className="text-sm font-semibold text-white mb-1">{title}</p><p className="text-xs text-gray-500 leading-relaxed">{desc}</p></div>
              </motion.div></motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Comparison table */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>Comparison</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">WADE vs a traditional security scanner</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">Traditional scanners and WADE are complementary — WebHound uses both.</p></div></FadeUp>
          <div className="rounded-2xl border border-white/[0.08] bg-[#111827] overflow-hidden">
            <div className="grid grid-cols-3 bg-[#0D1520] border-b border-white/[0.06]">
              <div className="px-5 py-3.5" />
              <div className="px-5 py-3.5 text-[10px] font-semibold text-gray-500 uppercase tracking-widest border-l border-white/[0.06]">Traditional Scanner</div>
              <div className="px-5 py-3.5 border-l border-white/[0.06]"><span className="text-[10px] font-semibold text-accent-green uppercase tracking-widest">WADE</span></div>
            </div>
            {COMPARISON_ROWS.map((row,i) => (
              <motion.div key={row.label} initial={{ opacity:0,x:-20 }} whileInView={{ opacity:1,x:0 }} viewport={{ once:true }} transition={{ duration:0.4, delay:i*0.07 }}
                className={`grid grid-cols-3 ${i<COMPARISON_ROWS.length-1?'border-b border-white/[0.04]':''}`}>
                <div className="px-5 py-3.5 text-xs font-medium text-gray-400">{row.label}</div>
                <div className="px-5 py-3.5 border-l border-white/[0.04]"><span className="text-xs text-gray-600">{row.scanner}</span></div>
                <div className="px-5 py-3.5 border-l border-white/[0.04] flex items-center gap-2 bg-accent-green/[0.025]"><CheckCircle className="w-3 h-3 text-accent-green flex-shrink-0" /><span className="text-xs text-gray-300">{row.wade}</span></div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Roadmap */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>Roadmap</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Where WADE is heading</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">WADE is designed to evolve toward smarter, more adaptive anomaly intelligence. The following capabilities are on our roadmap — not yet available in all plans.</p></div></FadeUp>
          <div className="rounded-2xl border border-accent-blue/15 bg-accent-blue/[0.03] p-8">
            <FadeUp><div className="flex items-center gap-3 mb-6"><div className="w-10 h-10 rounded-xl bg-accent-blue/10 border border-accent-blue/20 flex items-center justify-center"><BarChart3 className="w-4 h-4 text-accent-blue" /></div><div><p className="text-sm font-semibold text-white">WADE Intelligence — Future Roadmap</p><p className="text-xs text-gray-500">These are planned directions, not current features.</p></div></div></FadeUp>
            <ul className="space-y-3.5">
              {FUTURE_ITEMS.map((item,i) => (
                <motion.li key={i} className="flex items-start gap-3" initial={{ opacity:0,x:-16 }} whileInView={{ opacity:1,x:0 }} viewport={{ once:true }} transition={{ duration:0.38, delay:i*0.09 }}>
                  <div className="w-5 h-5 rounded-full bg-accent-blue/10 border border-accent-blue/15 flex items-center justify-center flex-shrink-0 mt-0.5"><span className="text-[9px] font-mono text-accent-blue/70">{i+1}</span></div>
                  <p className="text-sm text-gray-400 leading-relaxed">{item}</p>
                </motion.li>
              ))}
            </ul>
            <p className="text-xs text-gray-600 mt-6 border-t border-white/[0.05] pt-4">WebHound is built iteratively. The current version of WADE provides baseline comparison, anomaly scoring, and confidence-based alerts.</p>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-24 px-5 border-t border-white/[0.05]">
        <div className="max-w-2xl mx-auto text-center">
          <FadeUp>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/25 bg-accent-green/[0.06] mb-6"><Activity className="w-3.5 h-3.5 text-accent-green animate-pulse" /><span className="text-xs font-semibold text-accent-green tracking-wide">Powered by WADE</span></div>
            <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Start building your website security baseline.</h2>
            <p className="text-gray-400 mb-8 text-sm sm:text-base leading-relaxed max-w-lg mx-auto">Your first scan creates the baseline. Every scan after that, WADE is watching. Free to start — no installation required.</p>
            <div className="flex flex-col sm:flex-row justify-center gap-3">
              <Link href="/dashboard" className="inline-flex items-center justify-center gap-2 px-8 py-3.5 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors">Start Monitoring <ArrowRight className="w-4 h-4" /></Link>
              <Link href="/features" className="inline-flex items-center justify-center px-8 py-3.5 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors">See All Features</Link>
            </div>
            <div className="flex flex-wrap justify-center gap-x-6 gap-y-2 mt-8">
              {['Passive scanning','Baseline comparison','Confidence scoring','Authorized targets only'].map(t => (
                <div key={t} className="flex items-center gap-1.5 text-xs text-gray-600"><CheckCircle className="w-3 h-3 text-gray-700 flex-shrink-0" />{t}</div>
              ))}
            </div>
          </FadeUp>
        </div>
      </section>
    </div>
  )
}
