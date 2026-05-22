'use client'
import { useRef, useState, useEffect } from 'react'
import { motion, useInView } from 'framer-motion'
import Link from 'next/link'
import { Calendar, Bell, Activity, GitCompare, Shield, Globe, Code2, Eye, Lock, Search, ArrowRight, CheckCircle, AlertTriangle, Clock, Zap, PlusCircle, ScanLine, FileText, Store, Building2, Briefcase, Terminal } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

const WHY_ITEMS = [
  { icon: Code2, title: 'A single scan is a snapshot', desc: "Point-in-time scans show what's wrong right now — but can't tell you what changed since the last time you looked." },
  { icon: AlertTriangle, title: 'Compromises persist for weeks', desc: 'Injected scripts, skimmers, and malicious redirects often live in production for weeks before anyone notices.' },
  { icon: Globe, title: 'Deployments introduce regressions', desc: 'Every release can silently remove security headers, change cookie attributes, or add unfamiliar third-party domains.' },
]
const WORKFLOW_STEPS = [
  { icon: PlusCircle, step: 1, title: 'Add your website', desc: 'Enter your URL. No agents, no DNS records, no server access. Takes 30 seconds.' },
  { icon: Calendar, step: 2, title: 'Choose a scan schedule', desc: 'Pick daily, weekly, or a custom cadence that fits your release cycle.' },
  { icon: ScanLine, step: 3, title: 'WebHound creates a baseline', desc: 'The first scan fingerprints your site — scripts, domains, headers, forms, cookies, and structure.' },
  { icon: GitCompare, step: 4, title: 'WADE compares future scans', desc: 'Each subsequent scan is compared against the stored baseline and scored for anomalies.' },
  { icon: Bell, step: 5, title: 'Alerts surface suspicious changes', desc: 'Meaningful changes — new script domains, header regressions, form changes — trigger confidence-scored findings.' },
  { icon: FileText, step: 6, title: 'Reports help you fix issues', desc: 'Each finding includes context, affected URLs, and remediation guidance. Export SARIF, CSV, or Markdown.' },
]
const MONITORS: { icon: LucideIcon; title: string; desc: string }[] = [
  { icon: Shield, title: 'Security header regressions', desc: 'Tracks whether CSP, HSTS, X-Frame-Options, and other headers remain present and unchanged between scans.' },
  { icon: Globe, title: 'New third-party domains', desc: 'Flags any domain not in the baseline that your site now contacts for scripts, fonts, iframes, or API calls.' },
  { icon: Code2, title: 'Changed JavaScript', desc: 'Detects inline script hash changes and new external script files that appeared after the baseline was set.' },
  { icon: Search, title: 'Sensitive path exposure', desc: 'Re-checks sensitive paths each scan and alerts if something that was closed becomes accessible again.' },
  { icon: Eye, title: 'Cookie security changes', desc: 'Monitors whether cookies lose their Secure, HttpOnly, or SameSite attributes between deployments.' },
  { icon: Lock, title: 'TLS and DNS changes', desc: 'Validates certificates and email auth records on each scan and flags anything that weakens between runs.' },
  { icon: ArrowRight, title: 'Suspicious redirects', desc: 'Monitors HTTP redirect chains for new destinations or unexpected changes in redirect behavior.' },
  { icon: Activity, title: 'WADE anomaly changes', desc: 'Tracks your WADE anomaly score across scans to surface trending risk and patterns of concern.' },
]
interface UseCase { icon: LucideIcon; label: string; title: string; desc: string }
const USE_CASES: UseCase[] = [
  { icon: Store, label: 'Small Business', title: 'Local businesses and solo owners', desc: "Set up weekly monitoring and forget it. If something important changes on your site — a plugin breaks security headers or an unfamiliar script appears — you'll know before your customers do." },
  { icon: Building2, label: 'CMS Platforms', title: 'WordPress, Shopify, Wix, Squarespace', desc: 'Managed platforms update plugins and themes automatically. WebHound tells you what changed between those updates in security-relevant terms, not just changelog entries.' },
  { icon: Briefcase, label: 'Web Agencies', title: 'Agencies managing client sites', desc: 'Add multiple client websites and monitor all of them from one account. Get ahead of security regressions before clients notice — or before it becomes your emergency.' },
  { icon: Terminal, label: 'Developers', title: 'Development teams and release monitoring', desc: "Run a scan after every release to catch security regressions. WADE's baseline comparison shows exactly what changed since your last clean scan." },
]
const ALERT_TYPES = [
  { icon: Zap, title: 'Scan completed', desc: 'In-dashboard alert when any scheduled or manual scan finishes.', live: true },
  { icon: AlertTriangle, title: 'High-risk finding', desc: 'Alert when a HIGH or CRITICAL severity finding is detected on a monitored site.', live: true },
  { icon: Activity, title: 'WADE anomaly detected', desc: "Alert when WADE's anomaly score spikes above threshold on a comparison scan.", live: true },
  { icon: Clock, title: 'Monitoring status', desc: 'Alert if a scheduled scan fails or a monitored site becomes unreachable.', live: true },
  { icon: Bell, title: 'Email notifications', desc: 'Email delivery of alerts and scan summaries. Available on monitoring plans.', live: false },
]
const SAFETY_POINTS = [
  { icon: Shield, title: 'Passive scanning only', desc: "Every scheduled scan is read-only. We fetch publicly accessible content — nothing more." },
  { icon: CheckCircle, title: 'No exploitation', desc: 'Recurring scans do not probe for exploits, run injection tests, or brute-force anything.' },
  { icon: AlertTriangle, title: 'Authorized targets only', desc: 'You confirm authorization for every site you add. Unauthorized scanning violates our terms.' },
  { icon: Clock, title: 'Rate-limited and safe', desc: "Scheduled scans are paced to avoid impacting your site's performance or rate limits." },
]

// helpers
function FadeUp({ children, delay=0 }: { children: React.ReactNode; delay?: number }) {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  return <motion.div ref={ref} initial={{ opacity:0,y:24 }} animate={inView?{opacity:1,y:0}:{}} transition={{ duration:0.5,delay,ease:[0.25,0.46,0.45,0.94] }}>{children}</motion.div>
}
const SC = { hidden:{}, show:{ transition:{ staggerChildren:0.08 } } }
const SI = { hidden:{ opacity:0, y:20 }, show:{ opacity:1, y:0, transition:{ duration:0.45 } } }
const SL = ({ children }: { children: React.ReactNode }) => (
  <span className="inline-flex items-center gap-2 text-[11px] font-semibold text-accent-green uppercase tracking-widest mb-4">
    <span className="w-4 h-px bg-accent-green/50" />{children}<span className="w-4 h-px bg-accent-green/50" />
  </span>
)

function Counter({ target, label }: { target: number; label: string }) {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true })
  const [val, setVal] = useState(0)
  useEffect(() => {
    if (!inView) return
    const t0 = performance.now()
    const tick = (now: number) => {
      const p = Math.min((now - t0) / 1200, 1)
      setVal(Math.round((1-(1-p)**3)*target))
      if (p < 1) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  }, [inView, target])
  return <div ref={ref} className="flex flex-col items-center gap-1"><span className="text-2xl font-bold font-mono text-white tabular-nums">{val.toLocaleString()}</span><span className="text-[11px] text-gray-500">{label}</span></div>
}

function WorkflowStep({ icon: Icon, step, title, desc, index }: { icon: LucideIcon; step: number; title: string; desc: string; index: number }) {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })
  return (
    <motion.div ref={ref} initial={{ opacity:0,x:-20 }} animate={inView?{opacity:1,x:0}:{}} transition={{ duration:0.45,delay:index*0.1 }}
      className="flex gap-5 rounded-xl border border-white/[0.07] bg-[#111827] px-6 py-5 hover:border-accent-green/15 transition-colors">
      <motion.div initial={{ scale:0.8 }} animate={inView?{scale:[1,1.15,1]}:{}} transition={{ duration:0.5,delay:index*0.1+0.2 }}
        className="w-12 h-12 rounded-xl bg-accent-green/10 border border-accent-green/15 flex items-center justify-center flex-shrink-0">
        <Icon className="w-5 h-5 text-accent-green" />
      </motion.div>
      <div className="flex-1 min-w-0 py-1">
        <div className="text-[10px] font-mono text-accent-green/50 uppercase tracking-widest mb-1">Step {step}</div>
        <h3 className="text-sm font-semibold text-white mb-1">{title}</h3>
        <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
      </div>
    </motion.div>
  )
}

function WadeBar({ label, val, color, delay }: { label: string; val: number; color: string; delay: number }) {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true })
  return (
    <div ref={ref} className="flex items-center gap-2">
      <span className="text-[9px] text-gray-600 font-mono w-4">{label}</span>
      <div className="flex-1 h-1.5 rounded-full bg-white/[0.06]">
        <motion.div className={`h-full rounded-full ${color}`} initial={{ width:0 }} animate={inView?{width:`${val}%`}:{}} transition={{ duration:0.7,delay,ease:'easeOut' }} />
      </div>
      <span className="text-[9px] text-gray-500 font-mono w-4">{val}</span>
    </div>
  )
}

export default function MonitoringPage() {
  return (
    <div className="bg-[#0B0F19]">
      <style>{`@keyframes scanline{0%{top:0%;opacity:.5}100%{top:100%;opacity:0}}.scanline{animation:scanline 3.5s linear infinite;position:absolute;left:0;right:0;height:2px;background:linear-gradient(to bottom,transparent,rgba(139,255,62,.08),transparent);pointer-events:none}@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}.blink{animation:blink 1.2s ease-in-out infinite}`}</style>

      {/* Hero */}
      <section className="relative pt-10 pb-20 px-5 text-center overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[700px] h-[450px] bg-accent-green/[0.035] rounded-full blur-3xl pointer-events-none" />
        <div className="relative max-w-3xl mx-auto">
          <motion.div initial={{ opacity:0,y:-10 }} animate={{ opacity:1,y:0 }} transition={{ duration:0.45 }}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/30 bg-accent-green/[0.07] mb-6">
            <span className="w-2 h-2 rounded-full bg-accent-green blink" /><Calendar className="w-3.5 h-3.5 text-accent-green" />
            <span className="text-xs font-semibold text-accent-green tracking-wide">WATCHING · Scheduled · WADE-Powered</span>
          </motion.div>
          <motion.h1 initial={{ opacity:0,y:16 }} animate={{ opacity:1,y:0 }} transition={{ delay:0.15,duration:0.5 }}
            className="text-4xl sm:text-5xl font-semibold text-white tracking-tight leading-[1.1] mb-5">
            Continuous website security monitoring{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-accent-green to-accent-blue">without the enterprise complexity.</span>
          </motion.h1>
          <motion.p initial={{ opacity:0 }} animate={{ opacity:1 }} transition={{ delay:0.3,duration:0.5 }}
            className="text-base sm:text-lg text-gray-400 leading-relaxed mb-8 max-w-2xl mx-auto">
            WebHound watches your website over time with scheduled passive scans, WADE baseline comparisons, security drift detection, alerts, and clear reports — so you know when something important changes.
          </motion.p>
          <motion.div initial={{ opacity:0,y:12 }} animate={{ opacity:1,y:0 }} transition={{ delay:0.4 }} className="flex flex-col sm:flex-row justify-center gap-3 mb-10">
            <Link href="/dashboard" className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors">Start Monitoring <ArrowRight className="w-4 h-4" /></Link>
            <Link href="/wade" className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors">View WADE</Link>
          </motion.div>
          <motion.div initial={{ opacity:0,y:16 }} animate={{ opacity:1,y:0 }} transition={{ delay:0.55 }}
            className="inline-flex items-center gap-8 px-6 py-4 rounded-2xl bg-white/[0.03] border border-white/[0.07]">
            <Counter target={3} label="sites monitored" /><div className="w-px h-8 bg-white/[0.08]" />
            <Counter target={847} label="checks this week" /><div className="w-px h-8 bg-white/[0.08]" />
            <Counter target={2} label="anomalies flagged" />
          </motion.div>
        </div>
      </section>

      {/* Comparison strip */}
      <section className="py-16 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <div className="grid sm:grid-cols-3 gap-4">
            {[
              { label:'Manual checking', desc:"You visit the site occasionally and look for obvious problems. Invisible threats go unnoticed for weeks.", highlight:false, icon:Clock },
              { label:'Point-in-time scan', desc:"A scanner runs once, shows current issues. But it can't see what changed since your last scan — or alert you between runs.", highlight:false, icon:ScanLine },
              { label:'WebHound Monitoring', desc:'Scheduled passive scans with WADE baseline comparison. Automatically detects drift, regressions, and new threats between every run.', highlight:true, icon:Activity },
            ].map(({ label, desc, highlight, icon: Icon }, i) => (
              <motion.div key={label} initial={{ opacity:0,y:20 }} whileInView={{ opacity:1,y:0 }} viewport={{ once:true }} transition={{ duration:0.4,delay:i*0.1 }}
                className={`rounded-xl border p-5 ${highlight?'border-accent-green/25 bg-accent-green/[0.05] ring-1 ring-accent-green/10':'border-white/[0.07] bg-[#111827]'}`}>
                <div className={`w-9 h-9 rounded-lg flex items-center justify-center mb-3 ${highlight?'bg-accent-green/15':'bg-white/[0.05]'}`}>
                  <Icon className={`w-4 h-4 ${highlight?'text-accent-green':'text-gray-500'}`} />
                </div>
                <p className={`text-sm font-semibold mb-2 ${highlight?'text-accent-green':'text-gray-400'}`}>{label}</p>
                <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
                {highlight && <div className="mt-3 flex items-center gap-1.5"><CheckCircle className="w-3 h-3 text-accent-green" /><span className="text-[10px] text-accent-green font-medium">Continuous protection</span></div>}
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Why monitoring */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>Why Monitoring</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">One scan won't protect you. Continuous monitoring will.</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">Security issues that matter most aren't always there when you scan — they appear between scans.</p></div></FadeUp>
          <motion.div className="grid sm:grid-cols-3 gap-5" variants={SC} initial="hidden" whileInView="show" viewport={{ once:true, margin:'-60px' }}>
            {WHY_ITEMS.map(({ icon: Icon, title, desc }) => (
              <motion.div key={title} variants={SI}><motion.div whileHover={{ y:-4 }} transition={{ duration:0.2 }} className="rounded-xl border border-white/[0.06] bg-[#111827] p-7 h-full flex flex-col gap-4">
                <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/15 flex items-center justify-center"><Icon className="w-5 h-5 text-red-400/80" /></div>
                <div><p className="text-sm font-semibold text-white mb-2">{title}</p><p className="text-xs text-gray-500 leading-relaxed">{desc}</p></div>
              </motion.div></motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Workflow */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>How It Works</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Set it up once. Let WADE watch.</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">From first scan to continuous monitoring in a few minutes.</p></div></FadeUp>
          <div className="space-y-3">{WORKFLOW_STEPS.map(({ icon, step, title, desc }, i) => <WorkflowStep key={step} icon={icon} step={step} title={title} desc={desc} index={i} />)}</div>
        </div>
      </section>

      {/* Coverage */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>Coverage</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">What gets tracked between every scan</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">Eight categories of security drift that WebHound watches over time.</p></div></FadeUp>
          <motion.div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4" variants={SC} initial="hidden" whileInView="show" viewport={{ once:true, margin:'-60px' }}>
            {MONITORS.map(({ icon: Icon, title, desc }) => (
              <motion.div key={title} variants={SI}><motion.div whileHover={{ y:-3, boxShadow:'0 0 20px rgba(139,255,62,0.08)' }} transition={{ duration:0.2 }} className="rounded-xl border border-white/[0.07] bg-[#111827] p-5 h-full group">
                <div className="w-9 h-9 rounded-lg bg-accent-green/10 flex items-center justify-center mb-3 group-hover:bg-accent-green/15 transition-colors"><Icon className="w-4 h-4 text-accent-green" /></div>
                <h3 className="text-sm font-semibold text-white mb-1.5">{title}</h3><p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
              </motion.div></motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Alerts */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>Alerts</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Notified when it matters</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">WebHound surfaces alerts in your dashboard as scans complete. You see what changed, what WADE flagged, and what needs attention.</p></div></FadeUp>
          <motion.div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4" variants={SC} initial="hidden" whileInView="show" viewport={{ once:true, margin:'-60px' }}>
            {ALERT_TYPES.map(({ icon: Icon, title, desc, live }) => (
              <motion.div key={title} variants={SI}><motion.div whileHover={{ y:-2 }} transition={{ duration:0.2 }} className={`rounded-xl border p-5 flex flex-col gap-3 h-full ${live?'border-white/[0.07] bg-[#111827]':'border-white/[0.05] bg-[#0F1520]'}`}>
                <div className="flex items-start justify-between gap-2">
                  <div className="w-9 h-9 rounded-lg bg-accent-green/10 flex items-center justify-center flex-shrink-0"><Icon className="w-4 h-4 text-accent-green" /></div>
                  {live ? <span className="inline-flex items-center gap-1 text-[9px] font-semibold uppercase tracking-widest px-1.5 py-0.5 rounded bg-accent-green/15 text-accent-green border border-accent-green/20"><span className="w-1 h-1 rounded-full bg-accent-green blink" />Live</span>
                    : <span className="text-[9px] font-semibold uppercase tracking-widest px-1.5 py-0.5 rounded bg-white/[0.05] text-gray-500 border border-white/[0.07]">Planned</span>}
                </div>
                <div><h3 className="text-sm font-semibold text-white mb-1">{title}</h3><p className="text-xs text-gray-500 leading-relaxed">{desc}</p></div>
              </motion.div></motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Use cases */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>Who It's For</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Built for teams without a security team</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">WebHound makes enterprise-grade website monitoring accessible to anyone running a live site.</p></div></FadeUp>
          <motion.div className="grid sm:grid-cols-2 gap-5" variants={SC} initial="hidden" whileInView="show" viewport={{ once:true, margin:'-60px' }}>
            {USE_CASES.map(({ icon: Icon, label, title, desc }) => (
              <motion.div key={label} variants={SI}><motion.div whileHover={{ y:-3 }} transition={{ duration:0.2 }} className="rounded-xl border border-white/[0.07] bg-[#111827] p-6 flex gap-4 h-full">
                <div className="flex-shrink-0"><div className="w-10 h-10 rounded-xl bg-accent-green/10 flex items-center justify-center"><Icon className="w-4 h-4 text-accent-green" /></div></div>
                <div>
                  <span className="inline-block text-[9px] font-semibold uppercase tracking-widest text-accent-green bg-accent-green/10 border border-accent-green/15 px-2 py-0.5 rounded-full mb-2">{label}</span>
                  <h3 className="text-sm font-semibold text-white mb-2">{title}</h3><p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
                </div>
              </motion.div></motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Dashboard preview */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>Dashboard</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Your monitoring command center</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">All your monitored websites, scan history, alerts, and WADE status in one view.</p></div></FadeUp>
          <FadeUp delay={0.1}>
            <div className="relative mx-auto max-w-3xl">
              <div className="absolute -inset-4 rounded-3xl bg-accent-green/[0.03] blur-3xl pointer-events-none" />
              <motion.div whileHover={{ scale:1.005 }} transition={{ duration:0.3 }} className="relative rounded-2xl border border-white/[0.10] bg-[#111827] overflow-hidden">
                <div className="scanline" />
                <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.06] bg-[#0D1520]">
                  <div className="flex gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-red-500/60" /><div className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" /><div className="w-2.5 h-2.5 rounded-full bg-green-500/60" /></div>
                  <div className="flex-1 mx-3 px-3 py-1 rounded bg-[#0B0F19] border border-white/[0.05] text-center"><span className="text-[10px] text-gray-500 font-mono">app.webhoundsecurity.com/dashboard/monitoring</span></div>
                  <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-accent-green blink" /><span className="text-[10px] text-accent-green font-mono">WATCHING</span></div>
                </div>
                <div className="p-4 grid grid-cols-2 lg:grid-cols-3 gap-3">
                  <div className="rounded-xl border border-white/[0.06] bg-[#0B0F19] p-3">
                    <p className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-2">Monitored Sites</p>
                    <div className="space-y-1.5">
                      {[{d:'example.com',s:'bg-accent-green blink'},{d:'shop.example.com',s:'bg-accent-green blink'},{d:'staging.example.com',s:'bg-yellow-400'}].map(site => (
                        <div key={site.d} className="flex items-center gap-2"><div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${site.s}`} /><span className="text-[10px] text-gray-400 font-mono truncate">{site.d}</span></div>
                      ))}
                    </div>
                  </div>
                  <div className="rounded-xl border border-white/[0.06] bg-[#0B0F19] p-3">
                    <p className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-2">Next Scan</p>
                    <p className="text-lg font-bold font-mono text-white leading-none">14h 22m</p>
                    <p className="text-[10px] text-gray-500 mt-1">example.com · Weekly</p>
                    <div className="h-1 rounded-full bg-white/[0.05] mt-2"><div className="h-full w-[40%] rounded-full bg-accent-green/50" /></div>
                  </div>
                  <div className="rounded-xl border border-white/[0.06] bg-[#0B0F19] p-3">
                    <p className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-2">Latest Risk</p>
                    <div className="flex items-center gap-3">
                      <div className="relative w-12 h-12 flex items-center justify-center flex-shrink-0">
                        <svg className="absolute inset-0 w-full h-full -rotate-90" viewBox="0 0 48 48">
                          <circle cx="24" cy="24" r="18" stroke="#1F2937" strokeWidth="4" fill="none" />
                          <circle cx="24" cy="24" r="18" stroke="#EAB308" strokeWidth="4" fill="none" strokeDasharray={`${2*Math.PI*18*0.42} ${2*Math.PI*18*0.58}`} strokeLinecap="round" />
                        </svg>
                        <span className="text-sm font-bold font-mono text-yellow-400">42</span>
                      </div>
                      <div><p className="text-[10px] font-semibold text-yellow-400">Medium</p><p className="text-[9px] text-gray-600 mt-0.5">example.com</p></div>
                    </div>
                  </div>
                  <div className="col-span-2 rounded-xl border border-white/[0.06] bg-[#0B0F19] p-3">
                    <p className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-2">Recent Alerts</p>
                    <div className="space-y-1.5">
                      {[{dot:'bg-orange-400 blink',t:'New third-party domain detected',time:'2h ago'},{dot:'bg-yellow-400',t:'WADE anomaly score increased',time:'1d ago'},{dot:'bg-blue-400',t:'Scheduled scan completed',time:'2d ago'}].map((a,i) => (
                        <div key={i} className="flex items-center gap-2 rounded-lg bg-[#111827] px-2.5 py-1.5"><div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${a.dot}`} /><span className="text-[9px] text-gray-400 truncate flex-1">{a.t}</span><span className="text-[9px] text-gray-600 font-mono flex-shrink-0">{a.time}</span></div>
                      ))}
                    </div>
                  </div>
                  <div className="rounded-xl border border-accent-green/20 bg-accent-green/[0.03] p-3">
                    <p className="text-[9px] font-mono text-accent-green/60 uppercase tracking-widest mb-2">WADE Score</p>
                    <div className="space-y-1.5">
                      <WadeBar label="W1" val={8} color="bg-accent-green" delay={0.2} />
                      <WadeBar label="W2" val={12} color="bg-accent-green" delay={0.35} />
                      <WadeBar label="W3" val={34} color="bg-yellow-400" delay={0.5} />
                      <WadeBar label="W4" val={58} color="bg-orange-400" delay={0.65} />
                    </div>
                    <p className="text-[9px] text-accent-green/60 mt-2.5">↑ Trending up — review recommended</p>
                  </div>
                </div>
                <div className="px-4 py-2.5 border-t border-white/[0.06] bg-[#0D1520] flex items-center justify-between">
                  <span className="text-[9px] text-gray-600 font-mono">3 sites monitored · WADE active · Powered by WebHound</span>
                  <span className="text-[9px] text-accent-green font-mono">View all scans →</span>
                </div>
              </motion.div>
            </div>
          </FadeUp>
        </div>
      </section>

      {/* Safety */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-4xl mx-auto">
          <FadeUp><div className="text-center mb-12"><SL>Safety</SL><h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Safe to run continuously, on any live site</h2><p className="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">Recurring monitoring is only useful if it's safe enough to run automatically — without worrying it will interfere with your site or visitors.</p></div></FadeUp>
          <motion.div className="grid sm:grid-cols-2 gap-5" variants={SC} initial="hidden" whileInView="show" viewport={{ once:true, margin:'-60px' }}>
            {SAFETY_POINTS.map(({ icon: Icon, title, desc }) => (
              <motion.div key={title} variants={SI}><motion.div whileHover={{ y:-2 }} transition={{ duration:0.2 }} className="rounded-xl border border-white/[0.07] bg-[#111827] p-6 flex gap-4 h-full">
                <div className="w-9 h-9 rounded-lg bg-accent-green/10 flex items-center justify-center flex-shrink-0"><Icon className="w-4 h-4 text-accent-green" /></div>
                <div><h3 className="text-sm font-semibold text-white mb-1.5">{title}</h3><p className="text-xs text-gray-500 leading-relaxed">{desc}</p></div>
              </motion.div></motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-24 px-5 border-t border-white/[0.05]">
        <div className="max-w-2xl mx-auto text-center">
          <FadeUp>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/25 bg-accent-green/[0.06] mb-6"><span className="w-1.5 h-1.5 rounded-full bg-accent-green blink" /><span className="text-xs font-semibold text-accent-green tracking-wide">Passive · Scheduled · WADE-Powered</span></div>
            <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">Start monitoring before a small change becomes a security problem.</h2>
            <p className="text-gray-400 mb-8 text-sm sm:text-base leading-relaxed max-w-lg mx-auto">Free to start. No installation. Set a schedule once and let WebHound watch.</p>
            <div className="flex flex-col sm:flex-row justify-center gap-3">
              <Link href="/dashboard" className="inline-flex items-center justify-center gap-2 px-8 py-3.5 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors">Start Monitoring <ArrowRight className="w-4 h-4" /></Link>
              <Link href="/pricing" className="inline-flex items-center justify-center px-8 py-3.5 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors">View Pricing</Link>
            </div>
            <div className="flex flex-wrap justify-center gap-x-6 gap-y-2 mt-8">
              {['Passive scanning','Scheduled automatically','WADE baseline comparison','Authorized targets only'].map(t => (
                <div key={t} className="flex items-center gap-1.5 text-xs text-gray-600"><CheckCircle className="w-3 h-3 text-gray-700 flex-shrink-0" />{t}</div>
              ))}
            </div>
          </FadeUp>
        </div>
      </section>
    </div>
  )
}
