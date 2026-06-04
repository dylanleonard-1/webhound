'use client'

// WebHound — components/sections/FlagshipScanDemo.tsx
// Premium interactive scan demo prototype. Self-contained, front-end only.

import { useEffect, useMemo, useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import {
  AlertTriangle,
  ArrowRight,
  Check,
  Clock,
  Code2,
  Expand,
  FileText,
  Globe,
  Layers3,
  Lock,
  Maximize2,
  RefreshCcw,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  X,
} from 'lucide-react'

const GREEN = '#84ff00'
const ACCENT = '#9eff00'

const SCENES = [
  { key: 'ready', label: 'Ready', status: 'Live demo', title: 'See your website being checked in real time.', rail: 'WebHound maps your website, checks for risks, and explains what to fix first.' },
  { key: 'discover', label: 'Discover', status: 'Scanning...', title: 'WebHound discovers public assets.', rail: 'Pages, scripts, logins, APIs, and admin surfaces are discovered safely.' },
  { key: 'analyze', label: 'Analyze', status: 'Analyzing...', title: 'WebHound analyzes what matters.', rail: 'Headers, certificates, cookies, scripts, third parties, and exposed paths are reviewed.' },
  { key: 'findings', label: 'Findings', status: 'Issues found', title: 'WebHound identifies real risks.', rail: 'Findings are grouped by severity so teams know what needs attention first.' },
  { key: 'detail', label: 'Explain', status: 'WADE review', title: 'WADE explains the critical finding.', rail: 'Risk, impact, and recommended fixes are translated into plain English.' },
  { key: 'report', label: 'Report', status: 'Complete', title: 'The report is ready.', rail: 'You get a clear report with assets, findings, severity, and next steps.' },
] as const

const ASSETS = [
  { label: 'Homepage', icon: Globe, x: 10, y: 18 },
  { label: 'Collections', icon: Layers3, x: 12, y: 50 },
  { label: 'Products', icon: Layers3, x: 13, y: 78 },
  { label: 'Contact', icon: FileText, x: 78, y: 20 },
  { label: 'JavaScript', icon: Code2, x: 78, y: 47 },
  { label: 'Login', icon: Lock, x: 80, y: 72 },
  { label: 'Admin', icon: ShieldAlert, x: 45, y: 88 },
  { label: 'API', icon: Code2, x: 45, y: 12 },
]

const ANALYSIS = [
  ['SSL Certificate', 'Valid certificate detected.'],
  ['JavaScript', '7 external scripts detected.'],
  ['Third Parties', '5 services detected.'],
  ['Admin Pages', 'Administrative endpoint discovered.'],
]

const FINDINGS = [
  ['Critical', 'Admin page exposed', '/admin'],
  ['High', 'Outdated JavaScript library', 'jQuery 1.x detected'],
  ['Medium', 'Missing security headers', 'X-Frame-Options not set'],
  ['Low', 'Third-party tracking scripts', 'Review vendor exposure'],
]

export function FlagshipScanDemo() {
  const reduce = useReducedMotion()
  const [scene, setScene] = useState(0)
  const [expanded, setExpanded] = useState(false)

  useEffect(() => {
    if (reduce) return
    const id = window.setInterval(() => setScene(current => (current + 1) % SCENES.length), 2100)
    return () => window.clearInterval(id)
  }, [reduce])

  const active = SCENES[scene]
  const elapsed = `00:00:${String(Math.max(1, scene * 2 + 2)).padStart(2, '0')}`

  return (
    <section className="relative bg-[#020817] px-4 py-16 text-white sm:px-6 lg:px-8">
      <div className={`${expanded ? 'fixed inset-0 z-[100] overflow-auto bg-[#020817] p-3 sm:p-6' : 'mx-auto max-w-[1320px]'}`}>
        <div className="grid gap-5 lg:grid-cols-[280px_1fr]">
          {!expanded && <DemoRail scene={scene} active={active} />}
          <div className={expanded ? 'mx-auto w-full max-w-[1180px]' : ''}>
            <div
              className="overflow-hidden rounded-[24px] border border-white/[0.08] bg-[radial-gradient(circle_at_50%_0%,rgba(132,255,0,0.08),transparent_34%),linear-gradient(180deg,rgba(6,12,24,0.98),rgba(2,8,23,0.98))] shadow-[0_28px_90px_rgba(0,0,0,0.45)]"
            >
              <DemoTopBar active={active} elapsed={elapsed} expanded={expanded} onRestart={() => setScene(0)} onExpand={() => setExpanded(v => !v)} />
              <div className="relative min-h-[580px] overflow-hidden p-4 sm:p-6 lg:min-h-[620px]">
                <TelemetryField />
                <AnimatePresence mode="wait">
                  <motion.div
                    key={active.key}
                    initial={{ opacity: 0, y: 14, scale: 0.985 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -10, scale: 0.99 }}
                    transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
                    className="relative z-10"
                  >
                    {scene <= 1 && <DiscoveryScene progress={scene === 0 ? 0 : 8} />}
                    {scene === 2 && <AnalysisScene />}
                    {scene === 3 && <FindingsScene />}
                    {scene === 4 && <DetailScene />}
                    {scene === 5 && <ReportScene />}
                  </motion.div>
                </AnimatePresence>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-4 border-t border-white/[0.06] px-4 py-3 text-[11px] text-slate-400">
                <span className="inline-flex items-center gap-1"><Lock className="h-3 w-3" /> Read-only scan</span>
                <span>No changes made</span>
                <span>Takes about 2 minutes</span>
              </div>
            </div>
          </div>
        </div>
        {expanded && (
          <button onClick={() => setExpanded(false)} className="fixed right-4 top-4 z-[110] rounded-full border border-white/10 bg-white/10 p-3 backdrop-blur-xl">
            <X className="h-5 w-5" />
          </button>
        )}
      </div>
    </section>
  )
}

function DemoRail({ scene, active }: { scene: number; active: (typeof SCENES)[number] }) {
  return (
    <aside className="rounded-[24px] border border-white/[0.07] bg-white/[0.025] p-5 lg:sticky lg:top-24 lg:self-start">
      <div className="mb-10 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.18em]"><Shield className="h-5 w-5" style={{ color: GREEN }} /> WebHound</div>
      <p className="mb-3 text-[10px] font-bold uppercase tracking-[0.22em]" style={{ color: GREEN }}>Live scan demo</p>
      <h2 className="text-3xl font-bold leading-tight">{active.title}</h2>
      <p className="mt-4 text-sm leading-6 text-slate-400">{active.rail}</p>
      <div className="mt-8 space-y-3">
        {SCENES.slice(1).map((s, i) => {
          const step = i + 1
          const done = scene > step
          const current = scene === step
          return (
            <div key={s.key} className="flex items-center gap-3 rounded-xl border border-white/[0.06] bg-black/20 p-3">
              <span className="flex h-6 w-6 items-center justify-center rounded-full text-[10px] font-bold" style={{ background: done || current ? 'rgba(132,255,0,0.12)' : 'rgba(255,255,255,0.04)', color: done || current ? GREEN : '#94a3b8' }}>{done ? <Check className="h-3 w-3" /> : step}</span>
              <span className="text-sm font-semibold text-slate-200">{s.label}</span>
            </div>
          )
        })}
      </div>
    </aside>
  )
}

function DemoTopBar({ active, elapsed, expanded, onRestart, onExpand }: { active: (typeof SCENES)[number]; elapsed: string; expanded: boolean; onRestart: () => void; onExpand: () => void }) {
  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-white/[0.07] px-4 py-3 text-xs text-slate-300 sm:flex-nowrap">
      <span className="inline-flex items-center gap-2 rounded-full border border-white/[0.07] bg-black/25 px-3 py-1.5"><Globe className="h-3.5 w-3.5" /> northstarcommerce.com</span>
      <span className="inline-flex items-center gap-2 rounded-full border border-white/[0.07] bg-black/25 px-3 py-1.5"><span className="h-1.5 w-1.5 rounded-full" style={{ background: GREEN }} /> {active.status}</span>
      <span className="ml-auto inline-flex items-center gap-2"><Clock className="h-3.5 w-3.5" /> {elapsed}</span>
      <button onClick={onExpand} className="rounded-lg border border-white/[0.08] px-3 py-1.5 text-slate-300 hover:bg-white/[0.06]"><Maximize2 className="mr-1 inline h-3.5 w-3.5" /> {expanded ? 'Exit' : 'Expand'}</button>
      <button onClick={onRestart} className="rounded-lg border border-white/[0.08] px-3 py-1.5 text-slate-300 hover:bg-white/[0.06]"><RefreshCcw className="mr-1 inline h-3.5 w-3.5" /> Restart</button>
    </div>
  )
}

function TelemetryField() {
  const dots = useMemo(() => Array.from({ length: 72 }, (_, i) => ({ i, left: (i * 37) % 100, top: (i * 61) % 100, delay: (i % 12) * 0.2, size: 1 + (i % 3) })), [])
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden opacity-70">
      {dots.map(d => <motion.span key={d.i} className="absolute rounded-full" style={{ left: `${d.left}%`, top: `${d.top}%`, width: d.size + 1, height: d.size + 1, background: 'rgba(132,255,0,0.34)', boxShadow: '0 0 10px rgba(132,255,0,0.22)' }} animate={{ x: [0, 22, -12, 0], y: [0, -18, 12, 0], opacity: [0.12, 0.55, 0.2] }} transition={{ duration: 6 + (d.i % 5), repeat: Infinity, delay: d.delay, ease: 'easeInOut' }} />)}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,transparent,rgba(2,8,23,0.88)_72%)]" />
    </div>
  )
}

function WebsiteCard({ scanning = false }: { scanning?: boolean }) {
  return (
    <div className="relative mx-auto max-w-[640px] overflow-hidden rounded-[18px] border border-white/[0.08] bg-[#050b15] shadow-[0_25px_80px_rgba(0,0,0,0.45)]">
      {scanning && <motion.div className="absolute inset-y-0 z-20 w-24 bg-gradient-to-r from-transparent via-[rgba(132,255,0,0.16)] to-transparent" animate={{ x: [-120, 760] }} transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }} />}
      <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-3 text-xs text-slate-400"><span>★ NORTHSTAR</span><span>Home · Shop · Collections · Contact</span></div>
      <div className="grid min-h-[300px] grid-cols-2 gap-4 p-6">
        <div className="flex flex-col justify-center"><p className="text-xs" style={{ color: GREEN }}>Premium products.</p><h3 className="mt-4 text-3xl font-bold leading-tight">Built for performance.<br />Designed for growth.</h3><button className="mt-6 w-fit rounded-lg px-4 py-2 text-sm font-bold text-[#020817]" style={{ background: GREEN }}>Shop Now</button></div>
        <div className="rounded-2xl bg-[radial-gradient(circle_at_50%_45%,rgba(255,255,255,0.16),transparent_36%),linear-gradient(135deg,#101827,#020817)]" />
      </div>
    </div>
  )
}

function DiscoveryScene({ progress }: { progress: number }) {
  return <div className="relative pt-8"><WebsiteCard />{ASSETS.map((a, i) => <AssetNode key={a.label} item={a} active={i < progress} delay={i * 0.08} />)}<MetricStrip assets={progress ? 31 : 0} findings={0} risk="--" /></div>
}

function AssetNode({ item, active, delay }: { item: (typeof ASSETS)[number]; active: boolean; delay: number }) {
  const Icon = item.icon
  return <motion.div className="absolute hidden rounded-xl border px-3 py-2 text-xs lg:block" style={{ left: `${item.x}%`, top: `${item.y}%`, borderColor: active ? 'rgba(132,255,0,0.24)' : 'rgba(255,255,255,0.08)', background: 'rgba(2,8,23,0.82)' }} initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: active ? 1 : 0.35, scale: active ? 1 : 0.94 }} transition={{ delay }}><Icon className="mb-1 h-4 w-4" style={{ color: active ? GREEN : '#64748b' }} />{item.label}</motion.div>
}

function AnalysisScene() { return <div className="grid gap-5 lg:grid-cols-[1fr_320px]"><div><WebsiteCard scanning /><MetricStrip assets={31} findings={0} risk="--" /></div><div className="space-y-3">{ANALYSIS.map((a, i) => <InfoCard key={a[0]} title={a[0]} body={a[1]} delay={i * 0.08} />)}</div></div> }
function FindingsScene() { return <div className="grid gap-5 lg:grid-cols-[1fr_340px]"><div><WebsiteCard scanning /><MetricStrip assets={31} findings={4} risk="64" /></div><FindingsPanel /></div> }
function DetailScene() { return <div className="grid gap-5 lg:grid-cols-[1fr_360px]"><DetailPanel /><WadePanel /></div> }
function ReportScene() { return <div className="mx-auto max-w-3xl py-12 text-center"><motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full border border-white/[0.08] bg-white/[0.04]"><Check className="h-8 w-8" style={{ color: GREEN }} /></motion.div><h3 className="text-4xl font-bold">Scan Complete</h3><p className="mt-3 text-slate-400">Full report ready.</p><MetricStrip assets={38} findings={22} risk="72" /><div className="mt-8 flex flex-col justify-center gap-3 sm:flex-row"><button className="rounded-xl px-5 py-3 font-bold text-[#020817]" style={{ background: GREEN }}>View Report</button><button className="rounded-xl border border-white/[0.08] px-5 py-3 font-bold text-white">Start Free Scan</button></div></div> }

function InfoCard({ title, body, delay }: { title: string; body: string; delay: number }) { return <motion.div initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }} transition={{ delay }} className="rounded-2xl border border-white/[0.08] bg-white/[0.035] p-4"><p className="font-bold">{title}</p><p className="mt-1 text-sm text-slate-400">{body}</p></motion.div> }
function FindingsPanel() { return <div className="rounded-2xl border border-white/[0.08] bg-white/[0.035] p-4"><p className="mb-3 text-xs font-bold uppercase tracking-[0.2em] text-slate-400">Findings</p>{FINDINGS.map((f, i) => <motion.div key={f[1]} initial={{ opacity: 0, x: 14 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.12 }} className="mb-3 rounded-xl border border-white/[0.08] bg-black/25 p-3"><p className="text-xs font-bold" style={{ color: f[0] === 'Critical' ? '#ff6464' : GREEN }}>{f[0]}</p><p className="font-bold">{f[1]}</p><p className="text-sm text-slate-400">{f[2]}</p></motion.div>)}</div> }
function DetailPanel() { return <div className="rounded-2xl border border-white/[0.08] bg-white/[0.035] p-5"><p className="text-xs font-bold uppercase tracking-[0.2em] text-red-400">Critical</p><h3 className="mt-2 text-3xl font-bold">Admin Portal Exposed</h3><p className="mt-4 text-slate-400">Administrative interfaces are publicly accessible.</p><div className="mt-5 grid gap-3 sm:grid-cols-2"><InfoCard title="Risk" body="Admin panels are frequently targeted by attackers." delay={0} /><InfoCard title="Recommendation" body="Restrict access with MFA, VPN, IP allowlists, or admin gateways." delay={0.05} /></div></div> }
function WadePanel() { return <div className="rounded-2xl border border-red-500/20 bg-red-500/[0.035] p-5"><p className="mb-3 font-bold">WADE Analysis</p><div className="grid grid-cols-3 gap-2 text-center text-xs"><span>Likelihood<br /><b className="text-red-300">High</b></span><span>Impact<br /><b className="text-red-300">High</b></span><span>Priority<br /><b style={{ color: GREEN }}>Fix First</b></span></div><p className="mt-5 text-sm leading-6 text-slate-400">WADE has identified this as a high-risk exposure that should be addressed immediately.</p></div> }
function MetricStrip({ assets, findings, risk }: { assets: number; findings: number; risk: string }) { return <div className="mx-auto mt-5 grid max-w-[640px] grid-cols-3 rounded-2xl border border-white/[0.08] bg-black/25 p-4 text-center"><span><b className="block text-2xl" style={{ color: GREEN }}>{assets}</b><small className="text-slate-400">Assets Found</small></span><span><b className="block text-2xl">{findings}</b><small className="text-slate-400">Findings</small></span><span><b className="block text-2xl">{risk}</b><small className="text-slate-400">Risk Score</small></span></div> }
