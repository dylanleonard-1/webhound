'use client'

// WebHound — components/sections/FlagshipScanDemo.tsx
// Flagship interactive scan demo preview. Self-contained, front-end only.

import { useEffect, useMemo, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  AlertTriangle,
  ArrowRight,
  Check,
  Clock,
  Code2,
  FileText,
  Globe,
  Layers3,
  Lock,
  Maximize2,
  RefreshCcw,
  Shield,
  ShieldAlert,
  X,
} from 'lucide-react'

const GREEN = '#84ff00'

type Phase = 'idle' | 'discovering' | 'analyzing' | 'complete' | 'detail'

const ASSETS = [
  { label: 'Homepage', path: '/', icon: Globe, x: 8, y: 20 },
  { label: 'Collections', path: '/collections', icon: Layers3, x: 8, y: 50 },
  { label: 'Products', path: '/products', icon: Layers3, x: 8, y: 78 },
  { label: 'Contact Page', path: '/contact', icon: FileText, x: 78, y: 20 },
  { label: 'API Endpoints', path: '/api/*', icon: Code2, x: 78, y: 48 },
  { label: 'JS Assets', path: '/assets/*.js', icon: Code2, x: 78, y: 76 },
  { label: 'Login Page', path: '/login', icon: Lock, x: 44, y: 84 },
  { label: 'Admin Portal', path: '/admin', icon: ShieldAlert, x: 44, y: 12 },
]

const FINDINGS = [
  { severity: 'Critical', title: 'Admin Portal Found', body: 'Public admin endpoint discovered.', tone: '#ff5454' },
  { severity: 'High', title: 'Outdated JavaScript Library', body: 'jQuery 1.11.3 detected.', tone: '#ff9f43' },
  { severity: 'Medium', title: 'Missing Security Headers', body: 'X-Frame-Options not set.', tone: '#facc15' },
]

export function FlagshipScanDemo() {
  const reduce = useReducedMotion()
  const [phase, setPhase] = useState<Phase>('idle')
  const [assetStep, setAssetStep] = useState(0)
  const [findingStep, setFindingStep] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const [expanded, setExpanded] = useState(false)

  const running = phase === 'discovering' || phase === 'analyzing'

  useEffect(() => {
    if (!running) return
    const id = window.setInterval(() => setElapsed(v => v + 1), 1000)
    return () => window.clearInterval(id)
  }, [running])

  useEffect(() => {
    if (phase !== 'discovering' || reduce) return
    if (assetStep >= ASSETS.length) {
      const next = window.setTimeout(() => setPhase('analyzing'), 900)
      return () => window.clearTimeout(next)
    }
    const id = window.setTimeout(() => setAssetStep(v => v + 1), 520)
    return () => window.clearTimeout(id)
  }, [phase, assetStep, reduce])

  useEffect(() => {
    if (phase !== 'analyzing' || reduce) return
    if (findingStep >= FINDINGS.length) {
      const next = window.setTimeout(() => setPhase('complete'), 1100)
      return () => window.clearTimeout(next)
    }
    const id = window.setTimeout(() => setFindingStep(v => v + 1), 900)
    return () => window.clearTimeout(id)
  }, [phase, findingStep, reduce])

  const startScan = () => {
    setPhase('discovering')
    setElapsed(0)
    setAssetStep(0)
    setFindingStep(0)
  }

  const restart = () => {
    setPhase('idle')
    setElapsed(0)
    setAssetStep(0)
    setFindingStep(0)
  }

  const activeAssetCount = phase === 'idle' ? 0 : Math.round((assetStep / ASSETS.length) * 31)
  const activeTitle = getRailTitle(phase)
  const activeBody = getRailBody(phase)

  return (
    <section className="relative bg-[#020817] px-4 py-16 text-white sm:px-6 lg:px-8">
      <div className={`${expanded ? 'fixed inset-0 z-[100] overflow-auto bg-[#020817] p-3 sm:p-6' : 'mx-auto max-w-[1320px]'}`}>
        <div className="grid gap-5 lg:grid-cols-[280px_1fr]">
          {!expanded && <DemoRail phase={phase} assetStep={assetStep} findingStep={findingStep} title={activeTitle} body={activeBody} />}
          <div className={expanded ? 'mx-auto w-full max-w-[1180px]' : ''}>
            <div className="overflow-hidden rounded-[24px] border border-white/[0.08] bg-[radial-gradient(circle_at_50%_0%,rgba(132,255,0,0.08),transparent_34%),linear-gradient(180deg,rgba(6,12,24,0.98),rgba(2,8,23,0.98))] shadow-[0_28px_90px_rgba(0,0,0,0.45)]">
              <DemoTopBar phase={phase} elapsed={elapsed} expanded={expanded} onRestart={restart} onExpand={() => setExpanded(v => !v)} />
              <div className="relative min-h-[590px] overflow-hidden p-4 sm:p-6 lg:min-h-[620px]">
                <TelemetryField />
                {phase === 'idle' && <IdleScene onStart={startScan} />}
                {phase !== 'idle' && phase !== 'detail' && (
                  <ScanScene
                    phase={phase}
                    assetStep={assetStep}
                    findingStep={findingStep}
                    assetsFound={activeAssetCount}
                    onOpenCritical={() => setPhase('detail')}
                  />
                )}
                {phase === 'detail' && <DetailScene onBack={() => setPhase('complete')} />}
              </div>
              <div className="flex flex-wrap items-center justify-center gap-4 border-t border-white/[0.06] px-4 py-3 text-[11px] text-slate-400">
                <span className="inline-flex items-center gap-1"><Lock className="h-3 w-3" /> Read-only scan</span>
                <span>No changes made</span>
                <span>Takes about 2 minutes</span>
              </div>
            </div>
          </div>
        </div>
        {expanded && <button onClick={() => setExpanded(false)} className="fixed right-4 top-4 z-[110] rounded-full border border-white/10 bg-white/10 p-3 backdrop-blur-xl"><X className="h-5 w-5" /></button>}
      </div>
    </section>
  )
}

function getRailTitle(phase: Phase) {
  if (phase === 'idle') return 'See your website being checked in real time.'
  if (phase === 'discovering') return 'Mapping your website in real time.'
  if (phase === 'analyzing') return 'Analyzing for risks attackers could use.'
  if (phase === 'complete') return 'Scan complete. Findings are ready.'
  return 'WADE explains what this finding means.'
}

function getRailBody(phase: Phase) {
  if (phase === 'idle') return 'WebHound maps your website, checks for risks, and explains what to fix first.'
  if (phase === 'discovering') return 'WebHound is discovering pages, assets, and endpoints to build a complete picture of your attack surface.'
  if (phase === 'analyzing') return 'Findings appear one at a time as WebHound reviews the exposed surface.'
  if (phase === 'complete') return 'The final scan state is interactive. Click the critical finding to open the detailed report view.'
  return 'Recommendations, impact, and compliance context are translated into clear action.'
}

function DemoRail({ phase, assetStep, findingStep, title, body }: { phase: Phase; assetStep: number; findingStep: number; title: string; body: string }) {
  const steps = [
    ['Mapping website', phase !== 'idle' && assetStep >= 3],
    ['Discovering assets', phase !== 'idle' && assetStep >= ASSETS.length],
    ['Analyzing for risks', phase === 'analyzing' || phase === 'complete' || phase === 'detail'],
    ['Explaining findings', phase === 'complete' || phase === 'detail'],
    ['Report ready', phase === 'complete' || phase === 'detail'],
  ] as const
  return (
    <aside className="rounded-[24px] border border-white/[0.07] bg-white/[0.025] p-5 lg:sticky lg:top-24 lg:self-start">
      <div className="mb-10 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.18em]"><Shield className="h-5 w-5" style={{ color: GREEN }} /> WebHound</div>
      <p className="mb-3 text-[10px] font-bold uppercase tracking-[0.22em]" style={{ color: GREEN }}>Live scan demo</p>
      <h2 className="text-3xl font-bold leading-tight">{title}</h2>
      <p className="mt-4 text-sm leading-6 text-slate-400">{body}</p>
      <div className="mt-8 space-y-3">
        {steps.map(([label, done], i) => <div key={label} className="flex items-center gap-3 rounded-xl border border-white/[0.06] bg-black/20 p-3"><span className="flex h-6 w-6 items-center justify-center rounded-full text-[10px] font-bold" style={{ background: done ? 'rgba(132,255,0,0.12)' : 'rgba(255,255,255,0.04)', color: done ? GREEN : '#94a3b8' }}>{done ? <Check className="h-3 w-3" /> : i + 1}</span><span className="text-sm font-semibold text-slate-200">{label}</span></div>)}
      </div>
      {phase === 'analyzing' && <div className="mt-5 rounded-xl border border-red-500/20 bg-red-500/[0.04] p-3 text-sm text-red-200">Threat analysis: {findingStep} issues require attention</div>}
    </aside>
  )
}

function DemoTopBar({ phase, elapsed, expanded, onRestart, onExpand }: { phase: Phase; elapsed: number; expanded: boolean; onRestart: () => void; onExpand: () => void }) {
  const status = phase === 'idle' ? 'Live demo' : phase === 'complete' ? 'Scan complete' : phase === 'detail' ? 'Finding opened' : 'Scan running'
  return <div className="flex flex-wrap items-center gap-3 border-b border-white/[0.07] px-4 py-3 text-xs text-slate-300 sm:flex-nowrap"><span className="inline-flex items-center gap-2 rounded-full border border-white/[0.07] bg-black/25 px-3 py-1.5"><Globe className="h-3.5 w-3.5" /> northstarcommerce.com</span><span className="inline-flex items-center gap-2 rounded-full border border-white/[0.07] bg-black/25 px-3 py-1.5"><span className="h-1.5 w-1.5 rounded-full" style={{ background: GREEN }} /> {status}</span><span className="ml-auto inline-flex items-center gap-2"><Clock className="h-3.5 w-3.5" /> 00:00:{String(elapsed).padStart(2, '0')}</span><button onClick={onExpand} className="rounded-lg border border-white/[0.08] px-3 py-1.5 text-slate-300 hover:bg-white/[0.06]"><Maximize2 className="mr-1 inline h-3.5 w-3.5" /> {expanded ? 'Exit' : 'Expand'}</button><button onClick={onRestart} className="rounded-lg border border-white/[0.08] px-3 py-1.5 text-slate-300 hover:bg-white/[0.06]"><RefreshCcw className="mr-1 inline h-3.5 w-3.5" /> Restart</button></div>
}

function TelemetryField() {
  const dots = useMemo(() => Array.from({ length: 86 }, (_, i) => ({ i, left: (i * 37) % 100, top: (i * 61) % 100, delay: (i % 12) * 0.2, size: 1 + (i % 3) })), [])
  return <div className="pointer-events-none absolute inset-0 overflow-hidden opacity-55">{dots.map(d => <motion.span key={d.i} className="absolute rounded-full" style={{ left: `${d.left}%`, top: `${d.top}%`, width: d.size + 1, height: d.size + 1, background: 'rgba(132,255,0,0.28)', boxShadow: '0 0 10px rgba(132,255,0,0.16)' }} animate={{ x: [0, 22, -12, 0], y: [0, -18, 12, 0], opacity: [0.08, 0.45, 0.16] }} transition={{ duration: 6 + (d.i % 5), repeat: Infinity, delay: d.delay, ease: 'easeInOut' }} />)}<div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,transparent,rgba(2,8,23,0.88)_72%)]" /></div>
}

function IdleScene({ onStart }: { onStart: () => void }) {
  return <div className="relative z-10 grid min-h-[540px] place-items-center"><div className="w-full max-w-4xl"><WebsiteCard /><button onClick={onStart} className="mx-auto mt-7 flex w-full max-w-[420px] items-center justify-center gap-3 rounded-xl px-7 py-4 text-lg font-bold text-[#020817] shadow-[0_0_36px_rgba(132,255,0,0.22)]" style={{ background: `linear-gradient(135deg, ${GREEN}, #b6ff3f)` }}>Start Scan <ArrowRight className="h-5 w-5" /></button><p className="mt-4 text-center text-xs text-slate-400">Read-only scan · No changes made · Takes about 2 minutes</p></div></div>
}

function WebsiteCard({ scanning = false }: { scanning?: boolean }) {
  return <div className="relative mx-auto max-w-[640px] overflow-hidden rounded-[18px] border border-white/[0.08] bg-[#050b15] shadow-[0_25px_80px_rgba(0,0,0,0.45)]">{scanning && <motion.div className="absolute inset-y-0 z-20 w-24 bg-gradient-to-r from-transparent via-[rgba(132,255,0,0.16)] to-transparent" animate={{ x: [-120, 760] }} transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }} />}<div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-3 text-xs text-slate-400"><span>★ NORTHSTAR</span><span>Home · Shop · Collections · About · Contact</span></div><div className="grid min-h-[300px] grid-cols-2 gap-4 p-6"><div className="flex flex-col justify-center"><p className="text-xs" style={{ color: GREEN }}>Premium products.</p><h3 className="mt-4 text-3xl font-bold leading-tight">Built for performance.<br />Designed for growth.</h3><button className="mt-6 w-fit rounded-lg px-4 py-2 text-sm font-bold text-[#020817]" style={{ background: GREEN }}>Shop Now</button></div><div className="rounded-2xl bg-[radial-gradient(circle_at_50%_45%,rgba(255,255,255,0.16),transparent_36%),linear-gradient(135deg,#101827,#020817)]" /></div></div>
}

function ScanScene({ phase, assetStep, findingStep, assetsFound, onOpenCritical }: { phase: Phase; assetStep: number; findingStep: number; assetsFound: number; onOpenCritical: () => void }) {
  const showTrails = assetStep >= ASSETS.length
  return <div className="relative z-10 grid gap-5 lg:grid-cols-[1fr_300px]"><div className="relative min-h-[520px]"><WebsiteCard scanning={phase === 'discovering' || phase === 'analyzing'} />{showTrails && <TrailLayer />}{ASSETS.map((a, i) => <AssetNode key={a.label} item={a} active={i < assetStep} danger={a.label === 'Admin Portal' && phase !== 'discovering'} />)}<MetricStrip assets={assetsFound} findings={findingStep} risk={phase === 'complete' ? '72' : '--'} /></div><div className="space-y-3">{phase === 'discovering' && <StatusCard title="Discovering your attack surface..." body="Finding pages, assets, and endpoints." assets={assetsFound} />}{(phase === 'analyzing' || phase === 'complete') && <FindingsPanel count={findingStep} complete={phase === 'complete'} onOpenCritical={onOpenCritical} />}</div></div>
}

function TrailLayer() {
  return <svg className="pointer-events-none absolute inset-0 hidden h-full w-full lg:block" viewBox="0 0 100 100" preserveAspectRatio="none"><motion.path d="M50 50 C25 45 20 20 10 20 M50 50 C25 52 18 50 10 50 M50 50 C25 62 20 78 10 78 M50 50 C72 42 76 20 88 20 M50 50 C72 50 77 48 88 48 M50 50 C72 62 78 76 88 76 M50 50 C50 72 44 83 44 84 M50 50 C50 25 44 15 44 12" stroke="rgba(132,255,0,0.28)" strokeWidth="0.35" fill="none" strokeDasharray="2 3" initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 1.1, ease: 'easeInOut' }} /></svg>
}

function AssetNode({ item, active, danger }: { item: (typeof ASSETS)[number]; active: boolean; danger?: boolean }) {
  const Icon = item.icon
  return <motion.div className="absolute hidden rounded-xl border px-3 py-2 text-xs lg:block" style={{ left: `${item.x}%`, top: `${item.y}%`, borderColor: danger ? 'rgba(255,84,84,0.35)' : active ? 'rgba(132,255,0,0.24)' : 'rgba(255,255,255,0.08)', background: 'rgba(2,8,23,0.86)' }} initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: active ? 1 : 0, scale: active ? 1 : 0.94 }}><Icon className="mb-1 h-4 w-4" style={{ color: danger ? '#ff5454' : GREEN }} /><b>{item.label}</b><p className="text-[10px] text-slate-500">{item.path}</p><p className="mt-1 text-[10px]" style={{ color: danger ? '#ff8a8a' : GREEN }}>Discovered</p></motion.div>
}

function StatusCard({ title, body, assets }: { title: string; body: string; assets: number }) { return <div className="rounded-2xl border border-white/[0.08] bg-black/25 p-4"><p className="font-bold">{title}</p><p className="mt-1 text-sm text-slate-400">{body}</p><b className="mt-5 block text-4xl" style={{ color: GREEN }}>{assets}</b><p className="text-xs text-slate-500">assets discovered</p></div> }

function FindingsPanel({ count, complete, onOpenCritical }: { count: number; complete: boolean; onOpenCritical: () => void }) {
  return <div className="rounded-2xl border border-white/[0.08] bg-white/[0.035] p-4"><p className="mb-3 text-xs font-bold uppercase tracking-[0.2em] text-slate-400">Threat analysis</p>{FINDINGS.slice(0, count).map((f, i) => <motion.button key={f.title} onClick={complete && i === 0 ? onOpenCritical : undefined} initial={{ opacity: 0, x: 14 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.08 }} className="mb-3 block w-full rounded-xl border bg-black/25 p-3 text-left" style={{ borderColor: i === 0 ? 'rgba(255,84,84,0.3)' : 'rgba(255,255,255,0.08)' }}><p className="text-xs font-bold" style={{ color: f.tone }}>{f.severity}</p><p className="font-bold">{f.title}</p><p className="text-sm text-slate-400">{f.body}</p>{complete && i === 0 && <p className="mt-2 text-xs" style={{ color: GREEN }}>Click to open finding →</p>}</motion.button>)}</div>
}

function DetailScene({ onBack }: { onBack: () => void }) { return <div className="relative z-10 grid gap-5 lg:grid-cols-[1fr_360px]"><div className="rounded-2xl border border-white/[0.08] bg-white/[0.035] p-5"><button onClick={onBack} className="mb-5 text-sm text-slate-400">← Back to findings</button><p className="text-xs font-bold uppercase tracking-[0.2em] text-red-400">Critical</p><h3 className="mt-2 text-3xl font-bold">Admin Portal Exposed</h3><p className="mt-4 text-slate-400">Administrative interfaces are publicly accessible at <b className="text-white">/admin</b>.</p><div className="mt-5 grid gap-3 sm:grid-cols-2"><InfoBox title="Why it matters" body="Admin panels are frequent targets for credential attacks and takeover attempts." /><InfoBox title="Potential impact" body="Unauthorized access, account takeover, or full site compromise." /></div></div><div className="rounded-2xl border border-red-500/20 bg-red-500/[0.035] p-5"><p className="mb-3 font-bold">WADE Analysis</p><div className="grid grid-cols-3 gap-2 text-center text-xs"><span>Likelihood<br /><b className="text-red-300">High</b></span><span>Impact<br /><b className="text-red-300">High</b></span><span>Priority<br /><b style={{ color: GREEN }}>Fix First</b></span></div><p className="mt-5 text-sm leading-6 text-slate-400">Restrict access with MFA, VPN, IP allowlists, or administrative gateways.</p></div></div> }
function InfoBox({ title, body }: { title: string; body: string }) { return <div className="rounded-xl border border-white/[0.08] bg-black/25 p-4"><p className="font-bold">{title}</p><p className="mt-1 text-sm text-slate-400">{body}</p></div> }
function MetricStrip({ assets, findings, risk }: { assets: number; findings: number; risk: string }) { return <div className="mx-auto mt-5 grid max-w-[640px] grid-cols-3 rounded-2xl border border-white/[0.08] bg-black/25 p-4 text-center"><span><b className="block text-2xl" style={{ color: GREEN }}>{assets}</b><small className="text-slate-400">Assets Found</small></span><span><b className="block text-2xl">{findings}</b><small className="text-slate-400">Findings</small></span><span><b className="block text-2xl">{risk}</b><small className="text-slate-400">Risk Score</small></span></div> }
