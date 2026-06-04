'use client'

// WebHound — components/sections/FlagshipScanDemo.tsx
// Cinematic flagship scan demo preview. Mobile gets a guided native layout.

import Image from 'next/image'
import { useEffect, useMemo, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
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
  { label: 'Homepage', path: '/', icon: Globe, x: 5, y: 18 },
  { label: 'Collections', path: '/collections', icon: Layers3, x: 5, y: 48 },
  { label: 'Products', path: '/products', icon: Layers3, x: 5, y: 76 },
  { label: 'Contact Page', path: '/contact', icon: FileText, x: 82, y: 18 },
  { label: 'API Endpoints', path: '/api/*', icon: Code2, x: 82, y: 48 },
  { label: 'JS Assets', path: '/assets/*.js', icon: Code2, x: 82, y: 76 },
  { label: 'Login Page', path: '/login', icon: Lock, x: 48, y: 82 },
  { label: 'Admin Portal', path: '/admin', icon: ShieldAlert, x: 48, y: 12 },
]

const FINDINGS = [
  { severity: 'CRITICAL', title: 'Admin Portal Found', body: 'This admin portal is publicly accessible and not protected by authentication.', tone: '#ff5454' },
  { severity: 'HIGH', title: 'Outdated JavaScript Library', body: 'Known vulnerable library detected.', tone: '#ff9f43' },
  { severity: 'MEDIUM', title: 'Missing Security Headers', body: 'Missing browser protection headers.', tone: '#facc15' },
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
      const next = window.setTimeout(() => setPhase('analyzing'), 1400)
      return () => window.clearTimeout(next)
    }
    const id = window.setTimeout(() => setAssetStep(v => v + 1), 950)
    return () => window.clearTimeout(id)
  }, [phase, assetStep, reduce])

  useEffect(() => {
    if (phase !== 'analyzing' || reduce) return
    if (findingStep >= FINDINGS.length) {
      const next = window.setTimeout(() => setPhase('complete'), 1600)
      return () => window.clearTimeout(next)
    }
    const id = window.setTimeout(() => setFindingStep(v => v + 1), 1400)
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

  const assetsFound = phase === 'idle' ? 0 : Math.round((assetStep / ASSETS.length) * 31)
  const progress = getScanProgress(phase, assetStep, findingStep)

  return (
    <section className="relative min-h-screen overflow-hidden bg-[#020817] px-3 py-6 text-white sm:py-10">
      <div className="mx-auto block w-full max-w-[460px] lg:hidden">
        <MobileDemo phase={phase} elapsed={elapsed} assetStep={assetStep} findingStep={findingStep} assetsFound={assetsFound} progress={progress} onStart={startScan} onRestart={restart} onOpenCritical={() => setPhase('detail')} />
      </div>

      <div className={expanded ? 'fixed inset-0 z-[100] hidden place-items-center overflow-auto bg-[#020817] p-3 lg:grid' : 'mx-auto hidden w-full max-w-[1500px] place-items-center overflow-hidden lg:grid'}>
        <div className="w-[1320px]">
          <div className="grid grid-cols-[270px_1fr] gap-5 rounded-[30px] border border-white/[0.06] bg-[radial-gradient(circle_at_55%_0%,rgba(132,255,0,0.07),transparent_34%),linear-gradient(180deg,rgba(4,10,22,0.98),rgba(2,8,23,0.98))] p-5 shadow-[0_35px_120px_rgba(0,0,0,0.55)]">
            {!expanded && <NarratorRail phase={phase} assetStep={assetStep} findingStep={findingStep} />}
            <main className={expanded ? 'col-span-2' : ''}>
              <div className="overflow-hidden rounded-[18px] border border-[rgba(132,255,0,0.18)] bg-[#06101a]/90 shadow-[0_0_38px_rgba(132,255,0,0.06)]">
                <DemoTopBar phase={phase} elapsed={elapsed} expanded={expanded} onRestart={restart} onExpand={() => setExpanded(v => !v)} />
                <div className="relative h-[610px] overflow-hidden p-6">
                  <TelemetryField />
                  {phase === 'idle' && <IdleStage onStart={startScan} />}
                  {phase !== 'idle' && phase !== 'detail' && <ScanStage phase={phase} assetStep={assetStep} findingStep={findingStep} assetsFound={assetsFound} progress={progress} onOpenCritical={() => setPhase('detail')} />}
                  {phase === 'detail' && <DetailStage onBack={() => setPhase('complete')} />}
                </div>
                <div className="flex items-center justify-center gap-5 border-t border-white/[0.06] px-5 py-3 text-xs text-slate-500">
                  <span className="inline-flex items-center gap-1"><Lock className="h-3.5 w-3.5" /> Read-only scan</span>
                  <span>No changes made</span>
                  <span>Takes about 2 minutes</span>
                </div>
              </div>
            </main>
          </div>
        </div>
        {expanded && <button onClick={() => setExpanded(false)} className="fixed right-4 top-4 z-[110] rounded-full border border-white/10 bg-white/10 p-3 backdrop-blur-xl"><X className="h-5 w-5" /></button>}
      </div>
    </section>
  )
}

function getScanProgress(phase: Phase, assetStep: number, findingStep: number) {
  if (phase === 'idle') return 0
  if (phase === 'discovering') return Math.min(62, 8 + Math.round((assetStep / ASSETS.length) * 54))
  if (phase === 'analyzing') return Math.min(92, 64 + Math.round((findingStep / FINDINGS.length) * 28))
  if (phase === 'complete' || phase === 'detail') return 100
  return 0
}

function getStory(phase: Phase, assetStep: number, findingStep: number) {
  if (phase === 'idle') return { step: 'Ready', title: 'Ready to scan', body: 'Click Start Scan to see how WebHound checks the website safely.', next: 'Next: discover public pages and assets.' }
  if (phase === 'discovering') {
    const current = ASSETS[Math.max(0, Math.min(assetStep - 1, ASSETS.length - 1))]
    const next = ASSETS[Math.min(assetStep, ASSETS.length - 1)]
    return { step: 'Step 1 of 4', title: 'Discovering your website', body: current ? `Found ${current.label}: ${current.path}` : 'WebHound is finding public pages, scripts, APIs, and login areas.', next: assetStep >= ASSETS.length ? 'Next: analyze the discovered attack surface.' : `Next: ${next.label}` }
  }
  if (phase === 'analyzing') {
    const current = FINDINGS[Math.max(0, Math.min(findingStep - 1, FINDINGS.length - 1))]
    const next = FINDINGS[Math.min(findingStep, FINDINGS.length - 1)]
    return { step: 'Step 2 of 4', title: 'Analyzing security risks', body: current ? `Finding ${Math.max(1, findingStep)} of ${FINDINGS.length}: ${current.title}` : 'WebHound is reviewing the discovered surfaces for risk.', next: findingStep >= FINDINGS.length ? 'Next: prepare the report.' : `Next: ${next.title}` }
  }
  if (phase === 'complete') return { step: 'Step 3 of 4', title: 'Report ready', body: 'WebHound found the most important risks and prepared a clear report.', next: 'Tap the critical finding to see the explanation.' }
  return { step: 'Step 4 of 4', title: 'Finding explained', body: 'WADE translates the risk, impact, and recommended fix into plain English.', next: 'Restart the demo or return to findings.' }
}

function scanStatusText(phase: Phase, assetStep: number, findingStep: number) {
  return getStory(phase, assetStep, findingStep).body
}

function StoryCard({ phase, assetStep, findingStep }: { phase: Phase; assetStep: number; findingStep: number }) {
  const story = getStory(phase, assetStep, findingStep)
  return (
    <div className="rounded-2xl border border-white/[0.08] bg-black/35 p-4 backdrop-blur">
      <p className="text-[10px] font-bold uppercase tracking-[0.2em]" style={{ color: GREEN }}>{story.step}</p>
      <h3 className="mt-2 text-xl font-bold text-white">{story.title}</h3>
      <p className="mt-2 text-sm leading-6 text-slate-400">{story.body}</p>
      <p className="mt-3 text-xs font-semibold text-slate-500">{story.next}</p>
    </div>
  )
}

function ScanProgressBar({ phase, assetStep, findingStep, progress }: { phase: Phase; assetStep: number; findingStep: number; progress: number }) {
  return (
    <div className="rounded-2xl border border-white/[0.08] bg-black/35 p-4 backdrop-blur">
      <div className="mb-3 flex items-center justify-between gap-3">
        <p className="text-xs font-bold uppercase tracking-[0.18em]" style={{ color: GREEN }}>{phase === 'complete' ? 'Scan complete' : phase === 'idle' ? 'Scan ready' : 'Scan in progress'}</p>
        <p className="text-xs text-slate-400">{progress}%</p>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-white/[0.08]">
        <motion.div className="h-full rounded-full" style={{ background: `linear-gradient(90deg, ${GREEN}, #b6ff3f)`, boxShadow: '0 0 18px rgba(132,255,0,0.28)' }} animate={{ width: `${progress}%` }} transition={{ duration: 0.65, ease: [0.22, 1, 0.36, 1] }} />
      </div>
      <p className="mt-3 text-sm text-slate-400">{phase === 'complete' ? 'The scan is complete. Open a finding to see the explanation.' : scanStatusText(phase, assetStep, findingStep)}</p>
    </div>
  )
}

function MobileDemo({ phase, elapsed, assetStep, findingStep, assetsFound, progress, onStart, onRestart, onOpenCritical }: { phase: Phase; elapsed: number; assetStep: number; findingStep: number; assetsFound: number; progress: number; onStart: () => void; onRestart: () => void; onOpenCritical: () => void }) {
  return (
    <div className="overflow-hidden rounded-[28px] border border-white/[0.07] bg-[radial-gradient(circle_at_50%_0%,rgba(132,255,0,0.08),transparent_36%),linear-gradient(180deg,rgba(5,11,24,0.98),rgba(2,8,23,0.98))] shadow-[0_28px_80px_rgba(0,0,0,0.5)]">
      <div className="p-5">
        <div className="mb-8 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.18em]"><Shield className="h-5 w-5" style={{ color: GREEN }} /> WebHound</div>
        <p className="mb-3 text-[10px] font-bold uppercase tracking-[0.22em]" style={{ color: GREEN }}>Live scan demo</p>
        <h1 className="text-[32px] font-bold leading-[1.05]">See your website being checked <span style={{ color: GREEN }}>in real time.</span></h1>
        <p className="mt-4 text-sm leading-6 text-slate-400">WebHound maps your website, checks for risks, and explains what to fix first.</p>
      </div>

      <div className="border-y border-white/[0.06] bg-black/15 px-4 py-3">
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-300">
          <span className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-black/25 px-3 py-1.5"><Globe className="h-3.5 w-3.5" /> northstarcommerce.com</span>
          <span className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-black/25 px-3 py-1.5"><span className="h-1.5 w-1.5 rounded-full" style={{ background: GREEN }} /> {phase === 'idle' ? 'Live demo' : phase === 'complete' ? 'Scan complete' : phase === 'detail' ? 'Finding opened' : 'Scan running'}</span>
          <span className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-black/25 px-3 py-1.5"><Clock className="h-3.5 w-3.5" /> 00:00:{String(elapsed).padStart(2, '0')}</span>
          <button onClick={onRestart} className="rounded-full border border-white/[0.08] bg-black/25 px-3 py-1.5"><RefreshCcw className="mr-1 inline h-3.5 w-3.5" />Restart</button>
        </div>
      </div>

      <div className="relative min-h-[440px] overflow-hidden p-4">
        <TelemetryField />
        {phase === 'idle' && <div className="relative z-10 space-y-4"><StoryCard phase={phase} assetStep={assetStep} findingStep={findingStep} /><WebsiteCard large /><button onClick={onStart} className="mx-auto flex w-full items-center justify-center gap-3 rounded-xl px-5 py-4 text-lg font-bold text-[#020817] shadow-[0_0_34px_rgba(132,255,0,0.2)]" style={{ background: `linear-gradient(135deg, ${GREEN}, #b6ff3f)` }}>Start Scan <ArrowRight className="h-5 w-5" /></button></div>}
        {phase !== 'idle' && phase !== 'detail' && <MobileScanStage phase={phase} assetStep={assetStep} findingStep={findingStep} assetsFound={assetsFound} progress={progress} onOpenCritical={onOpenCritical} />}
        {phase === 'detail' && <div className="space-y-4"><StoryCard phase={phase} assetStep={assetStep} findingStep={findingStep} /><MobileDetail /></div>}
      </div>

      <div className="flex items-center justify-center gap-3 border-t border-white/[0.06] px-4 py-3 text-[11px] text-slate-500">
        <span>Read-only scan</span><span>No changes made</span><span>Takes about 2 minutes</span>
      </div>
    </div>
  )
}

function MobileScanStage({ phase, assetStep, findingStep, assetsFound, progress, onOpenCritical }: { phase: Phase; assetStep: number; findingStep: number; assetsFound: number; progress: number; onOpenCritical: () => void }) {
  const recentAssets = ASSETS.slice(Math.max(0, assetStep - 2), Math.min(assetStep, ASSETS.length))
  return (
    <div className="relative z-10 space-y-4">
      <WebsiteCard scanning />
      <StoryCard phase={phase} assetStep={assetStep} findingStep={findingStep} />
      <ScanProgressBar phase={phase} assetStep={assetStep} findingStep={findingStep} progress={progress} />
      {phase === 'discovering' && <div className="rounded-2xl border border-white/[0.08] bg-black/30 p-4"><div className="flex items-end justify-between"><div><p className="font-bold">Assets discovered</p><p className="mt-1 text-sm text-slate-400">Latest surfaces found by WebHound.</p></div><div><b className="block text-right text-4xl" style={{ color: GREEN }}>{assetsFound}</b><p className="text-xs text-slate-500">total</p></div></div>{recentAssets.length > 0 && <div className="mt-4 space-y-2">{recentAssets.map(asset => <div key={asset.label} className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-white/[0.03] px-3 py-2"><span className="text-sm font-semibold">{asset.label}</span><span className="text-xs" style={{ color: GREEN }}>Discovered</span></div>)}</div>}</div>}
      {phase === 'analyzing' && <FindingsPanelMobile count={findingStep} complete={false} onOpenCritical={onOpenCritical} />}
      {phase === 'complete' && <CompleteSummary onOpenCritical={onOpenCritical} />}
    </div>
  )
}

function CompleteSummary({ onOpenCritical }: { onOpenCritical: () => void }) {
  return <div className="rounded-2xl border border-white/[0.08] bg-black/35 p-4"><p className="text-[10px] font-bold uppercase tracking-[0.18em]" style={{ color: GREEN }}>What WebHound found</p><div className="mt-4 grid grid-cols-3 gap-2 text-center"><div className="rounded-xl bg-white/[0.04] p-3"><b className="block text-2xl">31</b><span className="text-[10px] text-slate-500">Assets</span></div><div className="rounded-xl bg-white/[0.04] p-3"><b className="block text-2xl">3</b><span className="text-[10px] text-slate-500">Findings</span></div><div className="rounded-xl bg-white/[0.04] p-3"><b className="block text-2xl text-red-300">1</b><span className="text-[10px] text-slate-500">Critical</span></div></div><button onClick={onOpenCritical} className="mt-4 block w-full rounded-xl border border-red-500/30 bg-red-500/[0.04] p-4 text-left"><p className="text-[10px] font-bold uppercase tracking-[0.16em] text-red-300">Critical</p><p className="mt-1 font-bold">Admin Portal Found</p><p className="mt-1 text-xs text-slate-400">Tap to see the risk and recommended fix.</p><p className="mt-2 text-xs" style={{ color: GREEN }}>Open finding →</p></button></div>
}

function FindingsPanelMobile({ count, complete, onOpenCritical }: { count: number; complete: boolean; onOpenCritical: () => void }) {
  const visible = FINDINGS.slice(Math.max(0, count - 1), count)
  return <div className="space-y-3">{visible.map(f => <button key={f.title} onClick={complete && f.severity === 'CRITICAL' ? onOpenCritical : undefined} className="block w-full rounded-xl border bg-black/35 p-4 text-left" style={{ borderColor: f.severity === 'CRITICAL' ? 'rgba(255,84,84,0.35)' : 'rgba(255,255,255,0.08)' }}><p className="text-[10px] font-bold uppercase tracking-[0.16em]" style={{ color: f.tone }}>{f.severity}</p><p className="mt-1 font-bold">{f.title}</p><p className="mt-1 text-xs leading-5 text-slate-400">{f.body}</p></button>)}</div>
}

function MobileDetail() { return <div className="relative z-10 rounded-2xl border border-red-500/20 bg-red-500/[0.035] p-5"><p className="text-xs font-bold uppercase tracking-[0.2em] text-red-400">Critical</p><h3 className="mt-2 text-2xl font-bold">Admin Portal Exposed</h3><p className="mt-3 text-sm text-slate-400">Administrative interfaces are publicly accessible at /admin.</p><div className="mt-5 space-y-3"><InfoBox title="Why it matters" body="Admin panels are frequent targets for credential attacks and account takeover." /><InfoBox title="Recommendation" body="Restrict access with MFA, VPN, IP allowlists, or admin gateways." /></div></div> }

function NarratorRail({ phase, assetStep, findingStep }: { phase: Phase; assetStep: number; findingStep: number }) {
  const title = phase === 'discovering' ? 'Mapping your website in real time.' : phase === 'analyzing' || phase === 'complete' ? 'See your website being checked in real time.' : phase === 'detail' ? 'Understand what needs fixing first.' : 'See your website being checked in real time.'
  const body = phase === 'discovering' ? 'WebHound is discovering your pages, assets, and endpoints to build a complete picture of your attack surface.' : phase === 'analyzing' ? 'WebHound finds risks attackers could use and shows what to fix first.' : phase === 'detail' ? 'WADE explains the risk, impact, and recommended fixes.' : 'WebHound maps your website, checks for risks, and explains what to fix first.'
  const steps = [
    ['Map your entire site', assetStep >= 3 || phase !== 'idle'],
    ['Find security issues', phase === 'analyzing' || phase === 'complete' || phase === 'detail'],
    ['Get clear explanations', phase === 'complete' || phase === 'detail'],
  ] as const
  return <aside className="relative flex min-h-[700px] flex-col rounded-[22px] p-6"><div className="mb-12 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.14em]"><Shield className="h-5 w-5" style={{ color: GREEN }} /> WebHound</div><p className="mb-4 text-[11px] font-bold uppercase tracking-[0.2em]" style={{ color: GREEN }}>Live scan demo</p><h1 className="text-[34px] font-bold leading-[1.05]">{title.includes('real time') ? <>See your website being checked <span style={{ color: GREEN }}>in real time.</span></> : title}</h1><p className="mt-5 text-[14px] leading-6 text-slate-400">{body}</p><div className="mt-8 space-y-4">{steps.map(([label, done], i) => <div key={label} className="flex gap-3"><span className="mt-1 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-white/[0.07] bg-black/25"><Check className="h-4 w-4" style={{ color: done ? GREEN : '#475569' }} /></span><div><p className="text-sm font-bold text-slate-200">{label}</p><p className="mt-1 text-[11px] leading-4 text-slate-500">{i === 0 ? 'We discover pages, assets, and endpoints.' : i === 1 ? 'We analyze for vulnerabilities attackers could use.' : 'We show what it means and how to fix it.'}</p></div></div>)}</div>{phase === 'analyzing' && <div className="mt-7 rounded-2xl border border-red-500/20 bg-red-500/[0.04] p-4"><p className="text-xs font-bold uppercase tracking-[0.16em] text-red-300">Threat analysis</p><p className="mt-2 text-sm text-slate-300">{findingStep} issues require attention</p></div>}<div className="mt-auto space-y-3 text-xs text-slate-500"><p className="inline-flex items-center gap-2"><Lock className="h-3.5 w-3.5" /> Read-only scan · No changes made</p><p>Takes about 2 minutes</p></div></aside>
}

function DemoTopBar({ phase, elapsed, expanded, onRestart, onExpand }: { phase: Phase; elapsed: number; expanded: boolean; onRestart: () => void; onExpand: () => void }) {
  const status = phase === 'idle' ? 'Live demo' : phase === 'complete' ? 'Scan complete' : phase === 'detail' ? 'Finding opened' : 'Scan running'
  return <div className="flex h-14 items-center gap-3 border-b border-white/[0.07] px-5 text-xs text-slate-300"><span className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-black/25 px-3 py-1.5"><Globe className="h-3.5 w-3.5" /> northstarcommerce.com</span><span className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-black/25 px-3 py-1.5"><span className="h-1.5 w-1.5 rounded-full" style={{ background: GREEN }} /> {status}</span><span className="ml-auto inline-flex items-center gap-2"><Clock className="h-3.5 w-3.5" /> 00:00:{String(elapsed).padStart(2, '0')}</span><button onClick={onExpand} className="rounded-lg border border-white/[0.08] px-3 py-1.5 text-slate-300"><Maximize2 className="mr-1 inline h-3.5 w-3.5" /> {expanded ? 'Exit' : 'Maximize'}</button><button onClick={onRestart} className="rounded-lg border border-white/[0.08] px-3 py-1.5 text-slate-300"><RefreshCcw className="mr-1 inline h-3.5 w-3.5" /> Restart</button></div>
}

function TelemetryField() {
  const dots = useMemo(() => Array.from({ length: 120 }, (_, i) => ({ i, left: (i * 37) % 100, top: (i * 61) % 100, delay: (i % 18) * 0.18, size: 1 + (i % 3) })), [])
  return <div className="pointer-events-none absolute inset-0 overflow-hidden opacity-45">{dots.map(d => <motion.span key={d.i} className="absolute rounded-full" style={{ left: `${d.left}%`, top: `${d.top}%`, width: d.size + 1, height: d.size + 1, background: 'rgba(132,255,0,0.26)', boxShadow: '0 0 10px rgba(132,255,0,0.15)' }} animate={{ x: [0, 26, -14, 0], y: [0, -20, 12, 0], opacity: [0.08, 0.42, 0.15] }} transition={{ duration: 6 + (d.i % 5), repeat: Infinity, delay: d.delay, ease: 'easeInOut' }} />)}<div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,transparent,rgba(2,8,23,0.9)_75%)]" /></div>
}

function IdleStage({ onStart }: { onStart: () => void }) {
  return <div className="relative z-10 mx-auto flex h-full max-w-[900px] flex-col justify-center"><WebsiteCard large /><button onClick={onStart} className="mx-auto mt-8 flex w-[420px] items-center justify-center gap-4 rounded-xl px-7 py-4 text-xl font-bold text-[#020817] shadow-[0_0_38px_rgba(132,255,0,0.22)]" style={{ background: `linear-gradient(135deg, ${GREEN}, #b6ff3f)` }}>Start Scan <ArrowRight className="h-6 w-6" /></button><p className="mt-4 text-center text-xs text-slate-500">Read-only scan · No changes made · Takes about 2 minutes</p></div>
}

function WebsiteCard({ scanning = false, large = false }: { scanning?: boolean; large?: boolean }) {
  return <div className={`relative mx-auto overflow-hidden rounded-[16px] border border-white/[0.09] bg-[#050b15] shadow-[0_25px_80px_rgba(0,0,0,0.45)] ${large ? 'w-full lg:w-[780px]' : 'w-full lg:w-[520px]'}`}>{scanning && <motion.div className="absolute inset-y-0 z-20 w-24 bg-gradient-to-r from-transparent via-[rgba(132,255,0,0.14)] to-transparent" animate={{ x: [-130, 850] }} transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut' }} />}<Image src="/images/northstar-commerce-preview.jpeg" alt="NorthStar Commerce website preview" width={1536} height={1024} priority className="block h-auto w-full" /></div>
}

function ScanStage({ phase, assetStep, findingStep, assetsFound, progress, onOpenCritical }: { phase: Phase; assetStep: number; findingStep: number; assetsFound: number; progress: number; onOpenCritical: () => void }) {
  const showTrails = assetStep >= ASSETS.length
  return <div className="relative z-10 h-full"><div className="absolute left-1/2 top-[42%] w-[520px] -translate-x-1/2 -translate-y-1/2"><WebsiteCard scanning={phase === 'discovering' || phase === 'analyzing'} /></div>{showTrails && <TrailLayer />}{ASSETS.map((a, i) => <AssetNode key={a.label} item={a} active={i < assetStep} danger={a.label === 'Admin Portal' && phase !== 'discovering'} />)}<div className="absolute bottom-6 left-6 w-[390px]"><ScanProgressBar phase={phase} assetStep={assetStep} findingStep={findingStep} progress={progress} /></div>{phase === 'discovering' && <div className="absolute bottom-6 right-6 w-[300px] rounded-2xl border border-white/[0.08] bg-black/30 p-5"><p className="font-bold">Assets discovered</p><b className="mt-2 block text-5xl" style={{ color: GREEN }}>{assetsFound}</b><p className="text-xs text-slate-500">pages, assets, and endpoints</p></div>}{(phase === 'analyzing' || phase === 'complete') && <FindingsPanel count={findingStep} complete={phase === 'complete'} onOpenCritical={onOpenCritical} />}</div>
}

function TrailLayer() {
  return <svg className="pointer-events-none absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none"><motion.path d="M50 45 C25 42 14 20 7 20 M50 45 C24 48 14 50 7 50 M50 45 C25 58 14 76 7 76 M50 45 C72 42 82 20 88 20 M50 45 C72 48 82 48 88 48 M50 45 C72 58 82 76 88 76 M50 45 C50 68 48 82 48 82 M50 45 C50 28 48 12 48 12" stroke="rgba(132,255,0,0.25)" strokeWidth="0.35" fill="none" strokeDasharray="2 3" initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 1.2, ease: 'easeInOut' }} /></svg>
}

function AssetNode({ item, active, danger }: { item: (typeof ASSETS)[number]; active: boolean; danger?: boolean }) {
  const Icon = item.icon
  return <motion.div className="absolute rounded-xl border px-3 py-2 text-xs" style={{ left: `${item.x}%`, top: `${item.y}%`, borderColor: danger ? 'rgba(255,84,84,0.4)' : active ? 'rgba(132,255,0,0.28)' : 'rgba(255,255,255,0.08)', background: 'rgba(2,8,23,0.9)' }} initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: active ? 1 : 0, scale: active ? 1 : 0.94 }}><Icon className="mb-1 h-4 w-4" style={{ color: danger ? '#ff5454' : GREEN }} /><b>{item.label}</b><p className="text-[10px] text-slate-500">{item.path}</p><p className="mt-1 text-[10px]" style={{ color: danger ? '#ff8a8a' : GREEN }}>Discovered</p></motion.div>
}

function FindingsPanel({ count, complete, onOpenCritical }: { count: number; complete: boolean; onOpenCritical: () => void }) {
  return <div className="absolute right-5 top-20 w-[270px] space-y-3">{FINDINGS.slice(0, count).map((f, i) => <motion.button key={f.title} onClick={complete && i === 0 ? onOpenCritical : undefined} initial={{ opacity: 0, x: 18 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.08 }} className="block w-full rounded-xl border bg-black/40 p-4 text-left backdrop-blur" style={{ borderColor: i === 0 ? 'rgba(255,84,84,0.35)' : 'rgba(255,255,255,0.08)' }}><p className="text-[10px] font-bold uppercase tracking-[0.16em]" style={{ color: f.tone }}>{f.severity}</p><p className="mt-1 font-bold">{f.title}</p><p className="mt-1 text-xs leading-5 text-slate-400">{f.body}</p>{complete && i === 0 && <p className="mt-2 text-xs" style={{ color: GREEN }}>Open finding →</p>}</motion.button>)}</div>
}

function DetailStage({ onBack }: { onBack: () => void }) {
  return <div className="relative z-10 grid h-full grid-cols-[1fr_300px] gap-5"><div className="rounded-2xl border border-white/[0.08] bg-black/25 p-6"><button onClick={onBack} className="mb-5 text-sm text-slate-400">← Back to findings</button><p className="text-xs font-bold uppercase tracking-[0.2em] text-red-400">Critical</p><h3 className="mt-2 text-[36px] font-bold">Admin Portal Exposed</h3><p className="mt-3 text-sm text-slate-400">URL: /admin</p><div className="mt-6 grid grid-cols-2 gap-4"><InfoBox title="What we found" body="A publicly accessible administrative portal was discovered." /><InfoBox title="Why it matters" body="Admin panels are frequent targets for credential attacks and account takeover." /><InfoBox title="Potential impact" body="Unauthorized access, customer data exposure, or site compromise." /><InfoBox title="Recommended action" body="Restrict access with MFA, VPN, IP allowlists, or admin gateways." /></div></div><div className="rounded-2xl border border-red-500/20 bg-red-500/[0.035] p-5"><p className="mb-4 font-bold">WADE Analysis</p><div className="grid grid-cols-3 gap-2 text-center text-xs"><span>Likelihood<br /><b className="text-red-300">High</b></span><span>Impact<br /><b className="text-red-300">High</b></span><span>Priority<br /><b style={{ color: GREEN }}>Fix First</b></span></div><p className="mt-5 text-sm leading-6 text-slate-400">WADE identified this as a high-risk exposure that should be addressed immediately.</p></div></div>
}

function InfoBox({ title, body }: { title: string; body: string }) { return <div className="rounded-xl border border-white/[0.08] bg-black/25 p-4"><p className="font-bold">{title}</p><p className="mt-1 text-sm leading-6 text-slate-400">{body}</p></div> }
