'use client'

// WebHound — components/sections/FlagshipScanDemo.tsx
// Cinematic flagship scan demo preview. Fixed design canvas scales on mobile.

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
      const next = window.setTimeout(() => setPhase('analyzing'), 1000)
      return () => window.clearTimeout(next)
    }
    const id = window.setTimeout(() => setAssetStep(v => v + 1), 560)
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

  const assetsFound = phase === 'idle' ? 0 : Math.round((assetStep / ASSETS.length) * 31)

  return (
    <section className="relative min-h-screen overflow-hidden bg-[#020817] py-6 text-white sm:py-10">
      <div className={expanded ? 'fixed inset-0 z-[100] grid place-items-center overflow-auto bg-[#020817] p-3' : 'mx-auto grid w-full place-items-center overflow-hidden px-2'}>
        <div className="relative h-[392px] w-[704px] sm:h-[520px] sm:w-[936px] md:h-[640px] md:w-[1152px] lg:h-auto lg:w-[1320px]">
          <div className="absolute left-0 top-0 w-[1320px] origin-top-left scale-[0.533] sm:scale-[0.709] md:scale-[0.873] lg:relative lg:scale-100">
            <div className="grid grid-cols-[270px_1fr] gap-5 rounded-[30px] border border-white/[0.06] bg-[radial-gradient(circle_at_55%_0%,rgba(132,255,0,0.07),transparent_34%),linear-gradient(180deg,rgba(4,10,22,0.98),rgba(2,8,23,0.98))] p-5 shadow-[0_35px_120px_rgba(0,0,0,0.55)]">
              {!expanded && <NarratorRail phase={phase} assetStep={assetStep} findingStep={findingStep} />}
              <main className={expanded ? 'col-span-2' : ''}>
                <div className="overflow-hidden rounded-[18px] border border-[rgba(132,255,0,0.18)] bg-[#06101a]/90 shadow-[0_0_38px_rgba(132,255,0,0.06)]">
                  <DemoTopBar phase={phase} elapsed={elapsed} expanded={expanded} onRestart={restart} onExpand={() => setExpanded(v => !v)} />
                  <div className="relative h-[610px] overflow-hidden p-6">
                    <TelemetryField />
                    {phase === 'idle' && <IdleStage onStart={startScan} />}
                    {phase !== 'idle' && phase !== 'detail' && <ScanStage phase={phase} assetStep={assetStep} findingStep={findingStep} assetsFound={assetsFound} onOpenCritical={() => setPhase('detail')} />}
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
        </div>
        {expanded && <button onClick={() => setExpanded(false)} className="fixed right-4 top-4 z-[110] rounded-full border border-white/10 bg-white/10 p-3 backdrop-blur-xl"><X className="h-5 w-5" /></button>}
      </div>
    </section>
  )
}

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
  return <div className={`relative mx-auto overflow-hidden rounded-[16px] border border-white/[0.09] bg-[#050b15] shadow-[0_25px_80px_rgba(0,0,0,0.45)] ${large ? 'w-[780px]' : 'w-[520px]'}`}>{scanning && <motion.div className="absolute inset-y-0 z-20 w-24 bg-gradient-to-r from-transparent via-[rgba(132,255,0,0.14)] to-transparent" animate={{ x: [-130, 850] }} transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut' }} />}<Image src="/images/northstar-commerce-preview.jpeg" alt="NorthStar Commerce website preview" width={1536} height={1024} priority className="block h-auto w-full" /></div>
}

function ScanStage({ phase, assetStep, findingStep, assetsFound, onOpenCritical }: { phase: Phase; assetStep: number; findingStep: number; assetsFound: number; onOpenCritical: () => void }) {
  const showTrails = assetStep >= ASSETS.length
  return <div className="relative z-10 h-full"><div className="absolute left-1/2 top-[44%] -translate-x-1/2 -translate-y-1/2"><WebsiteCard scanning={phase === 'discovering' || phase === 'analyzing'} /></div>{showTrails && <TrailLayer />}{ASSETS.map((a, i) => <AssetNode key={a.label} item={a} active={i < assetStep} danger={a.label === 'Admin Portal' && phase !== 'discovering'} />)}{phase === 'discovering' && <div className="absolute bottom-6 left-6 right-6 rounded-2xl border border-white/[0.08] bg-black/30 p-5"><p className="font-bold">Discovering your attack surface...</p><p className="mt-1 text-sm text-slate-400">Finding pages, assets, and endpoints.</p><b className="absolute right-8 top-5 text-5xl" style={{ color: GREEN }}>{assetsFound}</b><p className="absolute right-8 top-20 text-xs text-slate-500">assets discovered</p></div>}{(phase === 'analyzing' || phase === 'complete') && <FindingsPanel count={findingStep} complete={phase === 'complete'} onOpenCritical={onOpenCritical} />}</div>
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
