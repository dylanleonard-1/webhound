'use client'

// WebHound — components/sections/FlagshipScanDemo.tsx
// Cinematic flagship scan demo preview. Mobile uses a focused demo player.

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
  { severity: 'CRITICAL', title: 'Admin Portal Found', body: 'Public admin endpoint discovered.', tone: '#ff5454' },
  { severity: 'HIGH', title: 'Outdated JavaScript Library', body: 'Known vulnerable library detected.', tone: '#ff9f43' },
  { severity: 'MEDIUM', title: 'Missing Security Headers', body: 'Missing browser protection headers.', tone: '#facc15' },
]

const DETAIL_ACTIONS = ['Require MFA for all admin users', 'Restrict access by IP allowlist', 'Place admin area behind VPN or gateway', 'Monitor failed login attempts']
const DETAIL_IMPACTS = ['Credential attacks', 'Admin account takeover', 'Unauthorized website changes', 'Customer data exposure']

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
      const next = window.setTimeout(() => setPhase('analyzing'), 1200)
      return () => window.clearTimeout(next)
    }
    const id = window.setTimeout(() => setAssetStep(v => v + 1), 850)
    return () => window.clearTimeout(id)
  }, [phase, assetStep, reduce])

  useEffect(() => {
    if (phase !== 'analyzing' || reduce) return
    if (findingStep >= FINDINGS.length) {
      const next = window.setTimeout(() => setPhase('complete'), 1400)
      return () => window.clearTimeout(next)
    }
    const id = window.setTimeout(() => setFindingStep(v => v + 1), 1300)
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
    <section className="relative overflow-hidden bg-[#020817] px-3 py-6 text-white sm:py-10 lg:px-8 lg:py-24">
      <div className="mx-auto block w-full max-w-[460px] lg:hidden">
        <MobileDemo phase={phase} elapsed={elapsed} assetStep={assetStep} findingStep={findingStep} assetsFound={assetsFound} progress={progress} onStart={startScan} onRestart={restart} onOpenCritical={() => setPhase('detail')} onBackToResults={() => setPhase('complete')} />
      </div>

      <div className={expanded ? 'fixed inset-0 z-[100] hidden place-items-center overflow-auto bg-[#020817] p-6 lg:grid' : 'mx-auto hidden w-full max-w-[1440px] overflow-visible lg:block'}>
        {!expanded && (
          <div className="mx-auto mb-10 max-w-4xl text-center">
            <p className="mb-3 text-xs font-bold uppercase tracking-[0.26em]" style={{ color: GREEN }}>Live scan demo</p>
            <h2 className="text-4xl font-bold tracking-tight text-white xl:text-6xl">Watch WebHound scan a website.</h2>
            <p className="mx-auto mt-4 max-w-2xl text-base leading-7 text-slate-400">See pages discovered, risks surfaced, and WADE explain what to fix first.</p>
          </div>
        )}
        <div className="w-full">
          <div className="grid grid-cols-[340px_minmax(0,1fr)] gap-6 rounded-[34px] border border-white/[0.07] bg-[radial-gradient(circle_at_55%_0%,rgba(132,255,0,0.07),transparent_34%),linear-gradient(180deg,rgba(4,10,22,0.98),rgba(2,8,23,0.98))] p-6 shadow-[0_35px_120px_rgba(0,0,0,0.55)]">
            {!expanded && <NarratorRail phase={phase} assetStep={assetStep} findingStep={findingStep} />}
            <main className={expanded ? 'col-span-2' : ''}>
              <div className="overflow-hidden rounded-[22px] border border-[rgba(132,255,0,0.18)] bg-[#06101a]/90 shadow-[0_0_38px_rgba(132,255,0,0.06)]">
                <DemoTopBar phase={phase} elapsed={elapsed} expanded={expanded} onRestart={restart} onExpand={() => setExpanded(v => !v)} />
                <div className="relative h-[720px] overflow-hidden p-8">
                  <TelemetryField />
                  {phase === 'idle' && <IdleStage onStart={startScan} />}
                  {phase !== 'idle' && phase !== 'detail' && <ScanStage phase={phase} assetStep={assetStep} findingStep={findingStep} assetsFound={assetsFound} progress={progress} onOpenCritical={() => setPhase('detail')} />}
                  {phase === 'detail' && <DetailStage onBack={() => setPhase('complete')} />}
                </div>
                <div className="flex items-center justify-center gap-6 border-t border-white/[0.06] px-5 py-4 text-sm text-slate-500">
                  <span className="inline-flex items-center gap-1"><Lock className="h-4 w-4" /> Read-only scan</span>
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
  if (phase === 'discovering') return Math.min(58, 10 + Math.round((assetStep / ASSETS.length) * 48))
  if (phase === 'analyzing') return Math.min(92, 64 + Math.round((findingStep / FINDINGS.length) * 28))
  if (phase === 'complete' || phase === 'detail') return 100
  return 0
}

function getMobileCopy(phase: Phase, assetStep: number, findingStep: number) {
  if (phase === 'idle') return { eyebrow: 'Live scan demo', title: 'See your website checked in real time.', detail: 'Safe read-only scan. No changes made.' }
  if (phase === 'discovering') {
    const current = ASSETS[Math.max(0, Math.min(assetStep - 1, ASSETS.length - 1))]
    return { eyebrow: 'Discovering', title: 'Mapping the website.', detail: current ? `${current.label} discovered. ${Math.round((assetStep / ASSETS.length) * 31)} assets found so far.` : 'Finding public pages, assets, and endpoints.' }
  }
  if (phase === 'analyzing') return { eyebrow: 'Analyzing', title: 'Checking for security risks.', detail: findingStep === 0 ? 'Looking for exposed admin pages, outdated scripts, and missing protections.' : `${findingStep} of ${FINDINGS.length} key findings surfaced.` }
  if (phase === 'complete') return { eyebrow: 'Results dashboard', title: 'Security risk report.', detail: 'Review the risk score and open the critical finding.' }
  return { eyebrow: 'WADE explanation', title: 'Admin Portal Exposed.', detail: 'Evidence, impact, and recommended fix.' }
}

function MobileDemo({ phase, elapsed, assetStep, findingStep, assetsFound, progress, onStart, onRestart, onOpenCritical, onBackToResults }: { phase: Phase; elapsed: number; assetStep: number; findingStep: number; assetsFound: number; progress: number; onStart: () => void; onRestart: () => void; onOpenCritical: () => void; onBackToResults: () => void }) {
  const copy = getMobileCopy(phase, assetStep, findingStep)
  return (
    <div className="overflow-hidden rounded-[28px] border border-white/[0.07] bg-[radial-gradient(circle_at_50%_0%,rgba(132,255,0,0.08),transparent_36%),linear-gradient(180deg,rgba(5,11,24,0.98),rgba(2,8,23,0.98))] shadow-[0_28px_80px_rgba(0,0,0,0.5)]">
      <div className="p-5 pb-4">
        <div className="mb-5 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.18em]"><Shield className="h-5 w-5" style={{ color: GREEN }} /> WebHound</div>
        <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.22em]" style={{ color: GREEN }}>{copy.eyebrow}</p>
        <h1 className="text-[30px] font-bold leading-[1.05]">{copy.title}</h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">{copy.detail}</p>
      </div>

      <div className="border-y border-white/[0.06] bg-black/15 px-4 py-3">
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-300">
          <span className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-black/25 px-3 py-1.5"><Globe className="h-3.5 w-3.5" /> northstarcommerce.com</span>
          <span className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-black/25 px-3 py-1.5"><span className="h-1.5 w-1.5 rounded-full" style={{ background: GREEN }} /> {phase === 'idle' ? 'Live demo' : phase === 'complete' ? 'Complete' : phase === 'detail' ? 'Finding opened' : 'Scanning'}</span>
          <span className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-black/25 px-3 py-1.5"><Clock className="h-3.5 w-3.5" /> 00:00:{String(elapsed).padStart(2, '0')}</span>
          <button onClick={onRestart} className="rounded-full border border-white/[0.08] bg-black/25 px-3 py-1.5"><RefreshCcw className="mr-1 inline h-3.5 w-3.5" />Restart</button>
        </div>
      </div>

      <div className="relative overflow-hidden p-4">
        <TelemetryField />
        <div className="relative z-10 space-y-4">
          {phase !== 'detail' && phase !== 'complete' && (
            <div className="relative">
              <WebsiteCard scanning={phase !== 'idle'} large />
              {phase !== 'idle' && <ScanOverlay phase={phase} assetStep={assetStep} findingStep={findingStep} progress={progress} assetsFound={assetsFound} />}
            </div>
          )}

          {phase === 'idle' && <button onClick={onStart} className="flex w-full items-center justify-center gap-3 rounded-xl px-5 py-4 text-lg font-bold text-[#020817] shadow-[0_0_34px_rgba(132,255,0,0.2)]" style={{ background: `linear-gradient(135deg, ${GREEN}, #b6ff3f)` }}>Start Scan <ArrowRight className="h-5 w-5" /></button>}
          {phase === 'discovering' && <CompactEventCard label="Currently checking" title={copy.detail} body={`${assetsFound} assets discovered`} />}
          {phase === 'analyzing' && findingStep > 0 && <MobileFindingsList count={findingStep} />}
          {phase === 'complete' && <MobileResultsDashboard onOpenCritical={onOpenCritical} />}
          {phase === 'detail' && <MobileDetail onBack={onBackToResults} />}
        </div>
      </div>

      <div className="flex items-center justify-center gap-3 border-t border-white/[0.06] px-4 py-3 text-[11px] text-slate-500">
        <span>Read-only scan</span><span>No changes made</span><span>Takes about 2 minutes</span>
      </div>
    </div>
  )
}

function ScanOverlay({ phase, assetStep, findingStep, progress, assetsFound }: { phase: Phase; assetStep: number; findingStep: number; progress: number; assetsFound: number }) {
  const copy = getMobileCopy(phase, assetStep, findingStep)
  return (
    <div className="absolute inset-x-3 bottom-3 rounded-2xl border border-white/[0.1] bg-[#030814]/85 p-3 shadow-[0_16px_40px_rgba(0,0,0,0.45)] backdrop-blur-xl">
      <div className="mb-2 flex items-center justify-between gap-3">
        <p className="text-[10px] font-bold uppercase tracking-[0.18em]" style={{ color: GREEN }}>Scan in progress</p>
        <p className="text-xs text-slate-300">{progress}%</p>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.1]">
        <motion.div className="h-full rounded-full" style={{ background: `linear-gradient(90deg, ${GREEN}, #b6ff3f)`, boxShadow: '0 0 14px rgba(132,255,0,0.28)' }} animate={{ width: `${progress}%` }} transition={{ duration: 0.65, ease: [0.22, 1, 0.36, 1] }} />
      </div>
      <div className="mt-2 flex items-center justify-between gap-3 text-xs">
        <span className="text-slate-300">{phase === 'analyzing' && findingStep === 0 ? 'Scanning exposed surfaces...' : copy.detail}</span>
        <span style={{ color: GREEN }}>{phase === 'discovering' ? `${assetsFound} assets` : phase === 'analyzing' ? (findingStep === 0 ? 'Analyzing' : `${findingStep}/3 key`) : 'Ready'}</span>
      </div>
    </div>
  )
}

function MobileFindingsList({ count }: { count: number }) {
  return (
    <div className="rounded-[22px] border border-white/[0.08] bg-black/25 p-3">
      <div className="mb-3 flex items-center justify-between">
        <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">Key findings surfaced</p>
        <span className="text-xs text-slate-500">{count} shown</span>
      </div>
      <div className="space-y-2">
        {FINDINGS.slice(0, count).map((finding, index) => <FindingRow key={finding.title} finding={finding} featured={index === 0} />)}
      </div>
    </div>
  )
}

function MobileResultsDashboard({ onOpenCritical }: { onOpenCritical: () => void }) {
  return (
    <div className="rounded-[26px] border border-white/[0.08] bg-[radial-gradient(circle_at_100%_0%,rgba(255,84,84,0.12),transparent_34%),linear-gradient(180deg,rgba(5,11,24,0.96),rgba(2,8,23,0.96))] p-4 shadow-[0_28px_70px_rgba(0,0,0,0.45)] backdrop-blur">
      <div className="rounded-[22px] border border-white/[0.07] bg-black/25 p-4">
        <p className="text-[10px] font-bold uppercase tracking-[0.2em]" style={{ color: GREEN }}>Security risk</p>
        <div className="mt-3 flex items-end justify-between gap-4">
          <div>
            <h3 className="text-2xl font-bold">Risk detected</h3>
            <p className="mt-1 text-xs text-slate-500">northstarcommerce.com</p>
          </div>
          <div className="text-right">
            <b className="block text-5xl leading-none text-red-300">83%</b>
            <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-red-200">High risk</span>
          </div>
        </div>
        <div className="mt-4 h-2 overflow-hidden rounded-full bg-white/[0.08]">
          <div className="h-full w-[83%] rounded-full bg-gradient-to-r from-yellow-400 via-orange-500 to-red-500 shadow-[0_0_20px_rgba(255,84,84,0.3)]" />
        </div>
        <p className="mt-4 text-xs text-slate-400"><b className="text-slate-200">39 findings detected</b> across the public website.</p>
        <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-slate-300">
          <SummaryPill label="Critical" value="1" color="#ff5454" />
          <SummaryPill label="High" value="6" color="#ff9f43" />
          <SummaryPill label="Medium" value="20" color="#facc15" />
          <SummaryPill label="Low" value="12" color={GREEN} />
        </div>
      </div>

      <div className="mt-4 rounded-[22px] border border-white/[0.07] bg-black/25 p-3">
        <div className="mb-3 flex items-center justify-between">
          <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">Priority findings</p>
          <span className="rounded-full border border-white/[0.08] px-2 py-1 text-[10px] text-slate-400">Open critical</span>
        </div>
        <button onClick={onOpenCritical} className="block w-full text-left">
          <FindingRow finding={FINDINGS[0]} featured cta />
        </button>
        <FindingRow finding={FINDINGS[1]} count="6 issues" />
        <FindingRow finding={FINDINGS[2]} count="20 issues" />
        <div className="mt-2 rounded-2xl border border-white/[0.06] bg-white/[0.02] px-3 py-3 text-sm text-slate-400">12 low-priority hardening notes grouped in the full report.</div>
      </div>
    </div>
  )
}

function MobileDetail({ onBack }: { onBack: () => void }) {
  return (
    <div className="space-y-3">
      <div className="rounded-[26px] border border-red-500/25 bg-[radial-gradient(circle_at_100%_0%,rgba(255,84,84,0.14),transparent_34%),linear-gradient(180deg,rgba(12,8,18,0.96),rgba(3,7,18,0.96))] p-4 shadow-[0_28px_70px_rgba(0,0,0,0.45)]">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-red-300">Critical finding</p>
            <h3 className="mt-2 text-2xl font-bold leading-tight">Admin Portal Exposed</h3>
            <p className="mt-2 text-sm leading-6 text-slate-400">WebHound found a publicly reachable administrative interface.</p>
          </div>
          <div className="rounded-2xl border border-red-400/25 bg-red-500/[0.07] px-3 py-2 text-center">
            <b className="block text-2xl text-red-200">92</b>
            <span className="text-[9px] font-bold uppercase tracking-[0.12em] text-red-200">Risk</span>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
          <DetailMetric label="Priority" value="Fix First" tone={GREEN} />
          <DetailMetric label="Impact" value="High" tone="#ff9f43" />
          <DetailMetric label="URL" value="/admin" />
          <DetailMetric label="Exposure" value="Public" tone="#ff5454" />
        </div>
      </div>

      <div className="rounded-[22px] border border-white/[0.08] bg-black/25 p-4">
        <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">Evidence</p>
        <div className="mt-3 space-y-2 text-sm">
          <EvidenceRow label="Endpoint" value="northstarcommerce.com/admin" />
          <EvidenceRow label="Response" value="200 OK" />
          <EvidenceRow label="Auth required" value="No" danger />
        </div>
      </div>

      <div className="rounded-[22px] border border-white/[0.08] bg-black/25 p-4">
        <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">Potential impact</p>
        <div className="mt-3 grid grid-cols-2 gap-2">
          {DETAIL_IMPACTS.map(item => <MiniTag key={item} text={item} tone="#ff5454" />)}
        </div>
      </div>

      <div className="rounded-[22px] border border-white/[0.08] bg-black/25 p-4">
        <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">Recommended actions</p>
        <div className="mt-3 space-y-2">
          {DETAIL_ACTIONS.map(item => <ActionItem key={item} text={item} />)}
        </div>
      </div>

      <button onClick={onBack} className="flex w-full items-center justify-center gap-2 rounded-2xl px-4 py-3 text-sm font-bold text-[#020817]" style={{ background: `linear-gradient(135deg, ${GREEN}, #b6ff3f)` }}>
        Back to results dashboard <ArrowRight className="h-4 w-4" />
      </button>
    </div>
  )
}

function DetailMetric({ label, value, tone = '#e2e8f0' }: { label: string; value: string; tone?: string }) {
  return <div className="rounded-xl border border-white/[0.07] bg-white/[0.035] p-3"><p className="text-[9px] uppercase tracking-[0.14em] text-slate-500">{label}</p><p className="mt-1 font-bold" style={{ color: tone }}>{value}</p></div>
}

function EvidenceRow({ label, value, danger = false }: { label: string; value: string; danger?: boolean }) {
  return <div className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-white/[0.025] px-3 py-2"><span className="text-slate-500">{label}</span><span className="font-semibold" style={{ color: danger ? '#ff8a8a' : '#e2e8f0' }}>{value}</span></div>
}

function MiniTag({ text, tone }: { text: string; tone: string }) {
  return <span className="rounded-xl border border-white/[0.06] bg-white/[0.025] px-3 py-2 text-xs text-slate-300"><span className="mr-2 inline-block h-1.5 w-1.5 rounded-full" style={{ background: tone }} />{text}</span>
}

function ActionItem({ text }: { text: string }) {
  return <div className="flex items-center gap-2 rounded-xl border border-white/[0.06] bg-white/[0.025] px-3 py-2 text-sm text-slate-300"><Check className="h-4 w-4 shrink-0" style={{ color: GREEN }} />{text}</div>
}

function SummaryPill({ label, value, color }: { label: string; value: string; color: string }) {
  return <span className="inline-flex items-center gap-2 rounded-full border border-white/[0.07] bg-white/[0.035] px-3 py-2"><span className="h-2 w-2 rounded-full" style={{ background: color }} /><b>{value}</b><span className="text-slate-500">{label}</span></span>
}

function FindingRow({ finding, featured = false, cta = false, count }: { finding: (typeof FINDINGS)[number]; featured?: boolean; cta?: boolean; count?: string }) {
  return <div className={`mt-2 rounded-2xl border px-3 py-3 ${featured ? 'border-red-400/30 bg-red-500/[0.055] shadow-[0_0_22px_rgba(255,84,84,0.08)]' : 'border-white/[0.06] bg-white/[0.025]'}`}><div className="flex items-center gap-3"><span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl" style={{ background: `${finding.tone}18`, color: finding.tone }}><ShieldAlert className="h-4 w-4" /></span><span className="min-w-0 flex-1"><span className="block text-[10px] font-bold uppercase tracking-[0.14em]" style={{ color: finding.tone }}>{finding.severity}</span><span className="block truncate font-bold text-slate-100">{finding.title}</span></span>{cta ? <ArrowRight className="h-5 w-5 shrink-0" style={{ color: GREEN }} /> : <span className="text-xs font-semibold" style={{ color: finding.tone }}>{count ?? (finding.severity === 'CRITICAL' ? 'Open' : finding.severity[0] + finding.severity.slice(1).toLowerCase())}</span>}</div></div>
}

function CompactEventCard({ label, title, body }: { label: string; title: string; body: string }) {
  return <div className="rounded-2xl border border-white/[0.08] bg-black/30 p-4"><p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">{label}</p><h3 className="mt-2 text-xl font-bold leading-snug">{title}</h3><p className="mt-1 text-sm text-slate-400">{body}</p></div>
}

function NarratorRail({ phase, assetStep, findingStep }: { phase: Phase; assetStep: number; findingStep: number }) {
  const title = phase === 'discovering' ? 'Mapping your website in real time.' : phase === 'analyzing' || phase === 'complete' ? 'See your website being checked in real time.' : phase === 'detail' ? 'Understand what needs fixing first.' : 'See your website being checked in real time.'
  const body = phase === 'discovering' ? 'WebHound is discovering your pages, assets, and endpoints to build a complete picture of your attack surface.' : phase === 'analyzing' ? 'WebHound finds risks attackers could use and shows what to fix first.' : phase === 'detail' ? 'WADE explains the risk, impact, and recommended fixes.' : 'WebHound maps your website, checks for risks, and explains what to fix first.'
  const steps = [
    ['Map your entire site', assetStep >= 3 || phase !== 'idle'],
    ['Find security issues', phase === 'analyzing' || phase === 'complete' || phase === 'detail'],
    ['Get clear explanations', phase === 'complete' || phase === 'detail'],
  ] as const
  return <aside className="relative flex min-h-[760px] flex-col rounded-[24px] p-8"><div className="mb-14 flex items-center gap-2 text-sm font-bold uppercase tracking-[0.14em]"><Shield className="h-5 w-5" style={{ color: GREEN }} /> WebHound</div><p className="mb-4 text-xs font-bold uppercase tracking-[0.22em]" style={{ color: GREEN }}>Live scan demo</p><h1 className="text-[42px] font-bold leading-[1.02]">{title.includes('real time') ? <>See your website being checked <span style={{ color: GREEN }}>in real time.</span></> : title}</h1><p className="mt-6 text-[15px] leading-7 text-slate-400">{body}</p><div className="mt-10 space-y-5">{steps.map(([label, done], i) => <div key={label} className="flex gap-3"><span className="mt-1 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/[0.07] bg-black/25"><Check className="h-4 w-4" style={{ color: done ? GREEN : '#475569' }} /></span><div><p className="text-base font-bold text-slate-200">{label}</p><p className="mt-1 text-xs leading-5 text-slate-500">{i === 0 ? 'We discover pages, assets, and endpoints.' : i === 1 ? 'We analyze for vulnerabilities attackers could use.' : 'We show what it means and how to fix it.'}</p></div></div>)}</div>{phase === 'analyzing' && <div className="mt-8 rounded-2xl border border-red-500/20 bg-red-500/[0.04] p-5"><p className="text-xs font-bold uppercase tracking-[0.16em] text-red-300">Threat analysis</p><p className="mt-2 text-sm text-slate-300">{findingStep} issues require attention</p></div>}<div className="mt-auto space-y-3 text-sm text-slate-500"><p className="inline-flex items-center gap-2"><Lock className="h-4 w-4" /> Read-only scan · No changes made</p><p>Takes about 2 minutes</p></div></aside>
}

function DemoTopBar({ phase, elapsed, expanded, onRestart, onExpand }: { phase: Phase; elapsed: number; expanded: boolean; onRestart: () => void; onExpand: () => void }) {
  const status = phase === 'idle' ? 'Live demo' : phase === 'complete' ? 'Scan complete' : phase === 'detail' ? 'Finding opened' : 'Scan running'
  return <div className="flex h-16 items-center gap-3 border-b border-white/[0.07] px-6 text-sm text-slate-300"><span className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-black/25 px-3 py-1.5"><Globe className="h-4 w-4" /> northstarcommerce.com</span><span className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-black/25 px-3 py-1.5"><span className="h-1.5 w-1.5 rounded-full" style={{ background: GREEN }} /> {status}</span><span className="ml-auto inline-flex items-center gap-2"><Clock className="h-4 w-4" /> 00:00:{String(elapsed).padStart(2, '0')}</span><button onClick={onExpand} className="rounded-lg border border-white/[0.08] px-3 py-1.5 text-slate-300"><Maximize2 className="mr-1 inline h-4 w-4" /> {expanded ? 'Exit' : 'Maximize'}</button><button onClick={onRestart} className="rounded-lg border border-white/[0.08] px-3 py-1.5 text-slate-300"><RefreshCcw className="mr-1 inline h-4 w-4" /> Restart</button></div>
}

function TelemetryField() {
  const dots = useMemo(() => Array.from({ length: 90 }, (_, i) => ({ i, left: (i * 37) % 100, top: (i * 61) % 100, delay: (i % 18) * 0.18, size: 1 + (i % 3) })), [])
  return <div className="pointer-events-none absolute inset-0 overflow-hidden opacity-28">{dots.map(d => <motion.span key={d.i} className="absolute rounded-full" style={{ left: `${d.left}%`, top: `${d.top}%`, width: d.size + 1, height: d.size + 1, background: 'rgba(132,255,0,0.22)', boxShadow: '0 0 10px rgba(132,255,0,0.12)' }} animate={{ x: [0, 26, -14, 0], y: [0, -20, 12, 0], opacity: [0.06, 0.32, 0.12] }} transition={{ duration: 6 + (d.i % 5), repeat: Infinity, delay: d.delay, ease: 'easeInOut' }} />)}<div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,transparent,rgba(2,8,23,0.9)_75%)]" /></div>
}

function IdleStage({ onStart }: { onStart: () => void }) {
  return <div className="relative z-10 mx-auto flex h-full max-w-[1050px] flex-col justify-center"><WebsiteCard large /><button onClick={onStart} className="mx-auto mt-8 flex w-[460px] items-center justify-center gap-4 rounded-xl px-7 py-4 text-xl font-bold text-[#020817] shadow-[0_0_22px_rgba(132,255,0,0.18)]" style={{ background: `linear-gradient(135deg, ${GREEN}, #b6ff3f)` }}>Start Scan <ArrowRight className="h-6 w-6" /></button><p className="mt-4 text-center text-sm text-slate-500">Read-only scan · No changes made · Takes about 2 minutes</p></div>
}

function WebsiteCard({ scanning = false, large = false }: { scanning?: boolean; large?: boolean }) {
  return <div className={`relative mx-auto overflow-hidden rounded-[18px] border border-white/[0.09] bg-[#050b15] shadow-[0_25px_80px_rgba(0,0,0,0.45)] ${large ? 'w-full lg:w-[980px]' : 'w-full lg:w-[650px]'}`}>{scanning && <motion.div className="absolute inset-y-0 z-20 w-24 bg-gradient-to-r from-transparent via-[rgba(132,255,0,0.14)] to-transparent" animate={{ x: [-130, 1050] }} transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut' }} />}<Image src="/images/northstar-commerce-preview.jpeg" alt="NorthStar Commerce website preview" width={1536} height={1024} priority className="block h-auto w-full" /></div>
}

function ScanStage({ phase, assetStep, findingStep, assetsFound, progress, onOpenCritical }: { phase: Phase; assetStep: number; findingStep: number; assetsFound: number; progress: number; onOpenCritical: () => void }) {
  const showTrails = assetStep >= ASSETS.length
  return <div className="relative z-10 h-full"><div className="absolute left-1/2 top-[42%] w-[650px] -translate-x-1/2 -translate-y-1/2"><WebsiteCard scanning={phase === 'discovering' || phase === 'analyzing'} /></div>{showTrails && <TrailLayer />}{ASSETS.map((a, i) => <AssetNode key={a.label} item={a} active={i < assetStep} danger={a.label === 'Admin Portal' && phase !== 'discovering'} />)}<div className="absolute bottom-6 left-6 w-[420px]"><div className="rounded-2xl border border-white/[0.08] bg-black/35 p-5 backdrop-blur"><p className="mb-2 text-sm font-bold uppercase tracking-[0.18em]" style={{ color: GREEN }}>Scan in progress</p><div className="h-2 overflow-hidden rounded-full bg-white/[0.08]"><motion.div className="h-full rounded-full" style={{ background: `linear-gradient(90deg, ${GREEN}, #b6ff3f)` }} animate={{ width: `${progress}%` }} /></div></div></div>{phase === 'discovering' && <div className="absolute bottom-6 right-6 w-[330px] rounded-2xl border border-white/[0.08] bg-black/30 p-5"><p className="font-bold">Assets discovered</p><b className="mt-2 block text-5xl" style={{ color: GREEN }}>{assetsFound}</b><p className="text-sm text-slate-500">pages, assets, and endpoints</p></div>}{(phase === 'analyzing' || phase === 'complete') && <FindingsPanel count={findingStep} complete={phase === 'complete'} onOpenCritical={onOpenCritical} />}</div>
}

function TrailLayer() {
  return <svg className="pointer-events-none absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none"><motion.path d="M50 45 C25 42 14 20 7 20 M50 45 C24 48 14 50 7 50 M50 45 C25 58 14 76 7 76 M50 45 C72 42 82 20 88 20 M50 45 C72 48 82 48 88 48 M50 45 C72 58 82 76 88 76 M50 45 C50 68 48 82 48 82 M50 45 C50 28 48 12 48 12" stroke="rgba(132,255,0,0.25)" strokeWidth="0.35" fill="none" strokeDasharray="2 3" initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 1.2, ease: 'easeInOut' }} /></svg>
}

function AssetNode({ item, active, danger }: { item: (typeof ASSETS)[number]; active: boolean; danger?: boolean }) {
  const Icon = item.icon
  return <motion.div className="absolute rounded-xl border px-3 py-2 text-xs" style={{ left: `${item.x}%`, top: `${item.y}%`, borderColor: danger ? 'rgba(255,84,84,0.4)' : active ? 'rgba(132,255,0,0.28)' : 'rgba(255,255,255,0.08)', background: 'rgba(2,8,23,0.9)' }} initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: active ? 1 : 0, scale: active ? 1 : 0.94 }}><Icon className="mb-1 h-4 w-4" style={{ color: danger ? '#ff5454' : GREEN }} /><b>{item.label}</b><p className="text-[10px] text-slate-500">{item.path}</p><p className="mt-1 text-[10px]" style={{ color: danger ? '#ff8a8a' : GREEN }}>Discovered</p></motion.div>
}

function FindingsPanel({ count, complete, onOpenCritical }: { count: number; complete: boolean; onOpenCritical: () => void }) {
  return <div className="absolute right-5 top-20 w-[300px] space-y-3">{FINDINGS.slice(0, count).map((f, i) => <motion.button key={f.title} onClick={complete && i === 0 ? onOpenCritical : undefined} initial={{ opacity: 0, x: 18 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.08 }} className="block w-full rounded-xl border bg-black/40 p-4 text-left backdrop-blur" style={{ borderColor: i === 0 ? 'rgba(255,84,84,0.35)' : 'rgba(255,255,255,0.08)' }}><p className="text-[10px] font-bold uppercase tracking-[0.16em]" style={{ color: f.tone }}>{f.severity}</p><p className="mt-1 font-bold">{f.title}</p><p className="mt-1 text-xs leading-5 text-slate-400">{f.body}</p>{complete && i === 0 && <p className="mt-2 text-xs" style={{ color: GREEN }}>Open finding →</p>}</motion.button>)}</div>
}

function DetailStage({ onBack }: { onBack: () => void }) {
  return <div className="relative z-10 grid h-full grid-cols-[1fr_300px] gap-5"><div className="rounded-2xl border border-white/[0.08] bg-black/25 p-6"><button onClick={onBack} className="mb-5 text-sm text-slate-400">← Back to findings</button><p className="text-xs font-bold uppercase tracking-[0.2em] text-red-400">Critical</p><h3 className="mt-2 text-[36px] font-bold">Admin Portal Exposed</h3><p className="mt-3 text-sm text-slate-400">URL: /admin</p><div className="mt-6 grid grid-cols-2 gap-4"><InfoBox title="What we found" body="A publicly accessible administrative portal was discovered." /><InfoBox title="Why it matters" body="Admin panels are frequent targets for credential attacks and account takeover." /><InfoBox title="Potential impact" body="Unauthorized access, customer data exposure, or site compromise." /><InfoBox title="Recommended action" body="Restrict access with MFA, VPN, IP allowlists, or admin gateways." /></div></div><div className="rounded-2xl border border-red-500/20 bg-red-500/[0.035] p-5"><p className="mb-4 font-bold">WADE Analysis</p><div className="grid grid-cols-3 gap-2 text-center text-xs"><span>Likelihood<br /><b className="text-red-300">High</b></span><span>Impact<br /><b className="text-red-300">High</b></span><span>Priority<br /><b style={{ color: GREEN }}>Fix First</b></span></div><p className="mt-5 text-sm leading-6 text-slate-400">WADE identified this as a high-risk exposure that should be addressed immediately.</p></div></div>
}

function InfoBox({ title, body }: { title: string; body: string }) { return <div className="rounded-xl border border-white/[0.08] bg-black/25 p-4"><p className="font-bold">{title}</p><p className="mt-1 text-sm leading-6 text-slate-400">{body}</p></div> }
