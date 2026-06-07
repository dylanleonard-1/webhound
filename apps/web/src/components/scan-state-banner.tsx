'use client'

// Phase-19 Task 12: polished, reusable scan/account state banners — no
// blank screens, no raw stack traces. Covers the states the scan detail
// page and dashboard need beyond queued/running/completed/failed:
// partial completion, browser-degraded-but-static-OK, domain
// verification failed, payment required, and plan-limit reached.

import Link from 'next/link'
import {
  Clock, Loader2, CheckCircle, XCircle, AlertTriangle,
  ShieldAlert, CreditCard, Gauge, Globe,
} from 'lucide-react'

export type ScanState =
  | 'queued'
  | 'running'
  | 'completed'
  | 'partial'
  | 'browser_degraded'
  | 'failed'
  | 'verification_failed'
  | 'payment_required'
  | 'plan_limit'

interface StateConfig {
  label: string
  description: string
  color: string
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  spin?: boolean
  cta?: { label: string; href: string }
}

const STATES: Record<ScanState, StateConfig> = {
  queued: {
    label: 'Scan queued',
    description: 'Your scan is in the queue and will start shortly.',
    color: '#9ca3af', icon: Clock,
  },
  running: {
    label: 'Scan running',
    description: 'WebHound is analyzing your site. This usually takes a minute or two.',
    color: '#4F9CF9', icon: Loader2, spin: true,
  },
  completed: {
    label: 'Scan complete',
    description: 'Your report is ready.',
    color: '#8BFF3E', icon: CheckCircle,
  },
  partial: {
    label: 'Scan partially completed',
    description: 'Some checks could not finish, but we gathered usable results. Re-run the scan for full coverage.',
    color: '#FFC53E', icon: AlertTriangle,
  },
  browser_degraded: {
    label: 'Static scan completed',
    description: 'Browser-based discovery could not run for this site, so results are based on the static scan. Findings are still valid — some browser-only checks were skipped.',
    color: '#FFC53E', icon: AlertTriangle,
  },
  failed: {
    label: 'Scan failed',
    description: 'We hit an error completing this scan. No charge was made. You can try again.',
    color: '#ef4444', icon: XCircle,
    cta: { label: 'Retry scan', href: '/dashboard/scans' },
  },
  verification_failed: {
    label: 'Domain not verified',
    description: 'Deep scans require verified domain ownership. Complete verification to continue.',
    color: '#ef4444', icon: ShieldAlert,
    cta: { label: 'Verify domain', href: '/dashboard/websites' },
  },
  payment_required: {
    label: 'Payment required',
    description: 'This feature needs an active subscription. Choose a plan to continue.',
    color: '#4F9CF9', icon: CreditCard,
    cta: { label: 'View plans', href: '/dashboard/billing' },
  },
  plan_limit: {
    label: 'Plan limit reached',
    description: 'You have reached your plan’s scan limit. Upgrade for more scans and deeper monitoring.',
    color: '#FF8A3E', icon: Gauge,
    cta: { label: 'Upgrade plan', href: '/dashboard/billing' },
  },
}

export function ScanStateBanner({ state, detail }: { state: ScanState; detail?: string }) {
  const cfg = STATES[state] ?? STATES.queued
  const Icon = cfg.icon
  return (
    <div className="flex items-start gap-4 rounded-xl border p-5"
      style={{ borderColor: `${cfg.color}33`, background: `${cfg.color}0d` }}>
      <Icon className={`mt-0.5 h-6 w-6 shrink-0 ${cfg.spin ? 'animate-spin' : ''}`}
        style={{ color: cfg.color }} />
      <div className="flex-1">
        <p className="text-sm font-semibold text-white">{cfg.label}</p>
        <p className="mt-1 text-sm text-gray-400">{detail ?? cfg.description}</p>
        {cfg.cta && (
          <Link href={cfg.cta.href}
            className="mt-3 inline-block rounded-lg px-3 py-1.5 text-sm font-medium"
            style={{ color: cfg.color, background: `${cfg.color}1a` }}>
            {cfg.cta.label}
          </Link>
        )}
      </div>
    </div>
  )
}

// A bare icon — used elsewhere with an explicit Globe fallback.
export const ScanStateGlobe = Globe
