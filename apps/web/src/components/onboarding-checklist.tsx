'use client'

// Phase-19 Task 9 (frontend): the onboarding checklist. Renders the
// guided steps the API derives (apps/api/platform/onboarding) and points
// the user at their next action. Shows nothing once onboarding completes.

import Link from 'next/link'
import { Check, Circle, ArrowRight } from 'lucide-react'

export interface OnboardingStep {
  key: string
  label: string
  done: boolean
  required: boolean
}

export interface OnboardingStateData {
  steps: OnboardingStep[]
  completed_count: number
  total_count: number
  percent_complete: number
  is_complete: boolean
  next_step: OnboardingStep | null
}

// Where each step takes the user.
const STEP_HREF: Record<string, string> = {
  email_verified: '/dashboard/settings',
  domain_added: '/dashboard/websites',
  domain_verified: '/dashboard/websites',
  first_scan_started: '/dashboard/scans',
  first_report_viewed: '/dashboard/scans',
  monitoring_enabled: '/dashboard/monitoring',
  billing_active: '/dashboard/billing',
}

export function OnboardingChecklist({ state }: { state: OnboardingStateData }) {
  if (state.is_complete) return null

  return (
    <div className="rounded-xl border p-5"
      style={{ borderColor: 'rgba(139,255,62,0.18)', background: 'rgba(139,255,62,0.04)' }}>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <p className="text-sm font-semibold text-white">Get started with WebHound</p>
          <p className="text-xs text-gray-400">
            {state.completed_count} of {state.total_count} steps complete
          </p>
        </div>
        <span className="text-lg font-semibold" style={{ color: '#8BFF3E' }}>
          {state.percent_complete}%
        </span>
      </div>

      <div className="mb-4 h-1.5 w-full overflow-hidden rounded-full bg-gray-800">
        <div className="h-full rounded-full transition-all"
          style={{ width: `${state.percent_complete}%`, background: '#8BFF3E' }} />
      </div>

      <ul className="space-y-2">
        {state.steps.map(step => {
          const isNext = state.next_step?.key === step.key
          const href = STEP_HREF[step.key]
          const row = (
            <div className="flex items-center gap-3 text-sm">
              {step.done
                ? <Check className="h-4 w-4 shrink-0" style={{ color: '#8BFF3E' }} />
                : <Circle className="h-4 w-4 shrink-0 text-gray-600" />}
              <span className={step.done ? 'text-gray-500 line-through' : 'text-gray-200'}>
                {step.label}
              </span>
              {isNext && <ArrowRight className="ml-auto h-4 w-4" style={{ color: '#8BFF3E' }} />}
            </div>
          )
          return (
            <li key={step.key}>
              {!step.done && href
                ? <Link href={href} className="block rounded-lg px-1 py-1 hover:bg-white/5">{row}</Link>
                : <div className="px-1 py-1">{row}</div>}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
