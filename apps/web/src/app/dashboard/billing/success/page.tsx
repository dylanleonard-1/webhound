'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import {
  ArrowRight, CheckCircle2, CreditCard, Loader2, RefreshCw, Sparkles,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth'
import { api, type CurrentSubscriptionResponse } from '@/lib/api'
import { PLAN_DEFINITIONS, type PlanTier } from '@/lib/plans'

const LIME = '#8BFF3E'

const PLAN_LABEL: Record<string, string> = {
  free: 'Free',
  pro: 'Pro',
  shield: 'Shield',
  enterprise: 'Managed Security Review',
}

type Phase = 'syncing' | 'confirmed' | 'pending'

/**
 * Post-checkout landing page. Instead of waiting on the Stripe webhook to
 * land, it reconciles plan state directly via POST /billing/sync — the first
 * call almost always resolves the new tier, and we poll a few more times as a
 * safety net. If activation is still slow we surface a manual retry rather
 * than leaving the user staring at a spinner.
 */
function CheckoutSuccess() {
  const { refresh } = useAuth()
  const [sub, setSub] = useState<CurrentSubscriptionResponse | null>(null)
  const [phase, setPhase] = useState<Phase>('syncing')
  const [retrying, setRetrying] = useState(false)

  // syncOnce reconciles from Stripe and reports whether a paid plan is active.
  const syncOnce = useCallback(async (): Promise<boolean> => {
    try {
      const s = await api.billing.sync()
      setSub(s)
      if (s.plan && s.plan !== 'free') {
        setPhase('confirmed')
        refresh().catch(() => {})
        return true
      }
    } catch { /* swallow — caller decides whether to keep polling */ }
    return false
  }, [refresh])

  const pollRef = useRef(false)
  useEffect(() => {
    if (pollRef.current) return   // guard React 18 strict-mode double-run
    pollRef.current = true
    let cancelled = false
    let attempts = 0
    const MAX = 5

    ;(async () => {
      if (await syncOnce() || cancelled) return
      const id = window.setInterval(async () => {
        attempts += 1
        const done = await syncOnce()
        if (cancelled || done || attempts >= MAX) {
          window.clearInterval(id)
          if (!cancelled && !done) setPhase('pending')
        }
      }, 2000)
    })()

    return () => { cancelled = true }
  }, [syncOnce])

  async function handleRetry() {
    setRetrying(true)
    setPhase('syncing')
    const ok = await syncOnce()
    if (!ok) setPhase('pending')
    setRetrying(false)
  }

  const planName = sub ? (PLAN_LABEL[sub.plan] ?? sub.plan) : null
  const planDef =
    sub && sub.plan !== 'free' ? PLAN_DEFINITIONS[sub.plan as PlanTier] : null
  const unlocked = planDef?.features.filter(f => f.included).slice(0, 5) ?? []
  const renewsOn = sub?.current_period_end
    ? new Date(sub.current_period_end).toLocaleDateString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
      })
    : null

  return (
    <div className="min-h-[70vh] flex items-center justify-center px-4 py-12">
      <div
        className="w-full max-w-md rounded-2xl p-8 text-center"
        style={{
          background: 'rgba(255,255,255,0.02)',
          border: '1px solid rgba(255,255,255,0.08)',
        }}
      >
        {phase === 'syncing' && (
          <>
            <IconRing>
              <Loader2 className="w-7 h-7 animate-spin" style={{ color: LIME }} />
            </IconRing>
            <h1 className="text-[20px] font-bold text-white mt-5">
              Finalizing your subscription
            </h1>
            <p className="text-[13px] mt-2" style={{ color: 'rgba(255,255,255,0.55)' }}>
              Confirming your payment with Stripe and unlocking your new plan.
              This usually takes just a moment.
            </p>
          </>
        )}

        {phase === 'confirmed' && (
          <>
            <IconRing glow>
              <CheckCircle2 className="w-8 h-8" style={{ color: LIME }} />
            </IconRing>
            <p
              className="text-[11px] font-black tracking-[0.14em] uppercase mt-5"
              style={{ color: 'rgba(255,255,255,0.35)' }}
            >
              Payment confirmed
            </p>
            <h1 className="text-[24px] font-bold text-white mt-1.5 flex items-center justify-center gap-2">
              <Sparkles className="w-5 h-5" style={{ color: LIME }} />
              Welcome to {planName}
            </h1>
            <p className="text-[13px] mt-2" style={{ color: 'rgba(255,255,255,0.55)' }}>
              Your new limits are live now
              {renewsOn ? <> · renews {renewsOn}</> : null}.
            </p>

            {unlocked.length > 0 && (
              <ul className="mt-5 space-y-2 text-left">
                {unlocked.map(f => (
                  <li key={f.label} className="flex items-center gap-2.5">
                    <CheckCircle2
                      className="w-4 h-4 flex-shrink-0"
                      style={{ color: LIME }}
                    />
                    <span className="text-[13px] text-white">{f.label}</span>
                  </li>
                ))}
              </ul>
            )}

            <div className="mt-7 flex flex-col gap-2.5">
              <Link
                href="/dashboard"
                className="flex items-center justify-center gap-2 rounded-[10px] py-2.5 text-[13px] font-semibold text-black transition-opacity hover:opacity-90"
                style={{ background: LIME }}
              >
                Go to dashboard
                <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/dashboard/settings?tab=billing"
                className="flex items-center justify-center gap-2 rounded-[10px] py-2.5 text-[13px] font-medium text-white transition-colors hover:bg-white/[0.05]"
                style={{ border: '1px solid rgba(255,255,255,0.1)' }}
              >
                <CreditCard className="w-4 h-4" />
                Manage billing
              </Link>
            </div>
          </>
        )}

        {phase === 'pending' && (
          <>
            <IconRing>
              <RefreshCw className="w-7 h-7" style={{ color: '#f97316' }} />
            </IconRing>
            <h1 className="text-[20px] font-bold text-white mt-5">
              This is taking a little longer than usual
            </h1>
            <p className="text-[13px] mt-2" style={{ color: 'rgba(255,255,255,0.55)' }}>
              Your payment went through. It can take a moment for the new plan
              to activate — check again, or head to billing and it&apos;ll update
              automatically.
            </p>

            <div className="mt-7 flex flex-col gap-2.5">
              <button
                onClick={handleRetry}
                disabled={retrying}
                className="flex items-center justify-center gap-2 rounded-[10px] py-2.5 text-[13px] font-semibold text-black transition-opacity hover:opacity-90 disabled:opacity-60"
                style={{ background: LIME }}
              >
                {retrying ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <RefreshCw className="w-4 h-4" />
                )}
                Check again
              </button>
              <Link
                href="/dashboard/settings?tab=billing"
                className="flex items-center justify-center gap-2 rounded-[10px] py-2.5 text-[13px] font-medium text-white transition-colors hover:bg-white/[0.05]"
                style={{ border: '1px solid rgba(255,255,255,0.1)' }}
              >
                <CreditCard className="w-4 h-4" />
                Go to billing
              </Link>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function IconRing({ children, glow }: { children: React.ReactNode; glow?: boolean }) {
  return (
    <div
      className="mx-auto w-16 h-16 rounded-full flex items-center justify-center"
      style={{
        background: 'rgba(139,255,62,0.08)',
        border: '1px solid rgba(139,255,62,0.25)',
        boxShadow: glow ? '0 0 40px rgba(139,255,62,0.25)' : undefined,
      }}
    >
      {children}
    </div>
  )
}

export default CheckoutSuccess
