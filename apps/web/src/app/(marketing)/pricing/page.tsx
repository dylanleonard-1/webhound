'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowRight, Check, Minus, Sparkles, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { planOrder, type PlanDefinition, type PlanTier } from '@/lib/plans'
import { useAuth } from '@/contexts/auth'
import { cn } from '@/lib/utils'

function priceFor(plan: PlanDefinition): string {
  if (plan.priceUsdMonthly === 0) return '$0'
  return `$${plan.priceUsdMonthly}`
}

export default function PricingPage() {
  const { user } = useAuth()
  const [currentTier, setCurrentTier] = useState<PlanTier | null>(null)
  const [busyTier, setBusyTier] = useState<PlanTier | null>(null)

  useEffect(() => {
    if (!user) return
    api.billing.subscription()
      .then(s => setCurrentTier(s.plan))
      .catch(() => {})
  }, [user])

  async function handleCta(plan: PlanDefinition) {
    if (plan.tier === 'free') {
      window.location.href = user ? '/dashboard' : '/register'
      return
    }
    if (!user) {
      // Default to /login since most upgrades come from existing accounts;
      // the login page exposes a Sign-up link that preserves ?next=.
      window.location.href = `/login?next=${encodeURIComponent('/pricing')}`
      return
    }
    setBusyTier(plan.tier)
    try {
      const { url } = await api.billing.checkout({
        tier: plan.tier as 'pro' | 'shield' | 'enterprise',
      })
      window.location.href = url
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Checkout failed.'
      toast.error(msg)
    } finally {
      setBusyTier(null)
    }
  }

  const tiers = planOrder()

  return (
    <div className="min-h-screen pt-32 pb-24 px-4">
      <div className="max-w-6xl mx-auto">

        {/* Header */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1 mb-5 rounded-full"
               style={{ background: 'rgba(139,255,62,0.06)',
                        border: '1px solid rgba(139,255,62,0.18)' }}>
            <Sparkles className="w-3 h-3" style={{ color: '#8BFF3E' }} />
            <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: '#8BFF3E' }}>
              Plans &amp; pricing
            </span>
          </div>
          <h1 className="text-4xl sm:text-5xl font-bold text-white mb-4 tracking-tight">
            Find what attackers find,<br />before they do.
          </h1>
          <p className="text-lg max-w-2xl mx-auto leading-relaxed"
             style={{ color: 'rgba(255,255,255,0.55)' }}>
            Start free with one website. Upgrade for continuous monitoring,
            unlimited reports, and team access.
          </p>
        </div>

        {/* Tier cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
          {tiers.map(plan => {
            const isCurrent = currentTier === plan.tier
            const cadenceSuffix = plan.priceUsdMonthly > 0 ? '/mo' : ''
            return (
              <div
                key={plan.tier}
                className={cn(
                  'relative flex flex-col rounded-[14px] p-6 transition-all',
                  plan.isPopular ? 'scale-[1.02]' : '',
                )}
                style={{
                  background: plan.isPopular
                    ? 'linear-gradient(180deg, rgba(139,255,62,0.06), rgba(8,12,22,0.95))'
                    : 'rgba(8,12,22,0.95)',
                  border: plan.isPopular
                    ? '1px solid rgba(139,255,62,0.4)'
                    : '1px solid rgba(255,255,255,0.06)',
                  boxShadow: plan.isPopular
                    ? '0 0 24px rgba(139,255,62,0.18)' : undefined,
                }}
              >
                {plan.isPopular && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider"
                       style={{ background: '#8BFF3E', color: '#020617' }}>
                    Most popular
                  </div>
                )}
                {isCurrent && (
                  <div className="absolute -top-3 right-4 px-2.5 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider"
                       style={{ background: '#4F9CF9', color: '#020617' }}>
                    Current plan
                  </div>
                )}

                <div className="mb-4">
                  <h3 className="text-[18px] font-bold text-white mb-1">{plan.name}</h3>
                  <p className="text-[12px]" style={{ color: 'rgba(255,255,255,0.45)' }}>
                    {plan.tagline}
                  </p>
                </div>

                <div className="mb-6">
                  <div className="flex items-baseline gap-1.5">
                    <span className="text-[34px] font-bold text-white leading-none font-mono">
                      {priceFor(plan)}
                    </span>
                    {cadenceSuffix && (
                      <span className="text-[12px]" style={{ color: 'rgba(255,255,255,0.4)' }}>
                        {cadenceSuffix}
                      </span>
                    )}
                  </div>
                  <p className="text-[10px] mt-1.5" style={{ color: 'rgba(255,255,255,0.3)' }}>
                    {plan.tier === 'free'
                      ? 'forever, no credit card'
                      : 'billed monthly · cancel anytime'}
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => handleCta(plan)}
                  disabled={isCurrent || busyTier === plan.tier}
                  className={cn(
                    'w-full flex items-center justify-center gap-1.5 py-2.5 rounded-[8px] text-[13px] font-semibold transition-all mb-6 disabled:opacity-50 disabled:cursor-not-allowed',
                  )}
                  style={
                    plan.isPopular
                      ? { background: '#8BFF3E', color: '#020617' }
                      : { background: 'rgba(255,255,255,0.06)',
                          color: '#fff',
                          border: '1px solid rgba(255,255,255,0.12)' }
                  }
                >
                  {busyTier === plan.tier ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <>
                      {isCurrent ? 'Current plan' : plan.ctaLabel}
                      {!isCurrent && <ArrowRight className="w-3.5 h-3.5" />}
                    </>
                  )}
                </button>

                <ul className="space-y-2 flex-1">
                  {plan.features.map(f => (
                    <li key={f.label} className="flex items-start gap-2 text-[12px] leading-snug">
                      {f.included ? (
                        <Check className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" style={{ color: '#8BFF3E' }} />
                      ) : (
                        <Minus className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" style={{ color: 'rgba(255,255,255,0.15)' }} />
                      )}
                      <span style={{
                        color: f.included ? 'rgba(255,255,255,0.78)' : 'rgba(255,255,255,0.28)',
                      }}>
                        {f.label}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )
          })}
        </div>

        {/* Footer note */}
        <div className="mt-16 text-center max-w-2xl mx-auto">
          <p className="text-[13px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.4)' }}>
            Every paid plan runs the same WebHound scanning engine — 12 specialized
            engines with plain-English findings. Higher tiers add more websites,
            more scans, threat-intel enrichment, team seats, and API access.
          </p>
          <p className="text-[12px] mt-4" style={{ color: 'rgba(255,255,255,0.28)' }}>
            Need something beyond Enterprise (SSO, on-prem, custom SLA)? Email{' '}
            <Link href="mailto:sales@webhoundsecurity.com"
                  className="underline" style={{ color: '#8BFF3E' }}>
              sales@webhoundsecurity.com
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
