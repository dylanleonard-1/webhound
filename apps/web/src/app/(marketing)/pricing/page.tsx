'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  ArrowRight, Check, Sparkles, Loader2, Shield, Zap, Lock,
} from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { PLAN_DEFINITIONS, type PlanDefinition, type PlanTier } from '@/lib/plans'
import { useAuth } from '@/contexts/auth'
import { cn } from '@/lib/utils'

const PAID_ORDER: PlanTier[] = ['pro', 'shield', 'enterprise']

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

  const free = PLAN_DEFINITIONS.free
  const paid = PAID_ORDER.map(t => PLAN_DEFINITIONS[t])

  return (
    <div className="min-h-screen pt-28 pb-24 px-4">
      <div className="max-w-6xl mx-auto">

        {/* ── Header ─────────────────────────────────────────────────── */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 mb-5 rounded-full"
               style={{ background: 'rgba(139,255,62,0.06)',
                        border: '1px solid rgba(139,255,62,0.18)' }}>
            <Sparkles className="w-3 h-3" style={{ color: '#8BFF3E' }} />
            <span className="text-[11px] font-semibold uppercase tracking-wider"
                  style={{ color: '#8BFF3E' }}>
              Simple, predictable pricing
            </span>
          </div>
          <h1 className="text-4xl sm:text-5xl font-bold text-white mb-4 tracking-tight">
            Find what attackers find,<br />before they do.
          </h1>
          <p className="text-lg max-w-xl mx-auto leading-relaxed"
             style={{ color: 'rgba(255,255,255,0.55)' }}>
            One scanning engine. Three plans for how many sites you watch
            and how often. Cancel anytime, no contracts.
          </p>
        </div>

        {/* ── Free tier strip ────────────────────────────────────────── */}
        <div className="mb-10">
          <button
            type="button"
            onClick={() => handleCta(free)}
            className="w-full flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 rounded-[12px] px-5 py-4 transition-all hover:border-white/15 text-left"
            style={{
              background: 'rgba(255,255,255,0.025)',
              border: '1px solid rgba(255,255,255,0.08)',
            }}
          >
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
                   style={{ background: 'rgba(255,255,255,0.04)',
                            border: '1px solid rgba(255,255,255,0.08)' }}>
                <Zap className="w-4 h-4 text-white/60" />
              </div>
              <div>
                <div className="text-sm font-semibold text-white">
                  Just want to try it? Start free.
                </div>
                <div className="text-xs mt-0.5" style={{ color: 'rgba(255,255,255,0.45)' }}>
                  1 website · 5 scans / month · no credit card
                </div>
              </div>
            </div>
            <div className="flex items-center gap-1.5 text-[13px] font-semibold ml-12 sm:ml-0"
                 style={{ color: '#8BFF3E' }}>
              {currentTier === 'free' ? 'You’re on Free' : 'Start free'}
              <ArrowRight className="w-3.5 h-3.5" />
            </div>
          </button>
        </div>

        {/* ── Paid tier cards (3-up) ─────────────────────────────────── */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {paid.map(plan => {
            const isCurrent = currentTier === plan.tier
            const isPopular = plan.isPopular
            return (
              <div
                key={plan.tier}
                className={cn(
                  'relative flex flex-col rounded-[16px] p-7 transition-all',
                  isPopular && 'md:-mt-3 md:mb-3',
                )}
                style={{
                  background: isPopular
                    ? 'linear-gradient(180deg, rgba(139,255,62,0.05) 0%, rgba(8,12,22,0.95) 50%)'
                    : 'rgba(8,12,22,0.95)',
                  border: isPopular
                    ? '1px solid rgba(139,255,62,0.35)'
                    : '1px solid rgba(255,255,255,0.07)',
                  boxShadow: isPopular
                    ? '0 0 32px rgba(139,255,62,0.12)' : undefined,
                }}
              >
                {/* Top-row badges */}
                <div className="flex items-center justify-between mb-5 h-5">
                  <span className="text-[10px] font-bold uppercase tracking-[0.15em]"
                        style={{
                          color: isPopular ? '#8BFF3E' : 'rgba(255,255,255,0.35)',
                        }}>
                    {plan.name}
                  </span>
                  {isPopular && (
                    <span className="px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider"
                          style={{ background: '#8BFF3E', color: '#020617' }}>
                      Most popular
                    </span>
                  )}
                  {isCurrent && !isPopular && (
                    <span className="px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider"
                          style={{ background: '#4F9CF9', color: '#020617' }}>
                      Current
                    </span>
                  )}
                </div>

                {/* Price */}
                <div className="mb-2">
                  <div className="flex items-baseline gap-1.5">
                    <span className="text-[44px] font-bold text-white leading-none tracking-tight font-mono">
                      ${plan.priceUsdMonthly}
                    </span>
                    <span className="text-[14px]" style={{ color: 'rgba(255,255,255,0.45)' }}>
                      /mo
                    </span>
                  </div>
                </div>
                <p className="text-[13px] mb-6 leading-relaxed"
                   style={{ color: 'rgba(255,255,255,0.55)' }}>
                  {plan.tagline}
                </p>

                {/* CTA */}
                <button
                  type="button"
                  onClick={() => handleCta(plan)}
                  disabled={isCurrent || busyTier === plan.tier}
                  className="w-full flex items-center justify-center gap-1.5 py-3 rounded-[10px] text-[13px] font-semibold transition-all mb-7 disabled:opacity-50 disabled:cursor-not-allowed hover:brightness-110"
                  style={
                    isPopular
                      ? { background: '#8BFF3E', color: '#020617' }
                      : {
                          background: 'rgba(255,255,255,0.04)',
                          color: '#fff',
                          border: '1px solid rgba(255,255,255,0.1)',
                        }
                  }
                >
                  {busyTier === plan.tier ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : isCurrent ? (
                    'Current plan'
                  ) : (
                    <>
                      {plan.ctaLabel}
                      <ArrowRight className="w-3.5 h-3.5" />
                    </>
                  )}
                </button>

                {/* Headline numbers */}
                <div className="grid grid-cols-2 gap-3 mb-5 pb-5"
                     style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                  <Stat n={plan.maxWebsites} label="websites" />
                  <Stat n={plan.scansPerMonth} label="scans / mo" />
                </div>

                {/* Feature list (only included items) */}
                <ul className="space-y-2.5 flex-1">
                  {plan.features.filter(f => f.included).map(f => (
                    <li key={f.label}
                        className="flex items-start gap-2 text-[12.5px] leading-snug">
                      <Check className="w-3.5 h-3.5 flex-shrink-0 mt-0.5"
                             style={{ color: '#8BFF3E' }} />
                      <span style={{ color: 'rgba(255,255,255,0.8)' }}>
                        {f.label}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )
          })}
        </div>

        {/* ── Trust strip ────────────────────────────────────────────── */}
        <div className="mt-14 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <TrustItem icon={<Shield className="w-4 h-4" />}
                     title="Same engine, every plan"
                     body="All 12 scanning engines run on every paid plan — the differences are scale and depth." />
          <TrustItem icon={<Lock className="w-4 h-4" />}
                     title="No surprise bills"
                     body="Flat monthly price. We never charge per scan or per finding." />
          <TrustItem icon={<Zap className="w-4 h-4" />}
                     title="Cancel anytime"
                     body="One click in the billing portal. No retention calls, no contracts." />
        </div>

        {/* ── FAQ ────────────────────────────────────────────────────── */}
        <div className="mt-16 max-w-3xl mx-auto">
          <h2 className="text-xl font-bold text-white text-center mb-6">
            Common questions
          </h2>
          <div className="space-y-2">
            <Faq q="Can I switch plans later?"
                 a="Yes. Upgrade and you're charged a prorated amount immediately. Downgrade and the change takes effect at the next billing cycle." />
            <Faq q="What counts as a scan?"
                 a="One full run of our engine on one website — whether manual or scheduled. Cancelled scans don't count." />
            <Faq q="Do you support team accounts?"
                 a="Shield includes 3 seats, Enterprise includes 15. Need more? Email sales below." />
            <Faq q="Is there a free trial on paid plans?"
                 a="The Free plan is the trial — full engine, 5 scans/mo, forever. Upgrade only when you need more." />
          </div>
        </div>

        {/* ── Sales contact ──────────────────────────────────────────── */}
        <div className="mt-12 text-center">
          <p className="text-[13px]" style={{ color: 'rgba(255,255,255,0.4)' }}>
            Need SSO, on-prem, or a custom SLA?{' '}
            <Link href="mailto:sales@webhoundsecurity.com"
                  className="underline" style={{ color: '#8BFF3E' }}>
              Talk to sales
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}

// ── Small subcomponents ──────────────────────────────────────────────

function Stat({ n, label }: { n: number; label: string }) {
  return (
    <div>
      <div className="text-[18px] font-bold text-white font-mono leading-none">
        {n >= 1000 ? `${(n / 1000).toFixed(n % 1000 === 0 ? 0 : 1)}k` : n}
      </div>
      <div className="text-[11px] mt-1" style={{ color: 'rgba(255,255,255,0.4)' }}>
        {label}
      </div>
    </div>
  )
}

function TrustItem({ icon, title, body }: {
  icon: React.ReactNode
  title: string
  body: string
}) {
  return (
    <div className="rounded-[12px] p-4"
         style={{
           background: 'rgba(255,255,255,0.02)',
           border: '1px solid rgba(255,255,255,0.06)',
         }}>
      <div className="flex items-center gap-2 mb-1.5"
           style={{ color: '#8BFF3E' }}>
        {icon}
        <span className="text-[12px] font-semibold text-white">{title}</span>
      </div>
      <p className="text-[12px] leading-relaxed"
         style={{ color: 'rgba(255,255,255,0.5)' }}>
        {body}
      </p>
    </div>
  )
}

function Faq({ q, a }: { q: string; a: string }) {
  return (
    <details className="group rounded-[10px] px-4 py-3 transition-colors"
             style={{
               background: 'rgba(255,255,255,0.02)',
               border: '1px solid rgba(255,255,255,0.06)',
             }}>
      <summary className="text-[13px] font-semibold text-white cursor-pointer list-none flex items-center justify-between">
        {q}
        <ArrowRight className="w-3.5 h-3.5 transition-transform group-open:rotate-90"
                    style={{ color: 'rgba(255,255,255,0.4)' }} />
      </summary>
      <p className="text-[12.5px] mt-2 leading-relaxed"
         style={{ color: 'rgba(255,255,255,0.55)' }}>
        {a}
      </p>
    </details>
  )
}
