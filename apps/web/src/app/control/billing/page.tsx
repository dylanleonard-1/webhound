'use client'

// Billing Operations Center — true MRR/ARR/churn from Stripe + subscriptions
// list + recent webhook events for delivery monitoring.

import { useCallback, useEffect, useState } from 'react'
import {
  CreditCard, TrendingUp, AlertTriangle, Loader2, Activity, RefreshCcw,
} from 'lucide-react'
import {
  api, type BillingMetrics, type SubscriptionRow, type StripeEventRow,
} from '@/lib/api'

const LIME = '#8BFF3E'

function Stat({ label, value, sub, color }: {
  label: string; value: React.ReactNode; sub?: string; color?: string
}) {
  return (
    <div className="rounded-xl p-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)' }}>
      <div className="text-[11px] font-bold tracking-[0.1em] uppercase mb-1.5" style={{ color: 'rgba(255,255,255,0.4)' }}>{label}</div>
      <div className="text-[24px] font-bold leading-none" style={{ color: color ?? '#fff' }}>{value}</div>
      {sub && <div className="text-[11px] mt-1.5" style={{ color: 'rgba(255,255,255,0.4)' }}>{sub}</div>}
    </div>
  )
}

const STATUS_COLOR: Record<string, string> = {
  active: LIME, trialing: '#3b82f6', past_due: '#f59e0b', canceled: 'rgba(255,255,255,0.4)',
  unpaid: '#ef4444', incomplete: '#f97316', incomplete_expired: '#ef4444', paused: '#a855f7',
}

export default function BillingPage() {
  const [metrics, setMetrics] = useState<BillingMetrics | null>(null)
  const [subs, setSubs] = useState<SubscriptionRow[]>([])
  const [events, setEvents] = useState<StripeEventRow[]>([])
  const [subFilter, setSubFilter] = useState('')
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    Promise.all([
      api.internal.billingMetrics().then(setMetrics).catch(() => {}),
      api.internal.billingSubscriptions(subFilter || undefined).then(r => setSubs(r.items)).catch(() => {}),
      api.internal.billingEvents(50).then(r => setEvents(r.items)).catch(() => {}),
    ]).finally(() => setLoading(false))
  }, [subFilter])
  useEffect(() => { load() }, [load])

  const stripeBad = metrics && 'error' in metrics.stripe
  const stripe = !stripeBad && metrics ? metrics.stripe as Exclude<BillingMetrics['stripe'], { error: string }> : null

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <CreditCard className="w-5 h-5" style={{ color: LIME }} />
        <h1 className="text-[19px] font-bold text-white">Billing Operations</h1>
        <button onClick={load} className="ml-auto flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px]"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', color: 'rgba(255,255,255,0.65)' }}>
          <RefreshCcw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {stripeBad && (
        <div className="rounded-lg p-3 text-[12px] flex items-center gap-2"
             style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', color: '#fca5a5' }}>
          <AlertTriangle className="w-4 h-4" /> Stripe metrics unavailable — {(metrics.stripe as { error: string }).error}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="MRR" color={LIME}
              value={stripe ? `$${stripe.mrr_usd.toLocaleString(undefined, { maximumFractionDigits: 0 })}` : (stripeBad ? '—' : <Loader2 className="w-5 h-5 animate-spin" />)}
              sub={stripe ? `$${stripe.arr_usd.toLocaleString(undefined, { maximumFractionDigits: 0 })} ARR` : ''} />
        <Stat label="Active subs"
              value={stripe?.active_subscriptions ?? (metrics?.local.active_subscriptions_local ?? '—')}
              sub={metrics ? `${metrics.local.active_subscriptions_local} mirrored locally` : ''} />
        <Stat label="Past due" color={stripe && stripe.past_due > 0 ? '#f59e0b' : undefined}
              value={stripe ? stripe.past_due : '—'}
              sub="Subscriptions in past_due status" />
        <Stat label="Failed pay 24h" color={stripe && stripe.failed_payments_24h > 0 ? '#ef4444' : undefined}
              value={stripe ? stripe.failed_payments_24h : '—'}
              sub={metrics ? `${metrics.local.canceled_last_30d} canceled (30d)` : ''} />
      </div>

      {/* Subscriptions */}
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <TrendingUp className="w-4 h-4" style={{ color: LIME }} />
          <span className="text-[13px] font-semibold text-white">Subscriptions</span>
          <select value={subFilter} onChange={e => setSubFilter(e.target.value)}
                  className="ml-2 px-2.5 py-1 rounded text-[11px] text-white/75 outline-none"
                  style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <option value="" className="bg-[#0b0f17]">all</option>
            {['active','trialing','past_due','canceled','unpaid','incomplete','paused'].map(s =>
              <option key={s} value={s} className="bg-[#0b0f17]">{s}</option>)}
          </select>
        </div>
        <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
          <table className="w-full text-[12px]">
            <thead>
              <tr className="text-left" style={{ background: 'rgba(255,255,255,0.02)', color: 'rgba(255,255,255,0.4)' }}>
                <th className="font-semibold px-3 py-2.5">Customer</th>
                <th className="font-semibold px-3 py-2.5">Plan</th>
                <th className="font-semibold px-3 py-2.5">Status</th>
                <th className="font-semibold px-3 py-2.5">Period end</th>
                <th className="font-semibold px-3 py-2.5">Subscription</th>
              </tr>
            </thead>
            <tbody>
              {subs.length === 0 ? (
                <tr><td colSpan={5} className="px-3 py-6 text-center text-white/35">
                  {loading ? <Loader2 className="w-4 h-4 animate-spin inline" /> : 'No subscriptions match.'}
                </td></tr>
              ) : subs.map(s => {
                const c = STATUS_COLOR[s.status] ?? 'rgba(255,255,255,0.5)'
                return (
                  <tr key={s.id} className="border-t border-white/[0.04] hover:bg-white/[0.02]">
                    <td className="px-3 py-2 text-white/85 max-w-[260px] truncate">{s.email}</td>
                    <td className="px-3 py-2 capitalize text-white/70">{s.plan}</td>
                    <td className="px-3 py-2">
                      <span className="text-[11px] font-semibold capitalize" style={{ color: c }}>{s.status}</span>
                      {s.cancel_at_period_end && <span className="ml-1 text-[10px] text-orange-400">(cancels)</span>}
                    </td>
                    <td className="px-3 py-2 text-white/50">{s.current_period_end ? new Date(s.current_period_end).toLocaleDateString() : '—'}</td>
                    <td className="px-3 py-2 font-mono text-[10px] text-white/35">{s.stripe_subscription_id}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent Stripe events — webhook delivery monitoring */}
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4" style={{ color: LIME }} />
          <span className="text-[13px] font-semibold text-white">Recent Stripe events</span>
          <span className="text-[11px] text-white/40">webhook delivery health</span>
        </div>
        <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
          <table className="w-full text-[12px]">
            <thead>
              <tr className="text-left" style={{ background: 'rgba(255,255,255,0.02)', color: 'rgba(255,255,255,0.4)' }}>
                <th className="font-semibold px-3 py-2.5">Type</th>
                <th className="font-semibold px-3 py-2.5">Mode</th>
                <th className="font-semibold px-3 py-2.5">Created</th>
                <th className="font-semibold px-3 py-2.5">Event ID</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr><td colSpan={4} className="px-3 py-6 text-center text-white/35">
                  {loading ? <Loader2 className="w-4 h-4 animate-spin inline" /> : 'No events.'}
                </td></tr>
              ) : events.map(e => (
                <tr key={e.id} className="border-t border-white/[0.04]">
                  <td className="px-3 py-2 font-mono text-white/80">{e.type}</td>
                  <td className="px-3 py-2">
                    <span className="text-[10px] px-1.5 py-0.5 rounded font-bold uppercase"
                          style={{ background: e.livemode ? 'rgba(139,255,62,0.1)' : 'rgba(255,255,255,0.05)',
                                   color: e.livemode ? LIME : 'rgba(255,255,255,0.4)',
                                   border: `1px solid ${e.livemode ? 'rgba(139,255,62,0.2)' : 'rgba(255,255,255,0.08)'}` }}>
                      {e.livemode ? 'LIVE' : 'TEST'}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-white/55">{new Date(e.created * 1000).toLocaleString()}</td>
                  <td className="px-3 py-2 font-mono text-[10px] text-white/35">{e.id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
