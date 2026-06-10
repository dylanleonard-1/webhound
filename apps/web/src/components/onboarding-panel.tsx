'use client'

import { useEffect, useState } from 'react'
import {
  type LucideIcon,
  AlertTriangle, CheckCircle2, Circle, Globe2, History, KeyRound,
  ListChecks, Loader2, ScanLine, XCircle,
} from 'lucide-react'
import {
  api,
  type AccessValidationView,
  type OnboardingAuditView,
  type OnboardingReadinessView,
  type OnboardingWizardView,
  type ProviderProfileResponse,
  type TrustedAccessView,
} from '@/lib/api'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

// All data is read-only and sourced from the Phase 3.1-3.8 services — this
// component performs no recalculation and never displays secrets.

const GREEN = 'bg-[#8BFF3E]/10 text-[#8BFF3E] border border-[#8BFF3E]/20'
const AMBER = 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
const RED = 'bg-red-500/10 text-red-400 border border-red-500/20'
const GRAY = 'bg-white/5 text-gray-400 border border-white/10'

function statusClass(status: string | null | undefined): string {
  const s = (status || '').toLowerCase()
  if (['ready', 'active', 'completed', 'verified', 'pass'].includes(s)) return GREEN
  if (['limited', 'pending', 'warning', 'in_progress', 'validating'].includes(s)) return AMBER
  if (['failed', 'blocked', 'not_ready', 'revoked', 'expired', 'fail'].includes(s)) return RED
  return GRAY
}

function fmt(s: string | null | undefined): string {
  if (!s) return '—'
  const d = new Date(s)
  return isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

function humanize(s: string): string {
  return s.replace(/[._]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

function Row({ label, value, badge }: { label: string; value?: string | null; badge?: string }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-white/5 last:border-0">
      <span className="text-xs text-gray-500">{label}</span>
      {badge !== undefined
        ? <Badge className={statusClass(badge)}>{badge || '—'}</Badge>
        : <span className="text-xs text-gray-300 font-mono">{value || '—'}</span>}
    </div>
  )
}

function SectionTitle({ icon: Icon, title, source }: { icon: LucideIcon; title: string; source?: string }) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <Icon className="w-4 h-4 text-[#8BFF3E]" />
      <h3 className="text-sm font-semibold text-white">{title}</h3>
      {source && <span className="ml-auto text-[10px] text-gray-600 uppercase tracking-wider">{source}</span>}
    </div>
  )
}

interface PanelData {
  provider: ProviderProfileResponse | null
  trusted: TrustedAccessView | null
  validation: AccessValidationView | null
  readiness: OnboardingReadinessView | null
  wizard: OnboardingWizardView | null
  audit: OnboardingAuditView | null
}

export function OnboardingPanel({ websiteId }: { websiteId: string }) {
  const [data, setData] = useState<PanelData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      // Provider discovery 404s until it has run — tolerate it (and any
      // transient error) so the panel always renders what IS available.
      const [provider, trusted, validation, readiness, wizard, audit] = await Promise.all([
        api.websites.providers(websiteId).catch(() => null),
        api.websites.trustedAccess(websiteId).catch(() => null),
        api.websites.accessValidation(websiteId).catch(() => null),
        api.websites.onboarding(websiteId).catch(() => null),
        api.websites.onboardingWizard(websiteId).catch(() => null),
        api.websites.audit(websiteId).catch(() => null),
      ])
      if (!cancelled) {
        setData({ provider, trusted, validation, readiness, wizard, audit })
        setLoading(false)
      }
    }
    void load()
    return () => { cancelled = true }
  }, [websiteId])

  if (loading) {
    return (
      <Card className="p-5">
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading onboarding status…
        </div>
      </Card>
    )
  }
  if (!data) return null

  const { provider, trusted, validation, readiness, wizard, audit } = data
  const counts: [string, number][] = validation
    ? [['Pages', validation.pages_found], ['Scripts', validation.scripts_found],
       ['APIs', validation.apis_found], ['3rd Parties', validation.third_parties_found]]
    : []

  return (
    <div className="space-y-4">
      {/* Status overview */}
      <Card className="p-5">
        <SectionTitle icon={Globe2} title="Onboarding & Scanner Access" source="Phase 3" />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6">
          <Row label="Provider" value={provider?.cdn_provider || provider?.waf_provider || provider?.hosting_provider || readiness?.provider || 'unknown'} />
          <Row label="Verification" badge={readiness?.verification} />
          <Row label="Trusted Access" badge={trusted?.status} />
          <Row label="Validation" badge={validation?.status} />
          <Row label="Readiness" badge={readiness?.status} />
          <Row label="Monitoring" badge={readiness?.monitoring} />
        </div>
        {wizard && (
          <div className="mt-4">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs text-gray-500">Onboarding progress</span>
              <span className="text-xs text-[#8BFF3E] font-semibold">{wizard.completion_percent}% complete</span>
            </div>
            <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
              <div className="h-full rounded-full bg-[#8BFF3E]" style={{ width: `${wizard.completion_percent}%` }} />
            </div>
          </div>
        )}
      </Card>

      {/* Coverage limited notice */}
      {validation && validation.status === 'limited' && validation.challenge_detected && (
        <Card className="p-5" style={{ borderColor: 'rgba(245,158,11,0.3)' }}>
          <SectionTitle icon={AlertTriangle} title="Coverage Limited" source="Phase 3.5" />
          <Row label="Challenge Provider" value={validation.challenge_provider} />
          <Row label="Impact" value="Reduced browser visibility" />
          <p className="text-xs text-gray-400 mt-2">{validation.recommendation}</p>
        </Card>
      )}

      {/* Onboarding steps */}
      {wizard && wizard.steps.length > 0 && (
        <Card className="p-5">
          <SectionTitle icon={ListChecks} title="Onboarding Steps" source="Phase 3.7" />
          <div className="space-y-1">
            {wizard.steps.map((step) => {
              const done = ['completed', 'limited', 'active'].includes(step.status)
              const failed = step.status === 'failed'
              const current = step.step === wizard.current_step
              const Icon = failed ? XCircle : done ? CheckCircle2 : Circle
              const color = failed ? 'text-red-400' : done ? 'text-[#8BFF3E]' : current ? 'text-amber-400' : 'text-gray-600'
              return (
                <div key={step.key} className="flex items-center gap-2.5 py-1">
                  <Icon className={`w-4 h-4 ${color}`} />
                  <span className={`text-xs ${current ? 'text-white font-medium' : 'text-gray-400'}`}>{step.name}</span>
                  {current && <span className="text-[10px] text-amber-400 uppercase tracking-wider">current</span>}
                  <Badge className={`ml-auto ${statusClass(step.status)}`}>{step.status}</Badge>
                </div>
              )
            })}
          </div>
        </Card>
      )}

      {/* Website environment */}
      {provider && (
        <Card className="p-5">
          <SectionTitle icon={Globe2} title="Website Environment" source="Phase 3.1" />
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6">
            <Row label="Registrar" value={provider.registrar} />
            <Row label="DNS Provider" value={provider.dns_provider} />
            <Row label="Hosting" value={provider.hosting_provider} />
            <Row label="CDN" value={provider.cdn_provider} />
            <Row label="WAF" value={provider.waf_provider} />
            <Row label="CMS" value={provider.cms} />
            <Row label="Framework" value={provider.framework} />
            <Row label="Confidence" value={`${provider.confidence}%`} />
          </div>
        </Card>
      )}

      {/* Trusted access */}
      {trusted && (
        <Card className="p-5">
          <SectionTitle icon={KeyRound} title="Trusted Scanner Access" source="Phase 3.4" />
          <Row label="Status" badge={trusted.status} />
          <Row label="Provider" value={trusted.provider} />
          <Row label="Access Method" value={humanize(trusted.access_method)} />
          <Row label="Last Validation" value={fmt(trusted.last_validated_at)} />
          {trusted.status !== 'active' && (
            <p className="text-xs text-gray-400 mt-2">{trusted.recommended_action}</p>
          )}
        </Card>
      )}

      {/* Access validation */}
      {validation && (
        <Card className="p-5">
          <SectionTitle icon={ScanLine} title="Access Validation" source="Phase 3.5" />
          <Row label="Status" badge={validation.status} />
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 my-3">
            {counts.map(([k, v]) => (
              <div key={k} className="rounded-lg bg-white/5 p-2.5 text-center">
                <div className="text-lg font-semibold text-white">{v}</div>
                <div className="text-[10px] text-gray-500 uppercase tracking-wider">{k}</div>
              </div>
            ))}
          </div>
          <Row label="Challenge Detected"
               value={validation.challenge_detected === null ? 'unknown'
                      : validation.challenge_detected ? `yes (${validation.challenge_provider || 'unknown'})` : 'no'} />
          <Row label="Last Validation" value={fmt(validation.validated_at)} />
        </Card>
      )}

      {/* Audit timeline */}
      {audit && audit.audit_trail_available && (
        <Card className="p-5">
          <SectionTitle icon={History} title="Recent Activity" source="Phase 3.8" />
          <div className="space-y-2">
            {[...audit.timeline].slice(-8).reverse().map((ev, i) => (
              <div key={i} className="flex items-center gap-2.5 text-xs">
                <span className="text-gray-300 flex-1">{humanize(ev.event_type)}</span>
                {ev.status && <Badge className={statusClass(ev.status)}>{ev.status}</Badge>}
                <span className="text-gray-600 font-mono">{fmt(ev.created_at)}</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
