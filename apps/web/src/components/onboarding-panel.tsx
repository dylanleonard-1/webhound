'use client'

import { useCallback, useEffect, useState } from 'react'
import {
  type LucideIcon,
  AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, Globe2, History,
  KeyRound, Loader2, ScanLine, ShieldCheck,
} from 'lucide-react'
import { toast } from 'sonner'
import {
  api,
  type AccessValidationView,
  type CloudflareScannerAccessView,
  type OnboardingAuditView,
  type OnboardingReadinessView,
  type OnboardingWizardView,
  type ProviderProfileResponse,
  type TrustedAccessView,
} from '@/lib/api'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  type CtaAction,
  advancedDefaultOpen,
  buildOnboardingView,
  connectTarget,
  detectedProviderRows,
  providersConnectComplete,
  runValidationFeedback,
  shouldShowPrimaryCta,
} from '@/lib/onboarding-presentation'

// Primary card = customer-friendly guided setup (no raw statuses, no internals).
// Advanced Details (collapsible) keeps the full technical view for advanced/admin
// users — nothing is removed, only moved behind the expander.

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
  cfScanner: CloudflareScannerAccessView | null
}

export function OnboardingPanel({ websiteId, isAdmin = false, onRevealVerification }: {
  websiteId: string
  isAdmin?: boolean
  onRevealVerification?: () => void
}) {
  const [data, setData] = useState<PanelData | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [advancedOpen, setAdvancedOpen] = useState(advancedDefaultOpen(isAdmin))

  const load = useCallback(async () => {
    const [provider, trusted, validation, readiness, wizard, audit, cfScanner] = await Promise.all([
      api.websites.providers(websiteId).catch(() => null),
      api.websites.trustedAccess(websiteId).catch(() => null),
      api.websites.accessValidation(websiteId).catch(() => null),
      api.websites.onboarding(websiteId).catch(() => null),
      api.websites.onboardingWizard(websiteId).catch(() => null),
      api.websites.audit(websiteId).catch(() => null),
      api.websites.cloudflareScannerAccessStatus(websiteId).catch(() => null),
    ])
    setData({ provider, trusted, validation, readiness, wizard, audit, cfScanner })
    setLoading(false)
  }, [websiteId])

  useEffect(() => { void load() }, [load])

  if (loading) {
    return (
      <Card className="p-5">
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading setup…
        </div>
      </Card>
    )
  }
  if (!data) return null

  const { provider, trusted, validation, readiness, wizard, audit, cfScanner } = data
  const view = buildOnboardingView(wizard, provider, validation, cfScanner)

  // Card hides ONLY when setup is truly done: the wizard is complete AND every
  // DETECTED provider is connected. A partial connect (1 of 2 providers) keeps the
  // card visible — never hide just because overall_status is 'limited'. Manual-DNS
  // sites (no detected supported provider) fall back to the wizard's completion.
  const detectedCount = (readiness?.providers?.detected ?? []).length
  const allProvidersConnected = detectedCount === 0
    ? true
    : providersConnectComplete(readiness?.providers)
  if (view.isComplete && allProvidersConnected) return null

  async function handleConnectProvider(name: 'cloudflare' | 'vercel') {
    setBusy(true)
    try {
      const { authorization_url } = name === 'cloudflare'
        ? await api.websites.cloudflareConnect(websiteId)
        : await api.websites.vercelConnect(websiteId)
      window.location.href = authorization_url   // -> provider consent
      return
    } catch (e) {
      toast.error((e as Error)?.message || `Could not start the ${name} connection.`)
      setBusy(false)
    }
  }

  const providerRows = detectedProviderRows(readiness?.providers)
  const percent = wizard?.completion_percent ?? 0
  const onValidationStep = view.cta?.action === 'run_validation'
  const verified = (readiness?.verification ?? '') === 'verified'

  function revealVerification() {
    if (onRevealVerification) onRevealVerification()
    else document.getElementById('verify-ownership')?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }

  async function handleCta(action: CtaAction) {
    // "verify" is the provider-connect action. For Cloudflare (Phase 4.2) it
    // starts the REAL provider-OAuth flow and must NOT open manual DNS: we ask the
    // API for the Cloudflare authorization URL and hand the browser off to it. Any
    // other provider (or "manual_verify") falls back to the manual DNS/meta/
    // .well-known ownership flow.
    if (action === 'verify' && connectTarget(provider) === 'cloudflare_oauth') {
      setBusy(true)
      try {
        const { authorization_url } = await api.websites.cloudflareConnect(websiteId)
        window.location.href = authorization_url   // -> Cloudflare consent screen
        return                                       // (navigating away; keep busy)
      } catch (e) {
        toast.error((e as Error)?.message || 'Could not start the Cloudflare connection.')
        setBusy(false)
      }
      return
    }
    if (action === 'verify' || action === 'manual_verify') {
      revealVerification()
      return
    }
    // "Set Up Scanner Access": ONE flow now — the single Connect Cloudflare consent
    // already requests firewall-write and sets up the scanner rule. So this CTA just
    // (re-)runs that single connect (e.g. to grant the elevated scopes if the site
    // was connected read-only before). Other providers fall back to manual guidance.
    if (action === 'configure_access' && connectTarget(provider) === 'cloudflare_oauth') {
      setBusy(true)
      try {
        const { authorization_url } = await api.websites.cloudflareConnect(websiteId)
        window.location.href = authorization_url   // -> single Cloudflare consent
        return                                       // (navigating away; keep busy)
      } catch (e) {
        toast.error((e as Error)?.message
          || 'Could not start the Cloudflare connection — set up access manually below.')
        try { await api.websites.trustedAccessStart(websiteId); await load() } catch { /* noop */ }
        setBusy(false)
      }
      return
    }
    setBusy(true)
    try {
      if (action === 'run_validation') {
        // Validation consumes the latest scan's metadata — when there's no scan it
        // returns status="pending". Surface clear, actionable feedback instead of a
        // misleading generic success.
        const view = await api.websites.accessValidationRun(websiteId)
        await load()
        const fb = runValidationFeedback(view)
        if (fb.variant === 'success') toast.success(fb.message)
        else if (fb.variant === 'error') toast.error(fb.message)
        else toast(fb.message)   // warning + info -> neutral (run-a-scan guidance)
        return
      }
      if (action === 'configure_access') await api.websites.trustedAccessStart(websiteId)
      else if (action === 'activate_monitoring') await api.websites.activateMonitoring(websiteId)
      await load()
      toast.success('Setup updated')
    } catch (e) {
      toast.error((e as Error)?.message || 'That step can’t be completed yet.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      {/* ── Primary guided-setup card ─────────────────────────────── */}
      <Card className="p-5" style={{ border: '1px solid rgba(124,255,0,0.18)' }}>
        <div className="flex items-center gap-2 mb-1">
          <ShieldCheck className="w-5 h-5 text-[#8BFF3E]" />
          <h2 className="text-base font-semibold text-white">{view.title}</h2>
          {!view.isComplete && (
            <span className="ml-auto text-xs text-gray-500">Step {view.stepNumber} of {view.totalSteps}</span>
          )}
        </div>

        <div className="h-1.5 rounded-full bg-white/5 overflow-hidden my-3">
          <div className="h-full rounded-full bg-[#8BFF3E] transition-all" style={{ width: `${percent}%` }} />
        </div>

        {view.completed.length > 0 && (
          <div className="flex flex-wrap gap-x-4 gap-y-1.5 mb-4">
            {view.completed.map((c) => (
              <span key={c} className="inline-flex items-center gap-1.5 text-xs text-gray-300">
                <CheckCircle2 className="w-3.5 h-3.5 text-[#8BFF3E]" /> {c}
              </span>
            ))}
          </div>
        )}

        {view.environment.length > 0 && (
          <div className="grid grid-cols-3 gap-3 mb-4">
            {view.environment.map((e) => (
              <div key={e.label} className="rounded-lg bg-white/5 p-2.5">
                <div className="text-[10px] text-gray-500 uppercase tracking-wider">{e.label}</div>
                <div className="text-sm text-white font-medium truncate">{e.value}</div>
              </div>
            ))}
          </div>
        )}

        {view.isComplete ? (
          view.coverage.level === 'limited' ? (
            // Honest: monitoring is on, but coverage is partial due to a provider block.
            <div className="rounded-[10px] p-4" style={{ background: 'rgba(249,115,22,0.06)', border: '1px solid rgba(249,115,22,0.3)' }}>
              <div className="flex items-start gap-2">
                <ShieldCheck className="w-4 h-4 mt-0.5 flex-shrink-0" style={{ color: '#f97316' }} />
                <div className="flex-1">
                  <p className="text-sm font-semibold text-white">Monitoring active — limited coverage</p>
                  <p className="text-xs text-gray-300 mt-1 leading-relaxed">{view.coverage.message}</p>
                  {view.coverage.nextAction && (
                    <p className="text-xs text-[#8BFF3E] mt-1.5">Next: {view.coverage.nextAction}</p>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-2 text-sm text-[#8BFF3E] font-medium">
              <CheckCircle2 className="w-4 h-4" /> Monitoring is active for this website.
            </div>
          )
        ) : (
          <div className="rounded-[10px] p-4" style={{ background: 'rgba(8,12,22,0.6)', border: '1px solid rgba(255,255,255,0.06)' }}>
            <div className="text-[11px] text-gray-500 uppercase tracking-wider mb-1">Current step</div>
            <div className="text-sm font-semibold text-white">{view.currentStepTitle}</div>
            <p className="text-xs text-gray-400 mt-1 leading-relaxed">{view.currentStepExplanation}</p>
            {onValidationStep && view.validationPendingMessage && (
              <p className="text-xs text-gray-500 mt-2">{view.validationPendingMessage}</p>
            )}
            <div className="mt-3 flex items-center gap-3 flex-wrap">
              {/* Show the primary CTA unless the per-provider block already renders a
                  duplicate connect button (shouldShowPrimaryCta). Manual-verify and
                  non-connect CTAs always show; never hides ALL connect actions. */}
              {view.cta && shouldShowPrimaryCta(view.cta.action, providerRows) && (
                <Button onClick={() => handleCta(view.cta!.action)} disabled={busy}>
                  {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : view.cta.label}
                </Button>
              )}
              {view.secondaryCta && (
                <button
                  type="button"
                  onClick={() => handleCta(view.secondaryCta!.action)}
                  className="text-xs text-gray-500 hover:text-gray-300 underline-offset-2 hover:underline"
                >
                  {view.secondaryCta.label}
                </button>
              )}
            </div>

            {/* Per-detected-provider connect buttons + status — ONE row per detected
                provider (a CF+Vercel site shows BOTH; completion needs both). */}
            {providerRows.length > 0 && (
              <div className="mt-4 space-y-2">
                <p className="text-[11px] text-gray-500 uppercase tracking-wider">Detected providers</p>
                {providerRows.map((row) => {
                  const label = row.provider.charAt(0).toUpperCase() + row.provider.slice(1)
                  return (
                    <div key={row.provider} className="flex items-center justify-between gap-3 rounded-lg bg-white/5 p-2.5">
                      <span className="text-[13px] text-white capitalize">{label}</span>
                      {row.connected ? (
                        <span className="inline-flex items-center gap-1.5 text-[12px] text-[#8BFF3E]">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Connected
                        </span>
                      ) : row.connectable ? (
                        <Button
                          onClick={() => handleConnectProvider(row.provider as 'cloudflare' | 'vercel')}
                          disabled={busy} className="h-8 px-3 text-[12px]">
                          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : `Connect ${label}`}
                        </Button>
                      ) : (
                        <span className="text-[11px] text-gray-500">Verify manually</span>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}
      </Card>

      {/* ── Advanced details (technical / internal — collapsed by default) ── */}
      <button
        type="button"
        onClick={() => setAdvancedOpen((o) => !o)}
        className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors"
      >
        {advancedOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
        Advanced details{isAdmin ? ' (admin)' : ''}
      </button>

      {advancedOpen && (
        <div className="space-y-4">
          {!verified && (
            <Card className="p-5">
              <SectionTitle icon={KeyRound} title="Manual Verification" source="Fallback" />
              <p className="text-xs text-gray-400 mb-3">
                Prefer to verify ownership yourself? Use a DNS TXT record, meta tag, or
                a .well-known file instead of connecting your provider.
              </p>
              <Button variant="ghost" onClick={revealVerification}>Open manual verification</Button>
            </Card>
          )}
          {validation && validation.status === 'limited' && validation.challenge_detected && (
            <Card className="p-5" style={{ borderColor: 'rgba(245,158,11,0.3)' }}>
              <SectionTitle icon={AlertTriangle} title="Coverage Limited" source="Phase 3.5" />
              <Row label="Challenge Provider" value={validation.challenge_provider} />
              <Row label="Impact" value="Reduced browser visibility" />
              <p className="text-xs text-gray-400 mt-2">{validation.recommendation}</p>
            </Card>
          )}

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
              {cfScanner?.cloudflare_connected && (
                <div className="mt-3 pt-3 border-t border-white/5">
                  <Row label="Cloudflare scanner access" value={humanize(cfScanner.cloudflare_scanner_access)} />
                  {cfScanner.blocker && cfScanner.cloudflare_scanner_access === 'blocked_by_other_provider' && (
                    <Row label="Current blocker" value={humanize(cfScanner.blocker)} />
                  )}
                  <p className="text-xs text-gray-400 mt-2">{cfScanner.message}</p>
                  {cfScanner.next_action && (
                    <p className="text-xs text-[#8BFF3E] mt-1">Next: {cfScanner.next_action}</p>
                  )}
                  {cfScanner.rule?.last_validated_at && (
                    <p className="text-[11px] text-gray-500 mt-1">
                      Rule validated {fmt(cfScanner.rule.last_validated_at)}
                    </p>
                  )}
                </div>
              )}
            </Card>
          )}

          {validation && (
            <Card className="p-5">
              <SectionTitle icon={ScanLine} title="Access Validation" source="Phase 3.5" />
              <Row label="Status" badge={validation.status} />
              {validation.status !== 'pending' ? (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 my-3">
                  {([['Pages', validation.pages_found], ['Scripts', validation.scripts_found],
                     ['APIs', validation.apis_found], ['3rd Parties', validation.third_parties_found]] as [string, number][]).map(([k, v]) => (
                    <div key={k} className="rounded-lg bg-white/5 p-2.5 text-center">
                      <div className="text-lg font-semibold text-white">{v}</div>
                      <div className="text-[10px] text-gray-500 uppercase tracking-wider">{k}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-gray-500 my-3">
                  Validation will run automatically after ownership verification is complete.
                </p>
              )}
              <Row label="Challenge Detected"
                   value={validation.challenge_detected === null ? 'unknown'
                          : validation.challenge_detected ? `yes (${validation.challenge_provider || 'unknown'})` : 'no'} />
              <Row label="Last Validation" value={fmt(validation.validated_at)} />
            </Card>
          )}

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
      )}
    </div>
  )
}
