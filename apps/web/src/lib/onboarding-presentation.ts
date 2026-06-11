// Customer-facing onboarding presentation logic (pure, testable). Maps the raw
// Phase-3 backend state into a friendly guided-setup view. NO backend calls,
// NO raw status leakage. The technical/raw data stays available in the panel's
// Advanced Details section — this module only shapes the *customer* view.

import type {
  AccessValidationView,
  OnboardingWizardView,
  ProviderProfileResponse,
} from '@/lib/api'

export type CtaAction =
  | 'verify'
  | 'manual_verify'
  | 'configure_access'
  | 'run_validation'
  | 'activate_monitoring'
  | 'none'

// Raw backend status -> customer-friendly language. Never show raw values.
const FRIENDLY: Record<string, string> = {
  not_configured: 'Not set up yet',
  not_ready: 'Setup incomplete',
  pending: 'Waiting',
  blocked: 'Not available yet',
  unknown: 'Detecting',
  // positive / in-flight states also get friendly copy
  active: 'Active',
  ready: 'Ready',
  verified: 'Verified',
  completed: 'Done',
  limited: 'Limited coverage',
  in_progress: 'In progress',
  validating: 'Checking',
  failed: 'Needs attention',
  revoked: 'Turned off',
  expired: 'Expired',
}

export function friendlyStatus(raw: string | null | undefined): string {
  if (!raw) return 'Detecting'
  return FRIENDLY[raw.toLowerCase()] ?? 'In progress'
}

// Per-step customer copy + the single action for that step.
const STEP_META: Record<string, { title: string; explanation: string; cta: { label: string; action: CtaAction } | null }> = {
  provider_discovery: {
    title: 'Detecting your environment',
    explanation: 'WebHound is identifying your hosting, DNS, and framework.',
    cta: null,
  },
  verification: {
    title: 'Connect WebHound to your website',
    explanation: 'Connect your website provider so WebHound can verify ownership and prepare monitoring safely.',
    cta: { label: 'Connect Website', action: 'verify' },
  },
  trusted_access: {
    title: 'Set Up Scanner Access',
    explanation: 'Next, WebHound will guide you through giving the scanner access to your website.',
    cta: { label: 'Set Up Scanner Access', action: 'configure_access' },
  },
  providers_connected: {
    title: 'Connect your providers',
    explanation: 'Connect each detected provider (Cloudflare, Vercel) so WebHound can monitor safely. Use the connect buttons below.',
    cta: null,
  },
  readiness: {
    title: 'Finalize Setup',
    explanation: 'Confirming everything is ready, then monitoring can be turned on.',
    cta: { label: 'Activate Monitoring', action: 'activate_monitoring' },
  },
  monitoring: {
    title: 'Activate Monitoring',
    explanation: 'Turn on continuous monitoring for your website.',
    cta: { label: 'Activate Monitoring', action: 'activate_monitoring' },
  },
}

const DONE_LABEL: Record<string, string> = {
  provider_discovery: 'Environment detected',
  verification: 'Ownership verified',
  trusted_access: 'Scanner access configured',
  providers_connected: 'Providers connected',
  readiness: 'Ready for monitoring',
  monitoring: 'Monitoring active',
}

const DONE_STATUSES = new Set(['completed', 'limited', 'active', 'ready', 'verified'])

export interface OnboardingView {
  title: string
  stepNumber: number
  totalSteps: number
  currentStepTitle: string
  currentStepExplanation: string
  cta: { label: string; action: CtaAction } | null
  completed: string[]
  isComplete: boolean
  /** Hosting / DNS / Framework only — no confidence, evidence, or attribution. */
  environment: { label: string; value: string }[]
  /** True only once validation has actually run (never show 0/0/0/0 as data). */
  showValidationMetrics: boolean
  validationPendingMessage: string | null
  /** Secondary action for the connect step (e.g. "Manual verification" fallback). */
  secondaryCta: { label: string; action: CtaAction } | null
  /** Honest coverage state — 'limited' surfaces the blocker even once monitoring is on. */
  coverage: CoverageDiagnosis
}

/** Hosting / DNS / Framework only. Confidence, evidence, attribution are hidden. */
export function environmentFields(
  p: ProviderProfileResponse | null,
): { label: string; value: string }[] {
  if (!p) return []
  const out: { label: string; value: string }[] = []
  if (p.hosting_provider) out.push({ label: 'Hosting', value: p.hosting_provider })
  if (p.dns_provider) out.push({ label: 'DNS', value: p.dns_provider })
  if (p.framework) out.push({ label: 'Framework', value: p.framework })
  return out
}

/** Validation metrics are meaningful only after validation has run. */
export function showValidationMetrics(v: AccessValidationView | null): boolean {
  return !!v && v.status !== 'pending'
}

// Per-provider connect rows for the onboarding card. EVERY detected supported
// provider gets a row (so a site with both Cloudflare + Vercel shows BOTH buttons),
// each with its own connection status. `connectable` = we have a connect flow for it.
export type DetectedProvidersInput = { detected: string[]; connected: string[] } | null | undefined
export interface ProviderConnectRow { provider: string; connected: boolean; connectable: boolean }

export function detectedProviderRows(providers: DetectedProvidersInput): ProviderConnectRow[] {
  const detected = providers?.detected ?? []
  const connected = new Set(providers?.connected ?? [])
  return detected.map((p) => ({
    provider: p,
    connected: connected.has(p),
    connectable: p === 'cloudflare' || p === 'vercel',
  }))
}

// Completion requires EVERY detected supported provider to be connected.
export function providersConnectComplete(providers: DetectedProvidersInput): boolean {
  const detected = providers?.detected ?? []
  if (detected.length === 0) return false
  const connected = new Set(providers?.connected ?? [])
  return detected.every((p) => connected.has(p))
}

// Honest coverage assessment. Validation status "limited" means the scanner saw the
// site only partially (e.g. blocked by a provider challenge after 1 page). We must
// NOT present that as a clean "Coverage validated" — surface the blocker + pages +
// next action. Reuses the scanner-block diagnosis (blocker/next_action) when a
// provider is attributable.
export type CoverageLevel = 'full' | 'limited' | 'none'

interface ScannerDiag {
  blocker?: string | null
  diagnosis?: string | null
  next_action?: string | null
  cloudflare_scanner_access?: string
}

export interface CoverageDiagnosis {
  level: CoverageLevel
  blocker: string | null
  pages: number
  nextAction: string | null
  message: string | null
}

export function coverageDiagnosis(
  validation: AccessValidationView | null,
  cfScanner?: ScannerDiag | null,
): CoverageDiagnosis {
  const status = validation?.status
  const pages = validation?.pages_found ?? 0
  // Attribute the blocker: the validation's own challenge_provider first, else the
  // scanner diagnosis blocker (when it's a non-Cloudflare layer like Vercel).
  const cfBlocker = cfScanner && cfScanner.blocker && cfScanner.blocker !== 'cloudflare'
    ? cfScanner.blocker : null
  const blocker = validation?.challenge_provider || cfBlocker || null

  if (status === 'ready') {
    return { level: 'full', blocker: null, pages, nextAction: null, message: null }
  }
  if (status === 'limited') {
    const who = blocker ? blocker.charAt(0).toUpperCase() + blocker.slice(1) : null
    const next = cfScanner?.next_action
      || (who ? `Set up ${who} scanner access` : 'Set up scanner access')
    const pageWord = pages === 1 ? '1 page' : `${pages} pages`
    const blockedBy = who ? `blocked by ${who}` : 'partially blocked'
    return {
      level: 'limited', blocker, pages, nextAction: next,
      message: `Limited coverage — the scanner is ${blockedBy} (${pageWord} seen). `
        + `${next} for full coverage.`,
    }
  }
  return { level: 'none', blocker: null, pages, nextAction: null, message: null }
}

// Map a /access-validation/run result to clear, actionable user feedback. Access
// validation CONSUMES the latest scan's metadata and runs no new scan, so when
// there's no completed scan it returns status="pending" (no_scan_evidence) — the
// button is not broken, the user just needs to run a scan first. Surfacing that
// (instead of a misleading "Setup updated") is the fix.
export type ValidationFeedbackVariant = 'success' | 'warning' | 'error' | 'info'

export function runValidationFeedback(
  v: { status: string; recommendation?: string | null } | null | undefined,
): { variant: ValidationFeedbackVariant; message: string } {
  switch (v?.status) {
    case 'ready':
      return { variant: 'success',
               message: 'Coverage validated — the WebHound scanner can see your site. Monitoring can proceed.' }
    case 'limited':
      return { variant: 'warning',
               message: v?.recommendation
                 || 'Coverage is limited — finish scanner access setup to improve it, then re-validate.' }
    case 'failed':
      return { variant: 'error',
               message: v?.recommendation
                 || 'The scanner cannot reliably see the site yet. Run a scan, then re-validate.' }
    // pending / validating / unknown -> no scan to validate yet.
    default:
      return { variant: 'info',
               message: 'No scan to validate yet — run a one-off scan below, then click Validate again.' }
  }
}

// Provider-FIRST connect direction. Prefer the access provider (Cloudflare —
// DNS/WAF/access) over hosting (Vercel). null = no supported provider, so
// manual verification becomes the primary path.
export function detectedConnectProvider(
  p: ProviderProfileResponse | null,
): 'cloudflare' | 'vercel' | null {
  if (!p) return null
  const fields = [p.cdn_provider, p.waf_provider, p.dns_provider, p.hosting_provider]
    .map((x) => (x || '').toLowerCase())
  if (fields.some((x) => x.includes('cloudflare'))) return 'cloudflare'
  if (fields.some((x) => x.includes('vercel'))) return 'vercel'
  return null
}

const CONNECT_LABEL: Record<'cloudflare' | 'vercel', string> = {
  cloudflare: 'Connect Cloudflare',
  vercel: 'Connect Vercel',
}

/** Provider-first primary CTA for the connect/verify step. DNS-TXT/meta/.well-known
 * are NOT the primary path — they live behind "Manual verification". */
export function connectCta(p: ProviderProfileResponse | null): { label: string; action: CtaAction } {
  const cp = detectedConnectProvider(p)
  if (cp) return { label: CONNECT_LABEL[cp], action: 'verify' }
  return { label: 'Verify manually', action: 'manual_verify' }
}

// What the connect/verify CTA ('verify' action) should actually DO. Cloudflare
// (Phase 4.2) has a real provider-OAuth flow, so its CTA starts OAuth and must
// NOT open manual DNS. Any other detected provider falls back to the existing
// manual ownership-verification flow (no parallel wiring — Vercel OAuth is out of
// this scope). `null` means no provider was detected → manual verification.
export type ConnectTarget = 'cloudflare_oauth' | 'manual'

export function connectTarget(p: ProviderProfileResponse | null): ConnectTarget {
  return detectedConnectProvider(p) === 'cloudflare' ? 'cloudflare_oauth' : 'manual'
}

export function buildOnboardingView(
  wizard: OnboardingWizardView | null,
  provider: ProviderProfileResponse | null,
  validation: AccessValidationView | null,
  cfScanner?: ScannerDiag | null,
): OnboardingView {
  const steps = wizard?.steps ?? []
  const totalSteps = steps.length || 6
  const currentStep = wizard?.current_step ?? 1
  const isComplete = wizard?.overall_status === 'completed' || wizard?.overall_status === 'limited'

  const coverage = coverageDiagnosis(validation, cfScanner)

  const completed: string[] = ['Website connected']
  for (const s of steps) {
    if (!DONE_STATUSES.has(s.status) || !DONE_LABEL[s.key]) continue
    // Don't claim clean "Coverage validated" / "Monitoring active" when coverage is
    // limited by a provider block — qualify the milestone so it's honest.
    if (coverage.level === 'limited' && s.key === 'monitoring') {
      completed.push('Monitoring active (limited coverage)')
    } else {
      completed.push(DONE_LABEL[s.key])
    }
  }

  const currentKey = steps.find((s) => s.step === currentStep)?.key ?? 'provider_discovery'
  const meta = STEP_META[currentKey] ?? STEP_META.provider_discovery

  // Provider-first action for the connect/verify step; DNS/manual verification is
  // the fallback (and the primary only when no supported provider is detected).
  let cta = isComplete ? null : meta.cta
  let secondaryCta: { label: string; action: CtaAction } | null = null
  if (!isComplete && currentKey === 'verification') {
    cta = connectCta(provider)
    if (cta.action !== 'manual_verify') {
      secondaryCta = { label: 'Manual verification', action: 'manual_verify' }
    }
  }

  return {
    title: isComplete ? 'WebHound Monitoring Active' : 'Finish Setting Up WebHound',
    stepNumber: Math.min(currentStep, totalSteps),
    totalSteps,
    currentStepTitle: isComplete ? 'Setup complete' : meta.title,
    currentStepExplanation: isComplete
      ? 'Your website is verified and monitoring is active.'
      : meta.explanation,
    cta,
    completed: [...new Set(completed)],
    isComplete,
    environment: environmentFields(provider),
    showValidationMetrics: showValidationMetrics(validation),
    validationPendingMessage: showValidationMetrics(validation)
      ? null
      : 'Validation will run automatically after ownership verification is complete.',
    secondaryCta,
    coverage,
  }
}

// Sections that must stay behind Advanced Details (technical / internal — never
// in the primary customer view).
export const ADVANCED_ONLY_SECTIONS = [
  'recent_activity', 'confidence', 'evidence', 'provider_attribution',
  'trusted_access_details', 'access_validation_raw', 'automation_state', 'audit',
] as const

export function isAdvancedOnly(section: string): boolean {
  return (ADVANCED_ONLY_SECTIONS as readonly string[]).includes(section)
}

/** Advanced Details opens by default for admins, stays collapsed for customers. */
export function advancedDefaultOpen(isAdmin: boolean | undefined): boolean {
  return isAdmin === true
}
