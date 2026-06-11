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
  validation: {
    title: 'Validate Coverage',
    explanation: 'WebHound checks that it can fully see your website before monitoring begins.',
    cta: { label: 'Run Validation', action: 'run_validation' },
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
  validation: 'Coverage validated',
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
): OnboardingView {
  const steps = wizard?.steps ?? []
  const totalSteps = steps.length || 6
  const currentStep = wizard?.current_step ?? 1
  const isComplete = wizard?.overall_status === 'completed' || wizard?.overall_status === 'limited'

  const completed: string[] = ['Website connected']
  for (const s of steps) {
    if (DONE_STATUSES.has(s.status) && DONE_LABEL[s.key]) completed.push(DONE_LABEL[s.key])
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
