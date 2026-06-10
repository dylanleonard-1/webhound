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
    title: 'Verify Website Ownership',
    explanation: 'Verifying ownership ensures only authorized users can monitor this website.',
    cta: { label: 'Verify Website', action: 'verify' },
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

  return {
    title: isComplete ? 'WebHound Monitoring Active' : 'Finish Setting Up WebHound',
    stepNumber: Math.min(currentStep, totalSteps),
    totalSteps,
    currentStepTitle: isComplete ? 'Setup complete' : meta.title,
    currentStepExplanation: isComplete
      ? 'Your website is verified and monitoring is active.'
      : meta.explanation,
    cta: isComplete ? null : meta.cta,
    completed: [...new Set(completed)],
    isComplete,
    environment: environmentFields(provider),
    showValidationMetrics: showValidationMetrics(validation),
    validationPendingMessage: showValidationMetrics(validation)
      ? null
      : 'Validation will run automatically after ownership verification is complete.',
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
