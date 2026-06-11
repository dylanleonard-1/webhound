import { describe, expect, it } from 'vitest'

import type {
  AccessValidationView,
  OnboardingWizardView,
  ProviderProfileResponse,
} from './api'
import {
  advancedDefaultOpen,
  buildOnboardingView,
  connectCta,
  connectTarget,
  coverageDiagnosis,
  detectedProviderRows,
  providersConnectComplete,
  shouldShowPrimaryCta,
  detectedConnectProvider,
  environmentFields,
  friendlyStatus,
  runValidationFeedback,
  isAdvancedOnly,
  showValidationMetrics,
} from './onboarding-presentation'

const vercelOnly: ProviderProfileResponse = {
  id: 'p', website_id: 'w', domain: 'x', registrar: null, dns_provider: null,
  hosting_provider: 'Vercel', cdn_provider: null, waf_provider: null, cms: null,
  framework: 'Next.js', confidence: 80, evidence: [], detected_at: '',
}
const noSupported: ProviderProfileResponse = {
  id: 'p', website_id: 'w', domain: 'x', registrar: null, dns_provider: 'GoDaddy',
  hosting_provider: 'Netlify', cdn_provider: null, waf_provider: null, cms: null,
  framework: null, confidence: 60, evidence: [], detected_at: '',
}

function wizard(currentStep: number, overrides: Partial<OnboardingWizardView> = {}): OnboardingWizardView {
  const steps = [
    { step: 1, key: 'provider_discovery', name: 'Provider Discovery', status: 'pending' },
    { step: 2, key: 'verification', name: 'Website Verification', status: 'pending' },
    { step: 3, key: 'trusted_access', name: 'Trusted Scanner Access', status: 'pending' },
    { step: 4, key: 'providers_connected', name: 'Connect Providers', status: 'pending' },
    { step: 5, key: 'readiness', name: 'Activation Readiness', status: 'pending' },
    { step: 6, key: 'monitoring', name: 'Monitoring Activation', status: 'inactive' },
  ]
  for (const s of steps) if (s.step < currentStep) s.status = 'completed'
  return {
    overall_status: 'in_progress', completion_percent: 0, current_step: currentStep,
    provider: 'Vercel', steps, ...overrides,
  }
}

const provider: ProviderProfileResponse = {
  id: 'p', website_id: 'w', domain: 'x', registrar: null, dns_provider: 'Cloudflare',
  hosting_provider: 'Vercel', cdn_provider: 'Cloudflare', waf_provider: 'Cloudflare',
  cms: null, framework: 'Next.js', confidence: 72, evidence: ['nameserver attribution'], detected_at: '',
}

const pendingValidation: AccessValidationView = {
  status: 'pending', pages_found: 0, scripts_found: 0, apis_found: 0, third_parties_found: 0,
  browser_rendered: false, challenge_detected: null, challenge_provider: null,
  validated_at: null, recommendation: '',
}

describe('raw backend statuses are hidden (friendly language)', () => {
  it('maps internal statuses to customer copy', () => {
    expect(friendlyStatus('not_configured')).toBe('Not set up yet')
    expect(friendlyStatus('not_ready')).toBe('Setup incomplete')
    expect(friendlyStatus('pending')).toBe('Waiting')
    expect(friendlyStatus('blocked')).toBe('Not available yet')
    expect(friendlyStatus('unknown')).toBe('Detecting')
  })
  it('never returns the raw value', () => {
    for (const raw of ['not_configured', 'not_ready', 'pending', 'blocked']) {
      expect(friendlyStatus(raw)).not.toBe(raw)
    }
  })
})

describe('environment shows only Hosting/DNS/Framework (no internals)', () => {
  it('hides confidence, evidence, attribution', () => {
    const f = environmentFields(provider)
    expect(f.map((x) => x.label)).toEqual(['Hosting', 'DNS', 'Framework'])
    const blob = JSON.stringify(f)
    expect(blob).not.toContain('72')
    expect(blob).not.toContain('evidence')
    expect(blob).not.toContain('nameserver')
    expect(blob).not.toContain('cdn')
    expect(blob).not.toContain('waf')
  })
})

describe('pending validation does not show misleading zero metrics', () => {
  it('hides metrics + shows the will-run-automatically message', () => {
    expect(showValidationMetrics(pendingValidation)).toBe(false)
    const v = buildOnboardingView(wizard(2), provider, pendingValidation)
    expect(v.showValidationMetrics).toBe(false)
    expect(v.validationPendingMessage).toContain('automatically')
  })
  it('shows metrics once validation has run', () => {
    expect(showValidationMetrics({ ...pendingValidation, status: 'ready', pages_found: 38 })).toBe(true)
  })
})

describe('correct CTA for verification-pending + progression', () => {
  it('verification step is provider-first (Connect, not Verify Website / DNS)', () => {
    const v = buildOnboardingView(wizard(2), provider, null)
    expect(v.currentStepTitle).toBe('Connect WebHound to your website')
    expect(v.cta?.label).toBe('Connect Cloudflare') // provider has Cloudflare DNS
    expect(v.cta?.label).not.toBe('Verify Website')
    expect(v.cta?.label).not.toContain('TXT')
    expect(v.cta?.action).toBe('verify')
    expect(v.secondaryCta?.label).toBe('Manual verification') // DNS is fallback, not primary
  })
  it('CTA changes as onboarding progresses', () => {
    expect(buildOnboardingView(wizard(2), provider, null).cta?.action).toBe('verify')
    expect(buildOnboardingView(wizard(3), provider, null).cta?.action).toBe('configure_access')
    // Step 4 is now "connect providers" — no single CTA (per-provider buttons handle it).
    expect(buildOnboardingView(wizard(4), provider, null).cta).toBeNull()
    expect(buildOnboardingView(wizard(6), provider, null).cta?.action).toBe('activate_monitoring')
  })
  it('complete -> no CTA, monitoring active', () => {
    const v = buildOnboardingView(wizard(6, { overall_status: 'completed' }), provider, null)
    expect(v.isComplete).toBe(true)
    expect(v.cta).toBeNull()
    expect(v.title).toContain('Active')
  })
})

describe('simplified customer card', () => {
  it('shows friendly title + step count + ✓ milestones, never raw statuses', () => {
    const v = buildOnboardingView(wizard(3), provider, null)
    expect(v.title).toBe('Finish Setting Up WebHound')
    expect(v.stepNumber).toBe(3)
    expect(v.totalSteps).toBe(6)
    expect(v.completed).toContain('Website connected')
    expect(v.completed).toContain('Environment detected')
    expect(v.completed).toContain('Ownership verified')
    const blob = JSON.stringify(v)
    expect(blob).not.toContain('not_configured')
    expect(blob).not.toContain('not_ready')
    expect(blob).not.toContain('pending')
  })
})

describe('advanced vs customer split + admin visibility', () => {
  it('recent activity + technical sections are advanced-only', () => {
    expect(isAdvancedOnly('recent_activity')).toBe(true)
    expect(isAdvancedOnly('confidence')).toBe(true)
    expect(isAdvancedOnly('trusted_access_details')).toBe(true)
    expect(isAdvancedOnly('access_validation_raw')).toBe(true)
  })
  it('admins get Advanced Details open by default; customers collapsed', () => {
    expect(advancedDefaultOpen(true)).toBe(true)
    expect(advancedDefaultOpen(false)).toBe(false)
    expect(advancedDefaultOpen(undefined)).toBe(false)
  })
})

describe('provider-first connect direction (DNS only as fallback)', () => {
  it('prefers the access provider (Cloudflare over Vercel)', () => {
    expect(detectedConnectProvider(provider)).toBe('cloudflare') // Cloudflare DNS + Vercel hosting
    expect(detectedConnectProvider(vercelOnly)).toBe('vercel')
    expect(detectedConnectProvider(noSupported)).toBeNull()
    expect(detectedConnectProvider(null)).toBeNull()
  })
  it('Cloudflare -> Connect Cloudflare; Vercel-only -> Connect Vercel; none -> Verify manually', () => {
    expect(connectCta(provider).label).toBe('Connect Cloudflare')
    expect(connectCta(vercelOnly).label).toBe('Connect Vercel')
    expect(connectCta(noSupported)).toEqual({ label: 'Verify manually', action: 'manual_verify' })
  })
  it('Vercel-only -> Connect Vercel primary + Manual verification secondary', () => {
    const v = buildOnboardingView(wizard(2), vercelOnly, null)
    expect(v.cta?.label).toBe('Connect Vercel')
    expect(v.secondaryCta?.label).toBe('Manual verification')
  })
  it('no supported provider -> manual verification is the primary action, no secondary', () => {
    const v = buildOnboardingView(wizard(2), noSupported, null)
    expect(v.cta?.action).toBe('manual_verify')
    expect(v.cta?.label).toBe('Verify manually')
    expect(v.secondaryCta).toBeNull()
  })
})

describe('Cloudflare connect CTA starts OAuth, NOT manual DNS (Phase 4.2)', () => {
  it('Cloudflare provider -> real OAuth target (never manual)', () => {
    // The "Connect Cloudflare" button must hand off to the Cloudflare OAuth flow,
    // not open the DNS/meta/.well-known manual verification card.
    expect(connectTarget(provider)).toBe('cloudflare_oauth')
    expect(connectTarget(provider)).not.toBe('manual')
  })
  it('non-Cloudflare providers stay on the manual fallback (Vercel OAuth out of scope)', () => {
    expect(connectTarget(vercelOnly)).toBe('manual')
    expect(connectTarget(noSupported)).toBe('manual')
    expect(connectTarget(null)).toBe('manual')
  })
  it('the CTA label is still customer-friendly + DNS stays a secondary fallback', () => {
    const v = buildOnboardingView(wizard(2), provider, null)
    expect(v.cta?.label).toBe('Connect Cloudflare')
    expect(v.cta?.action).toBe('verify')             // routed to OAuth by connectTarget
    expect(v.secondaryCta?.action).toBe('manual_verify') // manual DNS remains a fallback
  })
})

describe('runValidationFeedback — Run Validation gives actionable feedback (no silent no-op)', () => {
  it('pending (no scan yet) -> info telling the user to run a scan first', () => {
    const fb = runValidationFeedback({ status: 'pending', recommendation: 'Run a scan, then validate access.' })
    expect(fb.variant).toBe('info')
    expect(fb.message).toMatch(/run a one-off scan/i)
  })
  it('validating / unknown / null also map to the run-a-scan info message', () => {
    expect(runValidationFeedback({ status: 'validating' }).variant).toBe('info')
    expect(runValidationFeedback({ status: 'whatever' }).variant).toBe('info')
    expect(runValidationFeedback(null).variant).toBe('info')
  })
  it('ready -> success', () => {
    expect(runValidationFeedback({ status: 'ready' }).variant).toBe('success')
  })
  it('limited -> warning (uses backend recommendation when present)', () => {
    const fb = runValidationFeedback({ status: 'limited', recommendation: 'Visibility is restricted.' })
    expect(fb.variant).toBe('warning')
    expect(fb.message).toBe('Visibility is restricted.')
  })
  it('failed -> error', () => {
    expect(runValidationFeedback({ status: 'failed' }).variant).toBe('error')
  })
})

describe('coverageDiagnosis — honest limited coverage (no fake clean validated)', () => {
  const lim = (over = {}): AccessValidationView => ({
    status: 'limited', pages_found: 1, scripts_found: 0, apis_found: 0, third_parties_found: 0,
    browser_rendered: false, challenge_detected: null, challenge_provider: null,
    validated_at: 't', recommendation: '', ...over,
  })

  it('limited + validation.challenge_provider=vercel -> names Vercel + next action', () => {
    const c = coverageDiagnosis(lim({ challenge_provider: 'vercel' }))
    expect(c.level).toBe('limited')
    expect(c.blocker).toBe('vercel')
    expect(c.pages).toBe(1)
    expect(c.message).toMatch(/Vercel/)
    expect(c.message).toMatch(/1 page/)
    expect(c.nextAction).toMatch(/Vercel/)
  })

  it('limited + scanner diagnosis blocker=vercel (non-cloudflare) -> uses it + its next_action', () => {
    const c = coverageDiagnosis(lim(), { blocker: 'vercel', diagnosis: 'both',
      next_action: 'Set up Vercel scanner access', cloudflare_scanner_access: 'blocked_by_other_provider' })
    expect(c.level).toBe('limited')
    expect(c.blocker).toBe('vercel')
    expect(c.nextAction).toBe('Set up Vercel scanner access')
  })

  it('limited with no attributable blocker -> still limited (1 page), generic next', () => {
    const c = coverageDiagnosis(lim())
    expect(c.level).toBe('limited')
    expect(c.blocker).toBeNull()
    expect(c.message).toMatch(/1 page/)
    expect(c.nextAction).toBe('Set up scanner access')
  })

  it('ready -> full coverage, no banner', () => {
    const c = coverageDiagnosis(lim({ status: 'ready', pages_found: 42 }))
    expect(c.level).toBe('full')
    expect(c.message).toBeNull()
  })

  it('does NOT attribute cloudflare scanner status as a blocker', () => {
    const c = coverageDiagnosis(lim(), { blocker: 'cloudflare' })
    expect(c.blocker).toBeNull()   // cloudflare is OUR layer, not a separate wall
  })
})

describe('limited coverage is surfaced, not a clean green checkmark', () => {
  function lwizard(): OnboardingWizardView {
    const w = wizard(6, { overall_status: 'limited' })
    for (const s of w.steps) s.status = s.key === 'monitoring' ? 'active' : 'completed'
    return w
  }
  const limitedVal: AccessValidationView = {
    status: 'limited', pages_found: 1, scripts_found: 0, apis_found: 0, third_parties_found: 0,
    browser_rendered: false, challenge_detected: null, challenge_provider: 'vercel',
    validated_at: 't', recommendation: '',
  }

  it('milestones qualify monitoring when coverage is limited', () => {
    const v = buildOnboardingView(lwizard(), provider, limitedVal,
      { blocker: 'vercel', next_action: 'Set up Vercel scanner access' })
    expect(v.coverage.level).toBe('limited')
    expect(v.completed).toContain('Monitoring active (limited coverage)')
  })

  it('full coverage keeps the clean milestones', () => {
    const w = wizard(6, { overall_status: 'completed' })
    for (const s of w.steps) s.status = s.key === 'monitoring' ? 'active' : 'completed'
    const v = buildOnboardingView(w, provider, { ...limitedVal, status: 'ready', pages_found: 40 })
    expect(v.coverage.level).toBe('full')
    expect(v.completed).toContain('Providers connected')
    expect(v.completed).toContain('Monitoring active')
  })
})

describe('detectedProviderRows — BOTH detected providers get a connect row', () => {
  it('CF + Vercel detected, only CF connected -> two rows, completion needs both', () => {
    const providers = { detected: ['cloudflare', 'vercel'], connected: ['cloudflare'] }
    const rows = detectedProviderRows(providers)
    expect(rows).toHaveLength(2)                       // BOTH buttons render
    const cf = rows.find((r) => r.provider === 'cloudflare')!
    const vc = rows.find((r) => r.provider === 'vercel')!
    expect(cf.connected).toBe(true)                   // CF shows Connected
    expect(vc.connected).toBe(false)                  // Vercel shows Connect
    expect(vc.connectable).toBe(true)
    expect(providersConnectComplete(providers)).toBe(false)   // not done until both
  })

  it('both connected -> complete', () => {
    const providers = { detected: ['cloudflare', 'vercel'], connected: ['cloudflare', 'vercel'] }
    expect(detectedProviderRows(providers).every((r) => r.connected)).toBe(true)
    expect(providersConnectComplete(providers)).toBe(true)
  })

  it('CF-only site -> one row, complete on CF', () => {
    const providers = { detected: ['cloudflare'], connected: ['cloudflare'] }
    expect(detectedProviderRows(providers)).toHaveLength(1)
    expect(providersConnectComplete(providers)).toBe(true)
  })

  it('no detected providers -> no rows, not complete', () => {
    expect(detectedProviderRows({ detected: [], connected: [] })).toHaveLength(0)
    expect(providersConnectComplete(null)).toBe(false)
  })
})

describe('detectedProviderRows dedupes providers (BUG: 3 Cloudflare buttons)', () => {
  it('Cloudflare detected in dns+waf+cdn -> exactly ONE Cloudflare row', () => {
    // Backend should already dedupe, but be defensive against duplicates.
    const providers = { detected: ['cloudflare', 'cloudflare', 'cloudflare', 'vercel'], connected: ['cloudflare'] }
    const rows = detectedProviderRows(providers)
    expect(rows).toHaveLength(2)                       // exactly 2 rows, not 4
    expect(rows.filter((r) => r.provider === 'cloudflare')).toHaveLength(1)
    expect(rows.filter((r) => r.provider === 'vercel')).toHaveLength(1)
  })

  it('one-of-two connected -> NOT complete (card must stay)', () => {
    expect(providersConnectComplete({ detected: ['cloudflare', 'vercel'], connected: ['cloudflare'] })).toBe(false)
  })
})

describe('shouldShowPrimaryCta — never hides ALL connect actions', () => {
  const rows = (n: number) => Array.from({ length: n }, () => ({ connectable: true }))

  it('manual-verify CTA ALWAYS shows (no detected providers = manual-DNS site)', () => {
    // The webhohoundsecurity.com case: nothing detected -> manual verify must show.
    expect(shouldShowPrimaryCta('manual_verify', [])).toBe(true)
    expect(shouldShowPrimaryCta('manual_verify', rows(2))).toBe(true)
  })

  it('connect CTA is suppressed ONLY when per-provider rows exist (avoids duplicate)', () => {
    expect(shouldShowPrimaryCta('verify', rows(2))).toBe(false)        // dup -> suppress
    expect(shouldShowPrimaryCta('configure_access', rows(2))).toBe(false)
  })

  it('connect CTA STILL shows when there are no provider rows (never hide all connect)', () => {
    expect(shouldShowPrimaryCta('verify', [])).toBe(true)
    expect(shouldShowPrimaryCta('configure_access', [])).toBe(true)
  })

  it('non-connect CTAs (activate monitoring) always show', () => {
    expect(shouldShowPrimaryCta('activate_monitoring', rows(2))).toBe(true)
    expect(shouldShowPrimaryCta(null, rows(2))).toBe(false)   // no cta -> nothing
  })
})
