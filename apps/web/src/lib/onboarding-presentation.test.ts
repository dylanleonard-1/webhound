import { describe, expect, it } from 'vitest'

import type {
  AccessValidationView,
  OnboardingWizardView,
  ProviderProfileResponse,
} from './api'
import {
  advancedDefaultOpen,
  buildOnboardingView,
  environmentFields,
  friendlyStatus,
  isAdvancedOnly,
  showValidationMetrics,
} from './onboarding-presentation'

function wizard(currentStep: number, overrides: Partial<OnboardingWizardView> = {}): OnboardingWizardView {
  const steps = [
    { step: 1, key: 'provider_discovery', name: 'Provider Discovery', status: 'pending' },
    { step: 2, key: 'verification', name: 'Website Verification', status: 'pending' },
    { step: 3, key: 'trusted_access', name: 'Trusted Scanner Access', status: 'pending' },
    { step: 4, key: 'validation', name: 'Access Validation', status: 'pending' },
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
  it('verification step -> Verify Website', () => {
    const v = buildOnboardingView(wizard(2), provider, null)
    expect(v.cta?.action).toBe('verify')
    expect(v.cta?.label).toBe('Verify Website')
    expect(v.currentStepTitle).toBe('Verify Website Ownership')
  })
  it('CTA changes as onboarding progresses', () => {
    expect(buildOnboardingView(wizard(2), provider, null).cta?.action).toBe('verify')
    expect(buildOnboardingView(wizard(3), provider, null).cta?.action).toBe('configure_access')
    expect(buildOnboardingView(wizard(4), provider, null).cta?.action).toBe('run_validation')
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
