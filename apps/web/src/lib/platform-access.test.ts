import { describe, expect, it } from 'vitest'
import type { PlatformAccessView } from './api'
import { platformAccessVisibility, isWizardVisible } from './platform-access'

// Build a full PlatformAccessView with sane defaults; override per case.
function view(over: Partial<PlatformAccessView>): PlatformAccessView {
  return {
    state: 'not_required',
    provider: null,
    provider_name: null,
    automation_capable: false,
    allowlist_method: null,
    challenge_detected: false,
    access_required: false,
    confidence: null,
    scanner_ips: [],
    remediation: null,
    verification: null,
    trusted_status: null,
    can_automate: false,
    support_url: null,
    ...over,
  }
}

describe('platformAccessVisibility — the mounted PlatformAccessWizard gate', () => {
  it('access_required → EXPANDED (visible, shows remediation steps + CTAs)', () => {
    const v = view({ state: 'access_required', provider: 'cloudflare', access_required: true })
    expect(platformAccessVisibility(v)).toBe('expanded')
    expect(isWizardVisible(v)).toBe(true)
  })

  it('failed (verification failed) → EXPANDED (visible)', () => {
    const v = view({ state: 'failed', provider: 'vercel', verification: 'failed' })
    expect(platformAccessVisibility(v)).toBe('expanded')
    expect(isWizardVisible(v)).toBe(true)
  })

  it('support_required / configuring / verification_running → EXPANDED (in-progress, visible)', () => {
    for (const state of ['support_required', 'configuring', 'verification_running']) {
      expect(platformAccessVisibility(view({ state }))).toBe('expanded')
      expect(isWizardVisible(view({ state }))).toBe(true)
    }
  })

  it('verified → COLLAPSED (success confirmation only, no steps/CTAs)', () => {
    const v = view({ state: 'verified', provider: 'cloudflare', verification: 'success', trusted_status: 'active' })
    expect(platformAccessVisibility(v)).toBe('collapsed')
    expect(isWizardVisible(v)).toBe(true)
  })

  it('complete → COLLAPSED (configured confirmation only)', () => {
    const v = view({ state: 'complete', provider: 'cloudflare', trusted_status: 'active' })
    expect(platformAccessVisibility(v)).toBe('collapsed')
    expect(isWizardVisible(v)).toBe(true)
  })

  it('not_required → HIDDEN (no provider blocking — render nothing)', () => {
    const v = view({ state: 'not_required' })
    expect(platformAccessVisibility(v)).toBe('hidden')
    expect(isWizardVisible(v)).toBe(false)
  })

  it('detected (provider present but not blocking) → HIDDEN (access not required)', () => {
    const v = view({ state: 'detected', provider: 'fastly', access_required: false })
    expect(platformAccessVisibility(v)).toBe('hidden')
    expect(isWizardVisible(v)).toBe(false)
  })

  it('null / missing view (load failed) → HIDDEN', () => {
    expect(platformAccessVisibility(null)).toBe('hidden')
    expect(platformAccessVisibility(undefined)).toBe('hidden')
    expect(isWizardVisible(null)).toBe(false)
  })

  it('unknown / unexpected state → HIDDEN (fail safe, never leak a broken card)', () => {
    expect(platformAccessVisibility(view({ state: 'something_new' }))).toBe('hidden')
  })

  it('is purely state-driven — provider identity never changes visibility', () => {
    // Same state, different providers → identical visibility (no provider logic).
    for (const provider of ['cloudflare', 'vercel', 'akamai', 'imperva', null]) {
      expect(platformAccessVisibility(view({ state: 'access_required', provider }))).toBe('expanded')
    }
  })
})
