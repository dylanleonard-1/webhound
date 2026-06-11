import { describe, expect, it } from 'vitest'
import type { CloudflareScannerAccessView } from './api'
import { scanBlockedView } from './scan-blocked'

function diag(over: Partial<CloudflareScannerAccessView>): CloudflareScannerAccessView {
  return {
    verified: true, cloudflare_connected: true,
    cloudflare_scanner_access: 'blocked_by_other_provider',
    blocker: 'vercel', diagnosis: 'both', confidence: 97, evidence: ['x'],
    next_action: 'Set up Vercel scanner access', message: '', rule: null, ...over,
  }
}

describe('scanBlockedView — only after a completed blocked/limited scan', () => {
  it('no scan yet (validation pending) -> NOT shown, even with a diagnosis', () => {
    expect(scanBlockedView(diag({ confidence: 97 }), 'pending').blocked).toBe(false)
    expect(scanBlockedView(diag({}), undefined).blocked).toBe(false)
    expect(scanBlockedView(diag({}), null).blocked).toBe(false)
  })

  it('clean scan (validation ready) -> NOT shown', () => {
    expect(scanBlockedView(diag({}), 'ready').blocked).toBe(false)
  })

  it('no-scan diagnosis with blocker "unknown" never shows (the early-popup bug)', () => {
    // Adding a site -> not connected -> diagnosis blocker 'unknown', no scan.
    const d = diag({ cloudflare_scanner_access: 'not_needed', blocker: 'unknown', confidence: null })
    expect(scanBlockedView(d, 'pending').blocked).toBe(false)
  })

  it('completed + limited + high confidence -> shown and NAMES the provider', () => {
    const v = scanBlockedView(diag({ confidence: 97, blocker: 'vercel' }), 'limited')
    expect(v.blocked).toBe(true)
    expect(v.provider).toBe('Vercel')
    expect(v.ticketBlocker).toBe('vercel')
  })

  it('completed + failed + low confidence -> shown but GENERIC (no provider named)', () => {
    const v = scanBlockedView(diag({ confidence: 40 }), 'failed')
    expect(v.blocked).toBe(true)
    expect(v.provider).toBeNull()
    expect(v.title).toMatch(/blocked or limited/i)
  })

  it('limited scan with no diagnosis -> generic popup', () => {
    const v = scanBlockedView(null, 'limited')
    expect(v.blocked).toBe(true)
    expect(v.provider).toBeNull()
  })
})
