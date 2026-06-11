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

describe('scanBlockedView — confidence-gated provider naming', () => {
  it('high confidence -> names the provider', () => {
    const v = scanBlockedView(diag({ confidence: 97 }))
    expect(v.blocked).toBe(true)
    expect(v.provider).toBe('Vercel')
    expect(v.title).toContain('Vercel')
    expect(v.ticketBlocker).toBe('vercel')
  })

  it('low confidence -> generic, does NOT name a provider', () => {
    const v = scanBlockedView(diag({ confidence: 40 }))
    expect(v.blocked).toBe(true)
    expect(v.provider).toBeNull()
    expect(v.title).not.toContain('Vercel')
    expect(v.title).toMatch(/blocked or limited/i)
    expect(v.ticketBlocker).toBe('vercel')   // still passed to the ticket for staff
  })

  it('unknown confidence (undefined) -> generic', () => {
    const v = scanBlockedView(diag({ confidence: null }))
    expect(v.provider).toBeNull()
  })

  it('not blocked -> nothing', () => {
    const v = scanBlockedView(diag({ cloudflare_scanner_access: 'active', blocker: 'cloudflare' }))
    expect(v.blocked).toBe(false)
  })

  it('null diagnosis -> not blocked', () => {
    expect(scanBlockedView(null).blocked).toBe(false)
  })
})
