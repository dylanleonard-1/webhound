// Pure helpers for the scan-blocked popup — confidence-gated provider naming so we
// only attribute the block to a specific provider when detection confidence is high.
import type { CloudflareScannerAccessView } from './api'

export const CONFIDENCE_NAME_THRESHOLD = 80

export interface ScanBlockedView {
  blocked: boolean
  /** Provider name to show, or null when confidence is too low to name one. */
  provider: string | null
  title: string
  body: string
  /** For the ticket payload. */
  ticketBlocker: string | null
}

export function scanBlockedView(d: CloudflareScannerAccessView | null): ScanBlockedView {
  const blocking = !!d && (
    d.cloudflare_scanner_access === 'blocked_by_other_provider'
    || (!!d.blocker && d.blocker !== 'cloudflare')
  )
  if (!d || !blocking) {
    return { blocked: false, provider: null, title: '', body: '', ticketBlocker: null }
  }
  const conf = typeof d.confidence === 'number' ? d.confidence : 0
  const highConfidence = conf >= CONFIDENCE_NAME_THRESHOLD && !!d.blocker
  if (highConfidence) {
    const who = d.blocker!.charAt(0).toUpperCase() + d.blocker!.slice(1)
    return {
      blocked: true,
      provider: who,
      title: `Your scan was blocked by ${who}`,
      body: `${who} served a security challenge to the WebHound scanner, so coverage is limited. `
        + `We can help you allowlist the scanner.`,
      ticketBlocker: d.blocker,
    }
  }
  // Low / unknown confidence — do NOT name a provider.
  return {
    blocked: true,
    provider: null,
    title: 'Your scan was blocked or limited',
    body: 'A security challenge limited the WebHound scanner’s coverage of your site. '
      + 'We can help you get the scanner allowlisted.',
    ticketBlocker: d.blocker ?? null,
  }
}
