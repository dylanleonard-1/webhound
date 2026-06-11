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

const _NOT_A_PROVIDER = new Set(['unknown', 'both', ''])

export function scanBlockedView(
  d: CloudflareScannerAccessView | null,
  validationStatus: string | null | undefined,
): ScanBlockedView {
  const none: ScanBlockedView = { blocked: false, provider: null, title: '', body: '', ticketBlocker: null }
  // STRICT gate: only after a COMPLETED scan whose result is blocked/limited.
  // 'pending' = no scan evidence yet (just added a site) -> never show.
  // 'ready'   = clean scan (full coverage)               -> never show.
  if (validationStatus !== 'limited' && validationStatus !== 'failed') return none
  if (!d) {
    // Scan is limited/failed but no provider diagnosis -> generic popup.
    return {
      blocked: true, provider: null, title: 'Your scan was blocked or limited',
      body: 'A security challenge limited the WebHound scanner’s coverage of your site. '
        + 'We can help you get the scanner allowlisted.',
      ticketBlocker: null,
    }
  }
  const conf = typeof d.confidence === 'number' ? d.confidence : 0
  // Only name a provider when it's an actual provider (not 'unknown'/'both'/'cloudflare')
  // AND confidence is high.
  const namedBlocker = d.blocker && !_NOT_A_PROVIDER.has(d.blocker) ? d.blocker : null
  const highConfidence = conf >= CONFIDENCE_NAME_THRESHOLD && !!namedBlocker
  if (highConfidence && namedBlocker) {
    const who = namedBlocker.charAt(0).toUpperCase() + namedBlocker.slice(1)
    return {
      blocked: true,
      provider: who,
      title: `Your scan was blocked by ${who}`,
      body: `${who} served a security challenge to the WebHound scanner, so coverage is limited. `
        + `We can help you allowlist the scanner.`,
      ticketBlocker: namedBlocker,
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
