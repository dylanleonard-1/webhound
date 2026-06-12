// Pure, provider-AGNOSTIC visibility logic for the PlatformAccessWizard.
//
// The wizard mounts unconditionally on the website detail page; this helper is
// the single source of truth for WHEN it shows and in what form. It switches on
// the server-provided `state` string ONLY — no provider-specific logic ever
// lives in the frontend (that all comes from provider_access_registry on the
// API side). Tested in platform-access.test.ts.
import type { PlatformAccessView } from './api'

export type WizardVisibility = 'hidden' | 'collapsed' | 'expanded'

// Actionable / in-progress states → the wizard is EXPANDED (remediation steps,
// IP copy, Verify / Connect / Support actions). "Appear when access is required
// OR verification failed."
const EXPANDED_STATES = new Set<string>([
  'access_required',
  'failed',
  'support_required',
  'configuring',
  'verification_running',
])

// Success / terminal states → COLLAPSED confirmation only (no steps, no CTAs).
// "If access is already verified … keep it collapsed."
const COLLAPSED_STATES = new Set<string>([
  'verified',
  'complete',
])

// Everything else (not_required, detected = provider present but not blocking,
// or any unknown state) → HIDDEN. "If access is … not required, keep it hidden."

export function platformAccessVisibility(
  view: PlatformAccessView | null | undefined,
): WizardVisibility {
  if (!view) return 'hidden'
  if (EXPANDED_STATES.has(view.state)) return 'expanded'
  if (COLLAPSED_STATES.has(view.state)) return 'collapsed'
  return 'hidden'
}

/** Convenience: is the wizard rendered at all (expanded OR collapsed)? */
export function isWizardVisible(
  view: PlatformAccessView | null | undefined,
): boolean {
  return platformAccessVisibility(view) !== 'hidden'
}
