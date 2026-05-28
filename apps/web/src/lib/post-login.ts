// Shared post-login destination logic. Staff (is_admin) default to /control
// so they land in the SOC instead of the customer dashboard. An explicit
// ?next= (already validated to a same-origin path) always wins.

import { api } from '@/lib/api'

/**
 * Resolve where to send the user after a successful sign-in.
 *
 * @param nextPath  Result of safeNext(searchParams.get('next')). The fallback
 *                  is '/dashboard' — so we only override that when the user
 *                  is staff AND no real next was provided.
 */
export async function resolvePostLoginPath(nextPath: string): Promise<string> {
  if (nextPath && nextPath !== '/dashboard') return nextPath
  try {
    const me = await api.auth.me()
    if (me.is_admin) return '/control'
  } catch {
    // /auth/me failed — fall through to the customer dashboard so we don't
    // strand staff on an error page when they could still hit /control by URL.
  }
  return '/dashboard'
}
