// Sentry server/edge initialization (Next.js instrumentation hook).
// No-op unless NEXT_PUBLIC_SENTRY_DSN is set and running in production —
// so local dev and unconfigured deploys never send events.
import * as Sentry from '@sentry/nextjs'

export async function register() {
  const dsn = process.env.NEXT_PUBLIC_SENTRY_DSN
  if (!dsn || process.env.NODE_ENV !== 'production') return
  if (process.env.NEXT_RUNTIME === 'nodejs' || process.env.NEXT_RUNTIME === 'edge') {
    Sentry.init({
      dsn,
      environment: process.env.NODE_ENV,
      tracesSampleRate: 0, // errors only by default
      sendDefaultPii: false,
    })
  }
}

// Captures errors thrown in nested React Server Components / route handlers.
export const onRequestError = Sentry.captureRequestError
