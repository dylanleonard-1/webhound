// Central site configuration — update this file when changing domain or branding.
// All domain/email/URL references throughout the codebase should import from here.

export const SITE = {
  name: 'WebHound',
  tagline: 'AI-powered attack surface intelligence',
  description:
    'WebHound scans your entire attack surface — DNS, SSL, APIs, and cloud infrastructure — running security checks and returning a risk-scored report with actionable remediation.',
  domain: 'webhoundsecurity.com',
  url: 'https://webhoundsecurity.com',
  appUrl: 'https://app.webhoundsecurity.com',
  apiUrl: process.env.NEXT_PUBLIC_API_URL ?? 'https://api.webhoundsecurity.com',

  email: {
    auth: 'auth@webhoundsecurity.com',
    noreply: 'noreply@webhoundsecurity.com',
    support: 'support@webhoundsecurity.com',
    security: 'security@webhoundsecurity.com',
    privacy: 'privacy@webhoundsecurity.com',
    legal: 'legal@webhoundsecurity.com',
    hello: 'hello@webhoundsecurity.com',
  },

  social: {
    twitter: '@webhoundsecurity',
    github: 'https://github.com/webhoundsecurity',
  },

  // Scanner bot identity
  botUrl: 'https://webhoundsecurity.com/bot',
  userAgent: 'WebHound/1.0 (security-scanner; +https://webhoundsecurity.com/bot)',
} as const
