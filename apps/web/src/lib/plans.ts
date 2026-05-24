// WebHound — apps/web/src/lib/plans.ts
// Plan-tier definitions mirrored from apps/api/billing/plans.py.
// Keep both files in sync when editing — the API enforces these limits
// server-side; the frontend renders the pricing page from this same data.

export type PlanTier = 'free' | 'starter' | 'pro' | 'enterprise'

export type SubscriptionStatus =
  | 'trialing' | 'active' | 'past_due' | 'unpaid'
  | 'canceled' | 'incomplete' | 'incomplete_expired' | 'paused'

export interface PlanFeature {
  label: string
  included: boolean
}

export interface PlanDefinition {
  tier: PlanTier
  name: string
  tagline: string
  priceUsdMonthly: number
  priceUsdYearly: number
  maxWebsites: number
  scansPerMonth: number
  scanHistoryDays: number
  maxConcurrentScans: number
  enginesAllowed: string[] | null
  monitoringEnabled: boolean
  exportsEnabled: boolean
  alertsEnabled: boolean
  threatIntelExternal: boolean
  teamSeats: number
  isPopular: boolean
  ctaLabel: string
  sortOrder: number
  features: PlanFeature[]
}

export const PLAN_DEFINITIONS: Record<PlanTier, PlanDefinition> = {
  free: {
    tier: 'free',
    name: 'Free',
    tagline: 'Try WebHound on a single site.',
    priceUsdMonthly: 0,
    priceUsdYearly: 0,
    maxWebsites: 1,
    scansPerMonth: 5,
    scanHistoryDays: 7,
    maxConcurrentScans: 1,
    enginesAllowed: [
      'security_headers', 'cors', 'cookies', 'csp',
      'secret_scanner', 'form_risk', 'input_analysis',
      'technology', 'sensitive_paths',
    ],
    monitoringEnabled: false,
    exportsEnabled: false,
    alertsEnabled: false,
    threatIntelExternal: false,
    teamSeats: 1,
    isPopular: false,
    ctaLabel: 'Start free',
    sortOrder: 10,
    features: [
      { label: '1 monitored website', included: true },
      { label: '5 scans / month', included: true },
      { label: '7-day scan history', included: true },
      { label: '9 of 12 security engines', included: true },
      { label: 'Plain-English findings', included: true },
      { label: 'Continuous monitoring', included: false },
      { label: 'PDF / CSV / SARIF exports', included: false },
      { label: 'Email + webhook alerts', included: false },
      { label: 'VirusTotal threat-intel enrichment', included: false },
      { label: 'API access', included: false },
    ],
  },
  starter: {
    tier: 'starter',
    name: 'Starter',
    tagline: 'For freelancers and small teams.',
    priceUsdMonthly: 19,
    priceUsdYearly: 190,
    maxWebsites: 5,
    scansPerMonth: 100,
    scanHistoryDays: 90,
    maxConcurrentScans: 2,
    enginesAllowed: null,
    monitoringEnabled: true,
    exportsEnabled: true,
    alertsEnabled: true,
    threatIntelExternal: false,
    teamSeats: 1,
    isPopular: false,
    ctaLabel: 'Upgrade to Starter',
    sortOrder: 20,
    features: [
      { label: '5 monitored websites', included: true },
      { label: '100 scans / month', included: true },
      { label: '90-day scan history', included: true },
      { label: 'All 12 security engines', included: true },
      { label: 'Continuous monitoring (weekly)', included: true },
      { label: 'PDF / CSV / SARIF exports', included: true },
      { label: 'Email alerts on new findings', included: true },
      { label: 'VirusTotal threat-intel enrichment', included: false },
      { label: 'Team seats', included: false },
      { label: 'API access', included: false },
    ],
  },
  pro: {
    tier: 'pro',
    name: 'Pro',
    tagline: 'For agencies and growing SaaS.',
    priceUsdMonthly: 49,
    priceUsdYearly: 490,
    maxWebsites: 25,
    scansPerMonth: 500,
    scanHistoryDays: 365,
    maxConcurrentScans: 5,
    enginesAllowed: null,
    monitoringEnabled: true,
    exportsEnabled: true,
    alertsEnabled: true,
    threatIntelExternal: true,
    teamSeats: 5,
    isPopular: true,
    ctaLabel: 'Upgrade to Pro',
    sortOrder: 30,
    features: [
      { label: '25 monitored websites', included: true },
      { label: '500 scans / month', included: true },
      { label: 'Full 1-year scan history', included: true },
      { label: 'All 12 security engines', included: true },
      { label: 'Continuous monitoring (daily)', included: true },
      { label: 'PDF / CSV / SARIF exports', included: true },
      { label: 'Email + webhook alerts', included: true },
      { label: 'VirusTotal threat-intel enrichment', included: true },
      { label: '5 team seats', included: true },
      { label: 'API access (read-only)', included: true },
    ],
  },
  enterprise: {
    tier: 'enterprise',
    name: 'Enterprise',
    tagline: 'Custom limits, SSO, and SOC 2 evidence support.',
    priceUsdMonthly: 0,
    priceUsdYearly: 0,
    maxWebsites: 10000,
    scansPerMonth: 100000,
    scanHistoryDays: 3650,
    maxConcurrentScans: 20,
    enginesAllowed: null,
    monitoringEnabled: true,
    exportsEnabled: true,
    alertsEnabled: true,
    threatIntelExternal: true,
    teamSeats: 999,
    isPopular: false,
    ctaLabel: 'Contact sales',
    sortOrder: 40,
    features: [
      { label: 'Unlimited websites', included: true },
      { label: 'Unlimited scans', included: true },
      { label: 'Custom scan-history retention', included: true },
      { label: 'All 12 security engines + custom rules', included: true },
      { label: 'SSO (SAML / OIDC)', included: true },
      { label: 'SOC 2 evidence collection', included: true },
      { label: 'Dedicated success manager', included: true },
      { label: '99.9% uptime SLA', included: true },
      { label: 'Custom integrations (Slack, Jira, PagerDuty)', included: true },
      { label: 'On-prem deployment available', included: true },
    ],
  },
}

export function getPlan(tier: PlanTier): PlanDefinition {
  return PLAN_DEFINITIONS[tier]
}

export function planOrder(): PlanDefinition[] {
  return Object.values(PLAN_DEFINITIONS).sort((a, b) => a.sortOrder - b.sortOrder)
}
