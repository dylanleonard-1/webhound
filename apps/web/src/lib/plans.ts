// WebHound — apps/web/src/lib/plans.ts
// Plan-tier definitions mirrored from apps/api/billing/plans.py.
// Keep both files in sync when editing — the API enforces these limits
// server-side; the frontend renders the pricing page from this same data.
//
// Stripe products (monthly recurring):
//   WebHound Pro        — $29 / mo
//   WebHound Shield     — $79 / mo
//   WebHound Enterprise — $129 / mo

export type PlanTier = 'free' | 'pro' | 'shield' | 'enterprise'

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
  maxWebsites: number
  scansPerMonth: number
  scanHistoryDays: number
  maxConcurrentScans: number
  enginesAllowed: string[] | null
  monitoringEnabled: boolean
  monitoringMinFrequency: 'manual' | 'weekly' | 'daily'
  exportsEnabled: boolean
  alertsEnabled: boolean
  threatIntelExternal: boolean
  teamSeats: number
  apiAccess: boolean
  isPopular: boolean
  ctaLabel: string
  sortOrder: number
  features: PlanFeature[]
}

export const PLAN_DEFINITIONS: Record<PlanTier, PlanDefinition> = {
  free: {
    tier: 'free',
    name: 'Free',
    tagline: 'Try WebHound on one website. No card required.',
    priceUsdMonthly: 0,
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
    monitoringMinFrequency: 'manual',
    exportsEnabled: false,
    alertsEnabled: false,
    threatIntelExternal: false,
    teamSeats: 1,
    apiAccess: false,
    isPopular: false,
    ctaLabel: 'Start free',
    sortOrder: 10,
    features: [
      { label: '1 monitored website', included: true },
      { label: '5 scans per month', included: true },
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
  pro: {
    tier: 'pro',
    name: 'Pro',
    tagline: 'For solo founders and small sites.',
    priceUsdMonthly: 29,
    maxWebsites: 5,
    scansPerMonth: 50,
    scanHistoryDays: 30,
    maxConcurrentScans: 2,
    enginesAllowed: null,
    monitoringEnabled: true,
    monitoringMinFrequency: 'weekly',
    exportsEnabled: true,
    alertsEnabled: true,
    threatIntelExternal: false,
    teamSeats: 1,
    apiAccess: false,
    isPopular: false,
    ctaLabel: 'Upgrade to Pro',
    sortOrder: 20,
    features: [
      { label: '5 monitored websites', included: true },
      { label: '50 scans per month', included: true },
      { label: '30-day scan history', included: true },
      { label: 'All 12 security engines', included: true },
      { label: 'Weekly continuous monitoring', included: true },
      { label: 'PDF / CSV / SARIF / JSON exports', included: true },
      { label: 'Email alerts on new findings', included: true },
      { label: 'VirusTotal threat-intel enrichment', included: false },
      { label: 'Team seats', included: false },
      { label: 'API access', included: false },
    ],
  },
  shield: {
    tier: 'shield',
    name: 'Shield',
    tagline: 'For growing SaaS and busy agencies.',
    priceUsdMonthly: 79,
    maxWebsites: 25,
    scansPerMonth: 250,
    scanHistoryDays: 180,
    maxConcurrentScans: 5,
    enginesAllowed: null,
    monitoringEnabled: true,
    monitoringMinFrequency: 'daily',
    exportsEnabled: true,
    alertsEnabled: true,
    threatIntelExternal: true,
    teamSeats: 3,
    apiAccess: true,
    isPopular: true,
    ctaLabel: 'Upgrade to Shield',
    sortOrder: 30,
    features: [
      { label: '25 monitored websites', included: true },
      { label: '250 scans per month', included: true },
      { label: '6-month scan history', included: true },
      { label: 'All 12 security engines', included: true },
      { label: 'Daily continuous monitoring', included: true },
      { label: 'All report formats + scheduled exports', included: true },
      { label: 'Email + webhook alerts', included: true },
      { label: 'VirusTotal threat-intel enrichment', included: true },
      { label: '3 team seats', included: true },
      { label: 'Read-only API access', included: true },
    ],
  },
  enterprise: {
    tier: 'enterprise',
    name: 'Enterprise',
    tagline: 'For established teams with SOC 2 obligations.',
    priceUsdMonthly: 129,
    maxWebsites: 200,
    scansPerMonth: 2000,
    scanHistoryDays: 365,
    maxConcurrentScans: 15,
    enginesAllowed: null,
    monitoringEnabled: true,
    monitoringMinFrequency: 'daily',
    exportsEnabled: true,
    alertsEnabled: true,
    threatIntelExternal: true,
    teamSeats: 15,
    apiAccess: true,
    isPopular: false,
    ctaLabel: 'Upgrade to Enterprise',
    sortOrder: 40,
    features: [
      { label: '200 monitored websites', included: true },
      { label: '2,000 scans per month', included: true },
      { label: 'Full 1-year scan history', included: true },
      { label: 'All 12 security engines + custom rules', included: true },
      { label: 'Daily continuous monitoring', included: true },
      { label: 'All report formats + SOC 2 evidence packs', included: true },
      { label: 'Email + webhook + Slack alerts', included: true },
      { label: 'VirusTotal + URLhaus enrichment', included: true },
      { label: '15 team seats', included: true },
      { label: 'Full API access (read + write)', included: true },
      { label: 'Priority support', included: true },
    ],
  },
}

export function getPlan(tier: PlanTier): PlanDefinition {
  return PLAN_DEFINITIONS[tier]
}

export function planOrder(): PlanDefinition[] {
  return Object.values(PLAN_DEFINITIONS).sort((a, b) => a.sortOrder - b.sortOrder)
}
