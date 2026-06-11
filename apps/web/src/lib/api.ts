const BASE_URL =
  (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_API_URL) ||
  'https://api.webhoundsecurity.com'

const TOKEN_KEY = 'webhound_token'

export function getStoredToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(TOKEN_KEY)
}

export function setStoredToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearStoredToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UserResponse {
  id: string
  email: string
  is_active: boolean
  is_admin: boolean
  email_verified: boolean
  phone_number: string | null
  phone_verified: boolean
  full_name?: string | null
  company_name?: string | null
  use_case?: string | null
  terms_agreed_at: string | null
  created_at: string
}

export type UseCase =
  | 'developer'
  | 'security_engineer'
  | 'founder'
  | 'agency'
  | 'it_team'
  | 'other'

export interface RegisterPayload {
  email: string
  password: string
  full_name?: string | null
  company_name?: string | null
  use_case?: UseCase | null
}

export interface TokenResponse {
  access_token: string
  token_type: string
}

export interface LoginChallenge {
  challenge_token: string
  email: string                       // masked
  expires_in: number                  // seconds
  delivery?: 'delivered' | 'failed'   // whether email send succeeded
  dev_code?: string                   // present in dev mode or for admin users
  delivery_error?: string             // provider error message, admin-only
}

export interface WebsiteResponse {
  id: string
  url: string
  hostname: string
  scheme: string
  display_name: string | null
  verification_status: 'unverified' | 'pending' | 'verified' | 'failed'
  created_at: string
  updated_at: string
}

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
export type ScanProfile = 'quick' | 'standard' | 'deep' | 'monitor'

// Phase-3 onboarding / scanner-access views (presentation only; sourced from
// the Phase 3.1-3.8 read endpoints — no recalculation client-side).
export interface ProviderProfileResponse {
  id: string
  website_id: string
  domain: string
  registrar: string | null
  dns_provider: string | null
  hosting_provider: string | null
  cdn_provider: string | null
  waf_provider: string | null
  cms: string | null
  framework: string | null
  confidence: number
  evidence: string[]
  detected_at: string
}

// Phase-4.2 Cloudflare provider OAuth. The connect endpoint returns ONLY the
// authorization URL (no secrets). The status view is customer-safe (no account/
// zone ids, tokens, or permissions).
export interface CloudflareConnectResponse {
  authorization_url: string
}

export interface ProviderConnectionView {
  provider: string | null
  connection_status: string
  connected: boolean
  connected_at: string | null
  domain: string | null
}

export interface TrustedAccessView {
  provider: string | null
  status: string
  access_method: string
  recommended_action: string
  scanner_identity_url: string
  verification_url: string
  ip_ranges_url: string
  last_validated_at: string | null
}

export interface CloudflareScannerAccessView {
  verified: boolean
  cloudflare_connected: boolean
  // not_needed | pending_permissions | pending_rule_setup | active | blocked_by_other_provider | failed
  cloudflare_scanner_access: string
  blocker: string | null          // actionable provider: cloudflare | vercel | ...
  diagnosis: string | null        // cloudflare | vercel | both | unknown
  next_action: string | null
  message: string
  rule: {
    rule_type: string | null
    created_by_webhound: boolean | null
    created_at: string | null
    last_validated_at: string | null
    degraded: boolean
  } | null
}

export interface AccessValidationView {
  status: string
  pages_found: number
  scripts_found: number
  apis_found: number
  third_parties_found: number
  browser_rendered: boolean
  challenge_detected: boolean | null
  challenge_provider: string | null
  validated_at: string | null
  recommendation: string
}

export interface OnboardingReadinessView {
  status: string
  checks: Record<string, string>
  monitoring_allowed: boolean
  deep_scan_allowed: boolean
  baseline_allowed: boolean
  provider: string | null
  verification: string
  trusted_access: string
  validation: string
  provider_connected?: string
  providers?: { detected: string[]; connected: string[]; missing: string[] }
  evidence: string[]
  recommendation: string
  monitoring: string
  coverage_notice: boolean
}

export interface OnboardingWizardStep {
  step: number
  key: string
  name: string
  status: string
}

export interface OnboardingWizardView {
  overall_status: string
  completion_percent: number
  current_step: number
  provider: string | null
  steps: OnboardingWizardStep[]
  notice?: string
}

export interface OnboardingAuditEvent {
  event_type: string
  resource_type: string | null
  resource_id: string | null
  domain: string | null
  provider: string | null
  status: string | null
  reason: string | null
  compliance_tags: string[] | null
  created_at: string | null
}

export interface OnboardingAuditView {
  audit_trail_available: boolean
  event_count: number
  last_verification: string | null
  last_validation: string | null
  last_monitoring_change: string | null
  last_provider_change: string | null
  timeline: OnboardingAuditEvent[]
}

export interface ScanJobResponse {
  id: string
  website_id: string
  status: ScanStatus
  profile: ScanProfile
  requested_url: string
  use_latest_baseline: boolean
  save_baseline: boolean
  created_at: string
  updated_at: string
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  celery_task_id: string | null
}

export type NotificationSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type NotificationType =
  | 'scan_completed'
  | 'scan_failed'
  | 'high_risk_finding'
  | 'critical_finding'
  | 'wade_anomaly'
  | 'schedule_failed'

export interface NotificationResponse {
  id: string
  type: NotificationType
  severity: NotificationSeverity
  title: string
  message: string
  is_read: boolean
  website_id: string | null
  scan_job_id: string | null
  scan_result_id: string | null
  created_at: string
}

export interface ListResponse<T> {
  items: T[]
  total: number
  limit: number
  offset: number
  has_more: boolean
  next_offset: number | null
}

export interface ApiError extends Error {
  status: number
  data: unknown
}

// ---------------------------------------------------------------------------
// Scan Results types
// ---------------------------------------------------------------------------

export interface ScanResultSummary {
  id: string
  scan_job_id: string
  website_id: string
  requested_url: string
  hostname: string
  risk_score: number
  risk_level: string
  duration_seconds: number | null
  pages_crawled: number
  total_findings: number
  actionable_findings: number
  severity_breakdown: Record<string, number>
  created_at: string
}

export interface ScanJobSummary {
  id: string
  website_id: string
  profile: string
  requested_url: string
  status: string
  started_at: string | null
  completed_at: string | null
  created_at: string
}

export interface WebsiteSummaryInResult {
  id: string
  url: string
  hostname: string
  scheme: string
}

export interface ScanResultDetail {
  id: string
  scan_job_id: string
  scan_id: string | null
  risk_score: number
  risk_level: string
  duration_seconds: number | null
  pages_crawled: number
  total_findings: number
  actionable_findings: number
  severity_breakdown: Record<string, number>
  scanner_metadata: Record<string, unknown> | null
  created_at: string
  scan_job: ScanJobSummary
  website: WebsiteSummaryInResult
}

export interface FrameworkAlignmentPayload {
  owasp_top10?: string[]
  cwe_ids?: string[]
  nist_controls?: string[]
  sans_top25?: string[]
  pci_dss?: string[]
  iso_27001?: string[]
  soc2?: string[]
  hipaa?: string[]
  gdpr?: string[]
  cvss_vector?: string | null
  cvss_score?: number | null
  exploitability?: string | null
  [key: string]: unknown
}

export interface GroupedFindingResponse {
  id: string
  title: string
  severity: string
  category: string
  scanner_engine: string
  affected_url_count: number
  affected_urls: string[] | null
  evidence_count: number
  confidence: number | null
  description: string | null
  remediation: string | null
  framework: FrameworkAlignmentPayload | null
  finding_ids: string[] | null
  created_at: string
}

export interface EvidenceItem {
  location?: string
  content?: string
  type?: string
  [key: string]: unknown
}

export interface GroupedFindingDetailResponse extends GroupedFindingResponse {
  sample_evidence: EvidenceItem[]
}

export interface FindingResponse {
  id: string
  scanner_finding_id: string | null
  title: string
  severity: string
  category: string
  scanner_engine: string
  affected_url: string | null
  confidence: number | null
  description: string | null
  remediation: string | null
  evidence: unknown[] | null
  framework: FrameworkAlignmentPayload | null
  created_at: string
}

export interface EngineDiagnosticResponse {
  id: string
  engine_name: string
  category: string | null
  status: string
  findings_count: number
  severity_counts: Record<string, number> | null
  duration_ms: number | null
  skipped_reason: string | null
  error_message: string | null
  created_at: string
}

export type ReportFormat = 'json' | 'sarif' | 'csv' | 'markdown' | 'pdf'
export type ScheduleFrequency = 'daily' | 'weekly' | 'monthly'

export interface ScanScheduleResponse {
  id: string
  website_id: string
  profile: ScanProfile
  frequency: ScheduleFrequency
  is_enabled: boolean
  use_latest_baseline: boolean
  save_baseline: boolean
  next_run_at: string
  last_run_at: string | null
  created_at: string
  updated_at: string
}

export interface BaselineSummary {
  id: string
  website_id: string
  baseline_id: string
  baseline_version: number
  created_at: string
}

export interface WadeHistoryItem {
  scan_result_id: string
  scan_job_id: string
  created_at: string
  anomaly_count: number
  risk_score: number
  risk_level: string
  top_anomaly_titles: string[]
}

export interface WadeHistoryResponse {
  items: WadeHistoryItem[]
  total: number
  limit: number
  offset: number
}

export interface ReportResponse {
  id: string
  format: ReportFormat
  path: string | null
  content_json: Record<string, unknown> | null
  created_at: string
}

// ---------------------------------------------------------------------------
// HTTP core
// ---------------------------------------------------------------------------

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  token?: string,
  timeoutMs = 30_000,
): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const tok = token ?? getStoredToken()
  if (tok) headers['Authorization'] = `Bearer ${tok}`

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  let res: Response
  try {
    res = await fetch(`${BASE_URL}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    })
  } catch (err) {
    clearTimeout(timer)
    if ((err as Error).name === 'AbortError') {
      throw Object.assign(new Error('Request timed out. Please try again.'), {
        status: 408,
        data: {},
      }) as ApiError
    }
    throw Object.assign(new Error('Cannot reach the server. Check your connection.'), {
      status: 0,
      data: {},
    }) as ApiError
  }
  clearTimeout(timer)

  if (res.status === 401) {
    clearStoredToken()
    window.location.replace('/login')
    throw Object.assign(new Error('Unauthorized'), { status: 401, data: {} })
  }

  if (!res.ok) {
    let data: unknown = {}
    try { data = await res.json() } catch { /* empty */ }
    const message =
      (data as { error?: { message?: string } })?.error?.message ?? res.statusText
    throw Object.assign(new Error(message), { status: res.status, data }) as ApiError
  }

  if (res.status === 204) return undefined as T
  return res.json()
}

function qs(params?: Record<string, string | number | boolean | undefined | null>): string {
  if (!params) return ''
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null) p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

// ---------------------------------------------------------------------------
// API surface
// ---------------------------------------------------------------------------

export const api = {
  auth: {
    register: (payload: RegisterPayload) =>
      request<UserResponse & { access_token: string; token_type: string; dev_verify_url?: string }>(
        'POST', '/auth/register', payload
      ),

    login: (email: string, password: string) =>
      request<LoginChallenge>('POST', '/auth/login', { email, password }),

    verifyLoginCode: (challenge_token: string, code: string) =>
      request<TokenResponse>('POST', '/auth/login/verify', { challenge_token, code }),

    resendLoginCode: (challenge_token: string) =>
      request<{ message: string; dev_code?: string }>('POST', '/auth/login/resend-code', { challenge_token }),

    me: () => request<UserResponse>('GET', '/auth/me'),

    acceptTerms: () =>
      request<UserResponse>('POST', '/auth/accept-terms', { agreed: true }),

    updateMe: (patch: { full_name?: string | null; company_name?: string | null; use_case?: UseCase | null }) =>
      request<UserResponse>('PATCH', '/auth/me', patch),

    changePassword: (current_password: string, new_password: string) =>
      request<{ message: string }>('POST', '/auth/change-password', { current_password, new_password }),

    deleteAccount: (password: string) =>
      request<{ message: string }>('DELETE', '/auth/me', { password }),

    verifyEmail: (token: string) =>
      request<{ message: string }>('GET', `/auth/verify-email?token=${encodeURIComponent(token)}`),

    resendVerification: () =>
      request<{ message: string; dev_verify_url?: string }>('POST', '/auth/resend-verification'),

    forgotPassword: (email: string) =>
      request<{ message: string; dev_reset_url?: string }>('POST', '/auth/forgot-password', { email }),

    resetPassword: (token: string, new_password: string) =>
      request<{ message: string }>('POST', '/auth/reset-password', { token, new_password }),
  },

  phone: {
    add: (phone_number: string) =>
      request<{ message: string }>('POST', '/auth/phone/add', { phone_number }),

    verify: (otp: string) =>
      request<{ message: string }>('POST', '/auth/phone/verify', { otp }),

    resend: () =>
      request<{ message: string }>('POST', '/auth/phone/resend'),

    remove: () =>
      request<{ message: string }>('DELETE', '/auth/phone/remove'),
  },

  websites: {
    list: (params?: { limit?: number; offset?: number; verification_status?: string }) =>
      request<ListResponse<WebsiteResponse>>('GET', `/websites${qs(params)}`),

    create: (url: string, display_name?: string) =>
      request<WebsiteResponse>('POST', '/websites', { url, display_name }),

    get: (id: string) => request<WebsiteResponse>('GET', `/websites/${id}`),

    patch: (id: string, data: { display_name?: string | null; verification_status?: string }) =>
      request<WebsiteResponse>('PATCH', `/websites/${id}`, data),

    delete: (id: string) => request<void>('DELETE', `/websites/${id}`),

    verifyInitiate: (id: string, method: 'dns_txt' | 'meta_tag' | 'html_file') =>
      request<{ method: string; token: string; hostname: string; url: string; already_verified?: boolean }>(
        'POST', `/websites/${id}/verify/initiate?method=${method}`
      ),

    verifyCheck: (id: string) =>
      request<{ verified: boolean }>('POST', `/websites/${id}/verify/check`),

    verifyStatus: (id: string) =>
      request<{ verification_status: string; pending_method: string | null; pending_token: string | null }>(
        'GET', `/websites/${id}/verify`
      ),

    // Phase-3 onboarding read endpoints (presentation only — no client-side
    // recalculation; all data comes from the existing Phase 3.1-3.8 services).
    providers: (id: string) =>
      request<ProviderProfileResponse>('GET', `/websites/${id}/providers`),
    trustedAccess: (id: string) =>
      request<TrustedAccessView>('GET', `/websites/${id}/trusted-access`),
    accessValidation: (id: string) =>
      request<AccessValidationView>('GET', `/websites/${id}/access-validation`),
    onboarding: (id: string) =>
      request<OnboardingReadinessView>('GET', `/websites/${id}/onboarding`),
    onboardingWizard: (id: string) =>
      request<OnboardingWizardView>('GET', `/websites/${id}/onboarding/wizard`),
    audit: (id: string) =>
      request<OnboardingAuditView>('GET', `/websites/${id}/audit`),

    // Phase-3 onboarding actions (the simplified wizard CTAs). All reuse the
    // existing endpoints; the caller refetches the read views afterwards.
    trustedAccessStart: (id: string) =>
      request<Record<string, unknown>>('POST', `/websites/${id}/trusted-access/start`),
    accessValidationRun: (id: string) =>
      request<AccessValidationView>('POST', `/websites/${id}/access-validation/run`),
    activateMonitoring: (id: string) =>
      request<Record<string, unknown>>('POST', `/websites/${id}/onboarding/activate-monitoring`),

    // Phase-4.2 Cloudflare provider OAuth (real provider connection). `connect`
    // returns the Cloudflare authorization URL to redirect the browser to; the
    // callback is handled server-side and never exposes tokens to the frontend.
    cloudflareConnect: (id: string) =>
      request<CloudflareConnectResponse>('POST', `/websites/${id}/providers/cloudflare/connect`),
    // Vercel read-only connect (existing endpoint; NOT firewall automation).
    vercelConnect: (id: string) =>
      request<CloudflareConnectResponse>('POST', `/websites/${id}/providers/vercel/connect`),
    cloudflareStatus: (id: string) =>
      request<ProviderConnectionView>('GET', `/websites/${id}/providers/cloudflare`),
    // Phase-3.4 scanner access: elevated OAuth re-consent that creates the
    // Cloudflare firewall skip rule for the scanner UA. `start` returns the
    // authorization URL; the callback creates+verifies the rules server-side.
    cloudflareScannerAccessStatus: (id: string) =>
      request<CloudflareScannerAccessView>('GET', `/websites/${id}/providers/cloudflare/scanner-access`),
    cloudflareScannerAccessStart: (id: string) =>
      request<CloudflareConnectResponse>('POST', `/websites/${id}/providers/cloudflare/scanner-access/start`),
    cloudflareScannerAccessDisconnect: (id: string) =>
      request<Record<string, unknown>>('POST', `/websites/${id}/providers/cloudflare/scanner-access/disconnect`),
  },

  scanJobs: {
    list: (params?: { limit?: number; offset?: number; website_id?: string; status?: string }) =>
      request<ListResponse<ScanJobResponse>>('GET', `/scan-jobs${qs(params)}`),

    create: (
      website_id: string,
      profile: ScanProfile = 'standard',
      opts?: { use_latest_baseline?: boolean; save_baseline?: boolean },
    ) =>
      request<ScanJobResponse>('POST', '/scan-jobs', {
        website_id,
        profile,
        use_latest_baseline: opts?.use_latest_baseline ?? false,
        save_baseline: opts?.save_baseline ?? true,
      }),

    get: (id: string) => request<ScanJobResponse>('GET', `/scan-jobs/${id}`),
  },

  scanResults: {
    list: (params?: { limit?: number; offset?: number; website_id?: string; scan_job_id?: string; risk_level?: string }) =>
      request<ListResponse<ScanResultSummary>>('GET', `/scan-results${qs(params)}`),

    get: (id: string) => request<ScanResultDetail>('GET', `/scan-results/${id}`),

    groupedFindings: (
      id: string,
      params?: { limit?: number; offset?: number; severity?: string; category?: string; scanner_engine?: string },
    ) => request<ListResponse<GroupedFindingResponse>>('GET', `/scan-results/${id}/grouped-findings${qs(params)}`),

    groupedFindingDetail: (scanResultId: string, groupedFindingId: string) =>
      request<GroupedFindingDetailResponse>('GET', `/scan-results/${scanResultId}/grouped-findings/${groupedFindingId}`),

    findings: (
      id: string,
      params?: { limit?: number; offset?: number; severity?: string; category?: string; scanner_engine?: string },
    ) => request<ListResponse<FindingResponse>>('GET', `/scan-results/${id}/findings${qs(params)}`),

    engineDiagnostics: (id: string, params?: { status?: string; category?: string; engine_name?: string }) =>
      request<EngineDiagnosticResponse[]>('GET', `/scan-results/${id}/engine-diagnostics${qs(params)}`),

    reports: (id: string) => request<ReportResponse[]>('GET', `/scan-results/${id}/reports`),

    reportByFormat: (id: string, fmt: ReportFormat) =>
      request<ReportResponse>('GET', `/scan-results/${id}/reports/${fmt}`),
  },

  notifications: {
    list: (params?: {
      limit?: number
      offset?: number
      is_read?: boolean
      type?: NotificationType
      severity?: NotificationSeverity
      website_id?: string
    }) => request<ListResponse<NotificationResponse>>('GET', `/notifications${qs(params)}`),

    unreadCount: () => request<{ count: number }>('GET', '/notifications/unread-count'),

    markRead: (id: string) =>
      request<NotificationResponse>('PATCH', `/notifications/${id}/read`),

    markAllRead: () => request<{ count: number }>('PATCH', '/notifications/read-all'),

    delete: (id: string) => request<void>('DELETE', `/notifications/${id}`),
  },

  schedules: {
    list: (params?: { limit?: number; offset?: number; website_id?: string }) =>
      request<ListResponse<ScanScheduleResponse>>('GET', `/scan-schedules${qs(params)}`),

    get: (id: string) => request<ScanScheduleResponse>('GET', `/scan-schedules/${id}`),

    create: (data: {
      website_id: string
      profile: ScanProfile
      frequency: ScheduleFrequency
      is_enabled?: boolean
      use_latest_baseline?: boolean
      save_baseline?: boolean
      next_run_at: string
    }) => request<ScanScheduleResponse>('POST', '/scan-schedules', data),

    update: (id: string, data: {
      profile?: ScanProfile
      frequency?: ScheduleFrequency
      is_enabled?: boolean
      use_latest_baseline?: boolean
      save_baseline?: boolean
      next_run_at?: string
    }) => request<ScanScheduleResponse>('PATCH', `/scan-schedules/${id}`, data),

    delete: (id: string) => request<void>('DELETE', `/scan-schedules/${id}`),
  },

  baselines: {
    list: (websiteId: string, params?: { limit?: number; offset?: number }) =>
      request<ListResponse<BaselineSummary>>('GET', `/websites/${websiteId}/baselines${qs(params)}`),

    latest: (websiteId: string) =>
      request<BaselineSummary>('GET', `/websites/${websiteId}/baselines/latest`),

    delete: (id: string) => request<void>('DELETE', `/baselines/${id}`),
  },

  wade: {
    history: (websiteId: string, params?: { limit?: number; offset?: number }) =>
      request<WadeHistoryResponse>('GET', `/websites/${websiteId}/wade/history${qs(params)}`),
  },

  // Slice 4.A + 4.C — public/guest scan flow.
  // create() is unauthenticated; claim() is authenticated and
  // migrates a guest scan to the calling user's account.
  publicScan: {
    create: (url: string) =>
      request<{ scan_id: string; guest_token: string; status: string; target_url: string; profile: string; rate_limit_remaining: number }>(
        'POST', '/public/scan', { url },
      ),
    status: (guestToken: string) =>
      request<{ scan_id: string; guest_token: string; status: string; target_url: string; profile: string; started_at: string | null; completed_at: string | null; error_message: string | null; result: unknown }>(
        'GET', `/public/scan/${guestToken}`,
      ),
    claim: (guestToken: string) =>
      request<{ scan_id: string; guest_token: string; website_id: string; status: string; target_url: string }>(
        'POST', `/public/scan/${guestToken}/claim`,
      ),
  },

  billing: {
    plans: () => request<PlanResponse[]>('GET', '/billing/plans'),

    subscription: () =>
      request<CurrentSubscriptionResponse>('GET', '/billing/subscription'),

    // Reconcile plan state directly from Stripe (post-checkout). Doesn't
    // depend on the webhook having landed, so the dashboard updates even if
    // webhook delivery is delayed or not configured (e.g. test mode).
    sync: () =>
      request<CurrentSubscriptionResponse>('POST', '/billing/sync'),

    checkout: (data: {
      tier: 'pro' | 'shield' | 'enterprise'
      success_path?: string
      cancel_path?: string
    }) =>
      request<{ id: string; url: string }>(
        'POST', '/billing/checkout-session', data,
      ),

    portal: (data?: { return_path?: string }) =>
      request<{ id: string; url: string }>(
        'POST', '/billing/portal-session', data ?? {},
      ),
  },

  // Internal /control command center (RBAC-gated; 403 for non-staff).
  internal: {
    me: () => request<InternalMe>('GET', '/internal/me'),
    commandCenter: () => request<CommandCenter>('GET', '/internal/command-center'),
    scans: (params: { status?: string; profile?: string; q?: string; limit?: number; offset?: number } = {}) => {
      const qs = new URLSearchParams()
      if (params.status) qs.set('status', params.status)
      if (params.profile) qs.set('profile', params.profile)
      if (params.q) qs.set('q', params.q)
      qs.set('limit', String(params.limit ?? 50))
      qs.set('offset', String(params.offset ?? 0))
      return request<ScanListResponse>('GET', `/internal/scans?${qs.toString()}`)
    },
    scanDetail: (id: string) => request<ScanDetail>('GET', `/internal/scans/${id}`),
    cancelScan: (id: string) => request<{ ok: boolean; id: string; status: string }>('POST', `/internal/scans/${id}/cancel`),
    rescan: (id: string) => request<{ ok: boolean; new_scan_id: string; origin: string }>('POST', `/internal/scans/${id}/rescan`),
    engines: () => request<{ engines: EngineHealthRow[] }>('GET', '/internal/engines'),
    alerts: (params: { status?: string; severity?: string; source?: string; limit?: number; offset?: number } = {}) => {
      const qs = new URLSearchParams()
      if (params.status) qs.set('status', params.status)
      if (params.severity) qs.set('severity', params.severity)
      if (params.source) qs.set('source', params.source)
      qs.set('limit', String(params.limit ?? 50))
      qs.set('offset', String(params.offset ?? 0))
      return request<AlertListResponse>('GET', `/internal/alerts?${qs.toString()}`)
    },
    alertsSummary: () => request<AlertSummary>('GET', '/internal/alerts/summary'),
    alertDetail: (id: string) => request<AlertDetail>('GET', `/internal/alerts/${id}`),
    ackAlert: (id: string) => request<{ ok: boolean; status: string }>('POST', `/internal/alerts/${id}/ack`),
    resolveAlert: (id: string) => request<{ ok: boolean; status: string }>('POST', `/internal/alerts/${id}/resolve`),
    assignAlert: (id: string, assignee_id: string | null) =>
      request<{ ok: boolean; assignee: string | null }>('POST', `/internal/alerts/${id}/assign`, { assignee_id }),
    commentAlert: (id: string, body: string) =>
      request<{ ok: boolean }>('POST', `/internal/alerts/${id}/comment`, { body }),
    customers: (params: { q?: string; plan?: string; status?: string; limit?: number; offset?: number } = {}) => {
      const qs = new URLSearchParams()
      if (params.q) qs.set('q', params.q)
      if (params.plan) qs.set('plan', params.plan)
      if (params.status) qs.set('status', params.status)
      qs.set('limit', String(params.limit ?? 50))
      qs.set('offset', String(params.offset ?? 0))
      return request<CustomerListResponse>('GET', `/internal/customers?${qs.toString()}`)
    },
    customerDetail: (id: string) => request<CustomerDetail>('GET', `/internal/customers/${id}`),
    suspendCustomer: (id: string, reason: string | null) =>
      request<{ ok: boolean; status: string }>('POST', `/internal/customers/${id}/suspend`, { reason }),
    reactivateCustomer: (id: string) =>
      request<{ ok: boolean; status: string }>('POST', `/internal/customers/${id}/reactivate`),
    forceLogoutCustomer: (id: string) =>
      request<{ ok: boolean }>('POST', `/internal/customers/${id}/force-logout`),
    changeCustomerPlan: (id: string, plan: 'free' | 'pro' | 'shield' | 'enterprise') =>
      request<{ ok: boolean; plan: string }>('POST', `/internal/customers/${id}/plan`, { plan }),
    customerNotes: (id: string) =>
      request<{ items: CustomerNote[] }>('GET', `/internal/customers/${id}/notes`),
    addCustomerNote: (id: string, body: string) =>
      request<{ ok: boolean; id: string }>('POST', `/internal/customers/${id}/notes`, { body }),
    deleteNote: (note_id: string) => request<{ ok: boolean }>('DELETE', `/internal/notes/${note_id}`),
    billingMetrics: () => request<BillingMetrics>('GET', '/internal/billing/metrics'),
    billingSubscriptions: (status?: string) => {
      const qs = new URLSearchParams()
      if (status) qs.set('status', status)
      qs.set('limit', '100')
      return request<{ items: SubscriptionRow[] }>('GET', `/internal/billing/subscriptions?${qs.toString()}`)
    },
    billingEvents: (limit = 50) =>
      request<{ items: StripeEventRow[]; error?: string }>('GET', `/internal/billing/events?limit=${limit}`),
    abuseFlags: (params: { status?: string; severity?: string; limit?: number; offset?: number } = {}) => {
      const qs = new URLSearchParams()
      if (params.status) qs.set('status', params.status)
      if (params.severity) qs.set('severity', params.severity)
      qs.set('limit', String(params.limit ?? 50))
      qs.set('offset', String(params.offset ?? 0))
      return request<AbuseFlagListResponse>('GET', `/internal/abuse/flags?${qs.toString()}`)
    },
    abuseSummary: () => request<AbuseSummary>('GET', '/internal/abuse/summary'),
    abuseFlagDetail: (id: string) => request<AbuseFlagDetail>('GET', `/internal/abuse/flags/${id}`),
    dismissAbuseFlag: (id: string, note: string | null) =>
      request<{ ok: boolean; status: string }>('POST', `/internal/abuse/flags/${id}/dismiss`, { note }),
    banFromAbuseFlag: (id: string, reason: string | null) =>
      request<{ ok: boolean; status: string }>('POST', `/internal/abuse/flags/${id}/ban`, { reason }),
    evaluateAbuse: (user_id: string) =>
      request<AbuseEvaluation>('POST', `/internal/abuse/evaluate/${user_id}`),
    customerFingerprints: (user_id: string) =>
      request<{ items: IPFingerprint[] }>('GET', `/internal/customers/${user_id}/fingerprints`),
    tickets: (params: { status?: string; priority?: string; user_id?: string; breached_only?: boolean; limit?: number; offset?: number } = {}) => {
      const qs = new URLSearchParams()
      if (params.status) qs.set('status', params.status)
      if (params.priority) qs.set('priority', params.priority)
      if (params.user_id) qs.set('user_id', params.user_id)
      if (params.breached_only) qs.set('breached_only', 'true')
      qs.set('limit', String(params.limit ?? 50))
      qs.set('offset', String(params.offset ?? 0))
      return request<TicketListResponse>('GET', `/internal/tickets?${qs.toString()}`)
    },
    ticketsSummary: () => request<TicketSummary>('GET', '/internal/tickets/summary'),
    ticketDetail: (id: string) => request<TicketDetail>('GET', `/internal/tickets/${id}`),
    createTicket: (body: TicketCreateBody) =>
      request<{ ok: boolean; id: string; number: number }>('POST', '/internal/tickets', body),
    setTicketStatus: (id: string, status: string) =>
      request<{ ok: boolean; status: string }>('POST', `/internal/tickets/${id}/status`, { status }),
    setTicketPriority: (id: string, priority: string) =>
      request<{ ok: boolean; priority: string }>('POST', `/internal/tickets/${id}/priority`, { priority }),
    assignTicket: (id: string, assignee_id: string | null) =>
      request<{ ok: boolean; assignee: string | null }>('POST', `/internal/tickets/${id}/assign`, { assignee_id }),
    commentTicket: (id: string, body: string, visibility: 'public' | 'internal' = 'public') =>
      request<{ ok: boolean }>('POST', `/internal/tickets/${id}/comment`, { body, visibility }),
    ticketVerifyRescan: (id: string, profile = 'standard') =>
      request<{ ok: boolean; verification_scan_id: string }>('POST', `/internal/tickets/${id}/verify-rescan`, { profile }),
    team: () => request<TeamResponse>('GET', '/internal/team'),
    teamSessions: (hours = 72) =>
      request<TeamSessionsResponse>('GET', `/internal/team/sessions?hours=${hours}`),
    setUserRole: (user_id: string, role: string) =>
      request<{ ok: boolean; admin_role: string }>('POST', `/internal/team/${user_id}/role`, { role }),
    deploys: (service?: string) => {
      const qs = new URLSearchParams()
      if (service) qs.set('service', service)
      qs.set('limit', '100')
      return request<DeploysResponse>('GET', `/internal/deploys?${qs.toString()}`)
    },
    currentDeploy: () => request<{ sha: string | null }>('GET', '/internal/deploys/current'),
    recordDeploy: (body: { service: string; sha: string; status?: string; note?: string | null }) =>
      request<{ ok: boolean; id: string }>('POST', '/internal/deploys', body),
    infraHistory: (hours = 24) =>
      request<{ items: InfraSample[] }>('GET', `/internal/infra/history?hours=${hours}`),
    maintenanceStatus: () => request<MaintenanceState>('GET', '/internal/maintenance'),
    setMaintenance: (active: boolean, reason: string | null) =>
      request<{ ok: boolean; active: boolean }>('POST', '/internal/maintenance', { active, reason }),
    searchLogs: (params: LogSearchParams = {}) =>
      request<LogSearchResponse>('GET', `/internal/logs?${_qs(params)}`),
    searchAudit: (params: AuditSearchParams = {}) =>
      request<AuditSearchResponse>('GET', `/internal/audit?${_qs(params)}`),
    logsCsvUrl: (params: LogSearchParams = {}) => `/internal/logs.csv?${_qs(params)}`,
    auditCsvUrl: (params: AuditSearchParams = {}) => `/internal/audit.csv?${_qs(params)}`,
    threatIndicators: (params: { kind?: string; source?: string; severity?: string; q?: string; include_expired?: boolean; limit?: number; offset?: number } = {}) =>
      request<ThreatListResponse>('GET', `/internal/threat-intel/indicators?${_qs(params)}`),
    threatMatch: (kind: string, value: string) =>
      request<{ hits: ThreatIndicatorRow[]; count: number }>('GET', `/internal/threat-intel/indicators/match?${_qs({ kind, value })}`),
    addThreatIndicator: (body: ThreatAddBody) =>
      request<{ ok: boolean; id: string; created: boolean }>('POST', '/internal/threat-intel/indicators', body),
    deleteThreatIndicator: (id: string) =>
      request<{ ok: boolean }>('DELETE', `/internal/threat-intel/indicators/${id}`),
    importThreatFeed: (body: ThreatImportBody) =>
      request<{ ok: boolean; created: number; updated: number; skipped: number }>('POST', '/internal/threat-intel/import', body),
    incidents: (params: { status?: string; severity?: string; source?: string; breached_only?: boolean; limit?: number; offset?: number } = {}) =>
      request<IncidentListResponse>('GET', `/internal/incidents?${_qs(params)}`),
    incidentsSummary: () => request<IncidentSummary>('GET', '/internal/incidents/summary'),
    incidentDetail: (id: string) => request<IncidentDetail>('GET', `/internal/incidents/${id}`),
    setIncidentStatus: (id: string, status: string) =>
      request<{ ok: boolean; status: string }>('POST', `/internal/incidents/${id}/status`, { status }),
    assignIncident: (id: string, assignee_id: string | null) =>
      request<{ ok: boolean; assignee: string | null }>('POST', `/internal/incidents/${id}/assign`, { assignee_id }),
    incidentNote: (id: string, body: string) =>
      request<{ ok: boolean }>('POST', `/internal/incidents/${id}/note`, { body }),
    engineMaintenance: (name: string, on: boolean, notes: string | null = null) =>
      request<{ ok: boolean; maintenance_mode: boolean }>('POST', `/internal/engines/${encodeURIComponent(name)}/maintenance`, { on, notes }),
    engineThreshold: (name: string, failure_pct: number | null) =>
      request<{ ok: boolean; auto_disable_at_failure_pct: number | null }>('POST', `/internal/engines/${encodeURIComponent(name)}/threshold`, { failure_pct }),
    engineDiagnostics: (name: string, hours = 168, limit = 100) =>
      request<EngineDiagnosticsResponse>('GET', `/internal/engines/${encodeURIComponent(name)}/diagnostics?hours=${hours}&limit=${limit}`),
  },

  // Phase-16 Agency/MSP portfolio command center.
  portfolio: {
    summary: () => request<PortfolioSummary>('GET', '/portfolio/summary'),
    sites: () => request<PortfolioSitesResponse>('GET', '/portfolio/sites'),
    alerts: () => request<PortfolioAlertsResponse>('GET', '/portfolio/alerts'),
    wade: () => request<PortfolioWadeSummary>('GET', '/portfolio/wade'),
    report: () => request<{ report: Record<string, unknown> }>('GET', '/portfolio/report'),
    listGroups: () => request<{ groups: PortfolioGroup[] }>('GET', '/portfolio/client-groups'),
    createGroup: (data: { name: string; group_type?: string; parent_group_id?: string | null }) =>
      request<PortfolioGroup>('POST', '/portfolio/client-groups', data),
    assignGroup: (siteId: string, group_id: string | null) =>
      request<void>('PATCH', `/portfolio/sites/${siteId}/group`, { group_id }),
  },
}

// ---------------------------------------------------------------------------
// Phase-16 portfolio types
// ---------------------------------------------------------------------------

export interface PortfolioSummary {
  summary: {
    sites_monitored: number
    portfolio_risk_score: number
    portfolio_health_score: number
    portfolio_monitoring_score: number
    portfolio_stability_score: number
    cross_site_alert_count: number
    sites_with_compromise: number
    [k: string]: unknown
  }
  dashboard: {
    risk_distribution: Record<string, number>
    health_distribution: Record<string, number>
    alert_distribution: Record<string, number>
    most_vulnerable_sites: Array<{ site_id: string; url: string; risk_level: string; health_score: number }>
    most_changed_sites: Array<{ site_id: string; url: string; change_frequency: number }>
    most_stable_sites: Array<{ site_id: string; url: string; health_score: number }>
    [k: string]: unknown
  }
  report: Record<string, unknown>
}

export interface PortfolioSiteRow {
  site_id: string
  domain: string
  url: string
  group_id: string | null
  risk_score: number
  risk_level: string
  health_score: number
  monitoring: boolean
  last_scan_at: string | null
  wade_changed: boolean
  top_issue: string | null
}

export interface PortfolioSitesResponse {
  sites: PortfolioSiteRow[]
  count: number
}

export interface PortfolioAlert {
  alert_type: string
  severity: string
  title: string
  detail: string
  affected_count: number
  affected_site_ids: string[]
  shared_indicator: string | null
}

export interface PortfolioAlertsResponse {
  alerts: PortfolioAlert[]
  count: number
}

export interface PortfolioGroup {
  group_id: string
  name: string
  group_type: string
  parent_group_id: string | null
  site_count: number
}

export interface PortfolioWadeSummary {
  sites_changed: string[]
  sites_with_suspicious_changes: string[]
  sites_with_new_third_parties: string[]
  sites_riskier: string[]
  sites_improved: string[]
  shared_changes: Array<{ indicator: string; site_ids: string[]; site_count: number }>
  changed_count: number
}

function _qs(params: object): string {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    qs.set(k, String(v))
  }
  return qs.toString()
}

// SSE stream for live SOC events. Uses fetch (not EventSource) so the Bearer
// token rides as a header. Returns an abort function. Calls onEvent for each
// JSON 'something changed' ping; onError on stream failure (caller may retry).
export function streamInternalEvents(
  onEvent: (data: Record<string, unknown>) => void,
  onError?: () => void,
  // Fires once the server's body stream actually begins yielding (the SSE
  // ": connected" comment, or the first keepalive). Distinct from onEvent
  // so the UI can show "connected but idle" instead of "disconnected".
  onConnect?: () => void,
): () => void {
  const controller = new AbortController()
  const tok = getStoredToken()
  ;(async () => {
    try {
      const res = await fetch(`${BASE_URL}/internal/stream`, {
        headers: tok ? { Authorization: `Bearer ${tok}` } : {},
        signal: controller.signal,
      })
      if (!res.ok || !res.body) { onError?.(); return }
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''
      let seenAnyBytes = false
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        if (!seenAnyBytes && value && value.byteLength > 0) {
          seenAnyBytes = true
          onConnect?.()
        }
        buf += decoder.decode(value, { stream: true })
        const frames = buf.split('\n\n')
        buf = frames.pop() ?? ''
        for (const frame of frames) {
          const line = frame.split('\n').find(l => l.startsWith('data:'))
          if (!line) continue
          try { onEvent(JSON.parse(line.slice(5).trim())) } catch { /* ignore */ }
        }
      }
      // Body ended normally — server closed the stream. Surface as error so
      // the layout reconnect logic kicks in.
      if (!controller.signal.aborted) onError?.()
    } catch {
      if (!controller.signal.aborted) onError?.()
    }
  })()
  return () => controller.abort()
}

// ---------------------------------------------------------------------------
// Internal command-center types (mirror apps/api/internal/router.py)
// ---------------------------------------------------------------------------

export interface InternalMe {
  id: string
  email: string
  full_name: string | null
  role: string
  is_super_admin: boolean
}

export interface CommandCenter {
  generated_at: string
  scans: {
    queued: number; running: number; failed_24h: number; completed_24h: number;
    total: number; avg_duration_s: number | null;
    completed_24h_delta_pct?: number | null;
    failed_24h_delta_pct?: number | null;
  } | { error: string }
  users: { total: number; paid: number; new_7d: number; new_7d_delta_pct?: number | null } | { error: string }
  billing: { active_subscriptions: number; mrr_usd: number; arr_usd: number } | { error: string }
  infra: { database: string; redis: string; queue_depth: number | null; worker: string; stripe_configured: boolean; maintenance?: boolean; overall?: 'operational' | 'degraded' | 'maintenance' | 'offline' } | { error: string }
  activity: { id: string; actor: string | null; action: string; target: string | null; at: string | null }[]
  incidents?: IncidentSummary
}

// Scan Ops (mirror apps/api/internal/scan_ops.py)
export interface ScanRow {
  id: string
  status: string
  profile: string
  url: string
  hostname: string | null
  owner: string | null
  created_at: string | null
  duration_s: number | null
  error: string | null
}

export interface ScanListResponse {
  items: ScanRow[]
  total: number
  limit: number
  offset: number
}

export interface EngineDiagnostic {
  engine: string
  category: string | null
  status: string
  findings: number
  duration_ms: number | null
  skipped_reason: string | null
  error: string | null
}

export interface ScanDetail extends ScanRow {
  started_at: string | null
  completed_at: string | null
  celery_task_id: string | null
  engines: EngineDiagnostic[]
}

export interface EngineScorecard {
  engine: string
  runs: number
  failed: number
  skipped: number
  failure_rate: number
  empty_rate: number
  avg_ms: number | null
  reliability: number | null
}

// SOC Alerts (mirror apps/api/internal/alerts.py)
export interface AlertRow {
  id: string
  dedup_key: string
  source: string
  severity: string
  status: string
  title: string
  description: string | null
  target_type: string | null
  target_id: string | null
  occurrences: number
  first_seen_at: string | null
  last_seen_at: string | null
  assignee_id: string | null
  acknowledged_by: string | null
  resolved_by: string | null
}

export interface AlertListResponse {
  items: AlertRow[]
  total: number
  limit: number
  offset: number
}

export interface AlertSummary {
  open: number
  active: number
  by_severity: Record<string, number>
}

export interface AlertComment {
  id: string
  kind: string
  author: string | null
  body: string
  at: string | null
}

export interface AlertDetail extends AlertRow {
  detail: Record<string, unknown>
  comments: AlertComment[]
}

// Customers (mirror apps/api/internal/customers.py)
export interface CustomerRow {
  id: string
  email: string
  full_name: string | null
  company_name: string | null
  plan: string
  is_active: boolean
  admin_role: string
  created_at: string | null
  last_login_at: string | null
  banned_at: string | null
}

export interface CustomerListResponse {
  items: CustomerRow[]
  total: number
  limit: number
  offset: number
}

export interface CustomerSubscription {
  id: string
  stripe_subscription_id: string
  plan: string
  status: string
  current_period_end: string | null
  cancel_at_period_end: boolean
  canceled_at: string | null
}

export interface CustomerDetail extends CustomerRow {
  is_admin: boolean
  email_verified: boolean
  oauth_provider: string | null
  stripe_customer_id: string | null
  banned_reason: string | null
  websites: number
  scans: number
  last_scan_at: string | null
  failed_30d: number
  subscriptions: CustomerSubscription[]
}

export interface CustomerNote {
  id: string
  author: string | null
  body: string
  at: string | null
}

// Billing Ops (mirror apps/api/internal/billing_ops.py)
export interface BillingMetrics {
  generated_at: string
  stripe: {
    mrr_usd: number
    arr_usd: number
    active_subscriptions: number
    past_due: number
    failed_payments_24h: number
  } | { error: string }
  local: {
    active_subscriptions_local: number
    canceled_last_30d: number
  }
}

export interface SubscriptionRow {
  id: string
  email: string
  stripe_subscription_id: string
  stripe_customer_id: string
  plan: string
  status: string
  current_period_end: string | null
  cancel_at_period_end: boolean
  canceled_at: string | null
}

export interface StripeEventRow {
  id: string
  type: string
  livemode: boolean
  created: number
  request_id: string | null
}

// Fraud & Abuse (mirror apps/api/internal/abuse.py)
export interface AbuseFlagRow {
  id: string
  dedup_key: string
  user_id: string | null
  ip_address: string | null
  score: number
  severity: string
  status: string
  reasons: string[]
  occurrences: number
  first_seen_at: string | null
  last_seen_at: string | null
  resolved_by: string | null
  resolved_at: string | null
  resolution_note: string | null
}

export interface AbuseFlagDetail extends AbuseFlagRow {
  detail: Record<string, Record<string, unknown>>
  user_email?: string | null
  user_is_active?: boolean
}

export interface AbuseFlagListResponse {
  items: AbuseFlagRow[]
  total: number
  limit: number
  offset: number
}

export interface AbuseSummary {
  pending: number
  by_severity: Record<string, number>
}

export interface AbuseEvaluation {
  score: { score: number; severity: string; reasons: string[]; detail: Record<string, Record<string, unknown>> }
  flag_id?: string
  flag_created?: boolean
}

export interface IPFingerprint {
  id: string
  ip_address: string
  user_agent: string
  occurrences: number
  first_seen_at: string | null
  last_seen_at: string | null
}

// Support / Fix Service tickets (mirror apps/api/internal/support.py)
export interface TicketRow {
  id: string
  number: number
  user_id: string | null
  assignee_id: string | null
  subject: string
  category: string
  priority: string
  status: string
  source_scan_id: string | null
  verification_scan_id: string | null
  sla_due_at: string | null
  opened_at: string | null
  first_response_at: string | null
  resolved_at: string | null
  closed_at: string | null
  breached: boolean
}

export interface TicketEvent {
  id: string
  kind: string
  visibility: string
  author: string | null
  body: string
  at: string | null
}

export interface TicketDetail extends TicketRow {
  description: string | null
  events: TicketEvent[]
  user_email?: string | null
  assignee_email?: string | null
}

export interface TicketListResponse {
  items: TicketRow[]
  total: number
  limit: number
  offset: number
}

export interface TicketSummary {
  by_status: Record<string, number>
  open: number
  breached: number
}

export interface TicketCreateBody {
  user_id?: string | null
  subject: string
  description?: string | null
  category?: string
  priority?: string
  source_scan_id?: string | null
}

// Team / Deploys / Infra / Maintenance (mirror apps/api/internal/team_deploys.py)
export interface StaffMember {
  id: string
  email: string
  full_name: string | null
  admin_role: string
  is_active: boolean
  last_login_at: string | null
}

export interface TeamResponse {
  staff: StaffMember[]
  force_logged_out_count: number
}

export interface LoginRow {
  id: string
  email: string
  admin_role: string
  last_login_at: string | null
}

export interface DenylistedUser {
  id: string
  email: string
  admin_role: string
  is_active: boolean
}

export interface TeamSessionsResponse {
  recent_logins: LoginRow[]
  force_logged_out: DenylistedUser[]
}

export interface DeployRow {
  id: string
  service: string
  sha: string
  status: string
  actor: string | null
  note: string | null
  started_at: string | null
  finished_at: string | null
}

export interface DeploysResponse {
  current_sha: string | null
  items: DeployRow[]
}

export interface InfraSample {
  taken_at: string | null
  queue_depth: number | null
  worker_alive: boolean
  worker_heartbeat_age_s: number | null
  redis_used_memory_mb: number | null
  active_scans: number | null
}

export interface MaintenanceState {
  active: boolean
  reason: string | null
  error?: string
}

// Log Explorer + Audit (mirror apps/api/internal/logs.py)
export interface LogRow {
  id: string
  timestamp: string | null
  source: string
  severity: string
  message: string
  context: Record<string, unknown>
  request_id: string | null
  actor_email: string | null
}

export interface LogSearchParams {
  source?: string
  severity?: string
  severity_at_least?: string
  q?: string
  request_id?: string
  since?: string
  until?: string
  limit?: number
  offset?: number
}

export interface LogSearchResponse {
  items: LogRow[]
  total: number
  limit: number
  offset: number
}

export interface AuditRow {
  id: string
  action: string
  actor_email: string | null
  actor_role: string | null
  target_type: string | null
  target_id: string | null
  detail: Record<string, unknown>
  ip_address: string | null
  request_id: string | null
  at: string | null
}

export interface AuditSearchParams {
  action?: string
  actor_email?: string
  target_type?: string
  target_id?: string
  q?: string
  since?: string
  until?: string
  limit?: number
  offset?: number
}

export interface AuditSearchResponse {
  items: AuditRow[]
  total: number
  limit: number
  offset: number
}

// Threat Intelligence (mirror apps/api/internal/threat_intel.py)
export interface ThreatIndicatorRow {
  id: string
  kind: string
  value: string
  source: string
  severity: string
  confidence: number
  tags: string[]
  notes: string | null
  first_seen_at: string | null
  last_seen_at: string | null
  expires_at: string | null
}

export interface ThreatListResponse {
  items: ThreatIndicatorRow[]
  total: number
  limit: number
  offset: number
}

export interface ThreatAddBody {
  kind: string
  value: string
  source?: string
  severity?: string
  confidence?: number
  tags?: string[]
  notes?: string | null
  expires_at?: string | null
}

export interface ThreatImportBody {
  source: string
  rows: { kind: string; value: string; severity?: string; confidence?: number; tags?: string[]; notes?: string }[]
  default_severity?: string
  default_confidence?: number
  expires_in_days?: number | null
}

// Incidents (mirror apps/api/internal/incidents.py)
export interface IncidentRow {
  id: string
  number: number
  correlation_key: string
  source: string
  title: string
  severity: string
  status: string
  target_type: string | null
  target_id: string | null
  detail: Record<string, unknown>
  alert_count: number
  assignee_id: string | null
  first_seen_at: string | null
  last_seen_at: string | null
  sla_due_at: string | null
  acknowledged_at: string | null
  acknowledged_by: string | null
  mitigated_at: string | null
  resolved_at: string | null
  resolved_by: string | null
  mttr_seconds: number | null
  breached: boolean
}

export interface IncidentEvent {
  id: string
  kind: string
  author: string | null
  body: string
  alert_id: string | null
  at: string | null
}

export interface IncidentDetail extends IncidentRow {
  events: IncidentEvent[]
  assignee_email?: string | null
}

export interface IncidentListResponse {
  items: IncidentRow[]
  total: number
  limit: number
  offset: number
}

export interface IncidentSummary {
  active: number
  by_status: Record<string, number>
  by_severity: Record<string, number>
  breached: number
  top: {
    id: string
    number: number
    title: string
    severity: string
    status: string
    alert_count: number
    last_seen_at: string | null
    breached: boolean
  } | null
}

// Engine diagnostics deep-dive (mirror apps/api/internal/engines.py engine_diagnostics)
export interface EngineDiagnosticRow {
  id: string
  scan_result_id: string
  status: string
  category: string | null
  findings: number
  duration_ms: number | null
  skipped_reason: string | null
  error: string | null
  timeout: boolean
  at: string | null
}

export interface EngineDiagnosticsResponse {
  engine: string
  runs: number
  window_hours: number
  by_status: Record<string, number>
  timeouts: number
  timeout_rate?: number
  duration: {
    p50?: number | null
    p90?: number | null
    p99?: number | null
    avg?: number | null
    max?: number | null
    min?: number | null
  }
  errors: { message: string; count: number }[]
  items: EngineDiagnosticRow[]
}

// Engines (Phase 2 endpoint extended; mirror apps/api/internal/scan_ops.py engine_scorecards)
export interface EngineHealthRow {
  engine: string
  runs: number
  failed: number
  skipped: number
  empty?: number
  failure_rate: number
  empty_rate: number
  avg_ms: number | null
  max_ms?: number | null
  reliability: number | null
  state?: 'healthy' | 'degraded' | 'unstable' | 'critical' | 'maintenance'
  maintenance_mode?: boolean
  auto_disable_at_failure_pct?: number | null
  notes?: string | null
}

// ---------------------------------------------------------------------------
// Billing types (mirror apps/api/routers/billing.py)
// ---------------------------------------------------------------------------

export interface PlanResponse {
  tier: 'free' | 'pro' | 'shield' | 'enterprise'
  name: string
  tagline: string
  price_usd_monthly: number
  max_websites: number
  scans_per_month: number
  scan_history_days: number
  max_concurrent_scans: number
  scan_profiles_allowed: string[]
  monitoring_enabled: boolean
  monitoring_min_frequency: 'manual' | 'weekly' | 'daily'
  exports_enabled: boolean
  alerts_enabled: boolean
  threat_intel_external: boolean
  team_seats: number
  api_access: boolean
  is_popular: boolean
  cta_label: string
  sort_order: number
  features: { label: string; included: boolean }[]
}

export interface CurrentSubscriptionResponse {
  plan: 'free' | 'pro' | 'shield' | 'enterprise'
  status: string | null
  current_period_end: string | null
  cancel_at_period_end: boolean
  usage: {
    websites_used: number
    websites_limit: number
    scans_used_30d: number
    scans_limit: number
  }
}
