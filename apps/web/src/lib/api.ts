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

  billing: {
    plans: () => request<PlanResponse[]>('GET', '/billing/plans'),

    subscription: () =>
      request<CurrentSubscriptionResponse>('GET', '/billing/subscription'),

    checkout: (data: {
      tier: 'starter' | 'pro'
      cadence?: 'monthly' | 'yearly'
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
}

// ---------------------------------------------------------------------------
// Billing types (mirror apps/api/routers/billing.py)
// ---------------------------------------------------------------------------

export interface PlanResponse {
  tier: 'free' | 'starter' | 'pro' | 'enterprise'
  name: string
  tagline: string
  price_usd_monthly: number
  price_usd_yearly: number
  max_websites: number
  scans_per_month: number
  scan_history_days: number
  max_concurrent_scans: number
  monitoring_enabled: boolean
  exports_enabled: boolean
  alerts_enabled: boolean
  threat_intel_external: boolean
  team_seats: number
  is_popular: boolean
  cta_label: string
  sort_order: number
  features: { label: string; included: boolean }[]
}

export interface CurrentSubscriptionResponse {
  plan: 'free' | 'starter' | 'pro' | 'enterprise'
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
