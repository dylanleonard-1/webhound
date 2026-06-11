'use client'

import { Suspense, useCallback, useEffect, useState, type FormEvent } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { motion } from 'framer-motion'
import { toast } from 'sonner'
import {
  User, Lock, Bell, Key, Plug, CreditCard, Users,
  LogOut, AlertTriangle, CheckCircle2, Loader2, ChevronRight,
  Mail, Sparkles, X,
} from 'lucide-react'
import { useAuth } from '@/contexts/auth'
import { api, type UseCase } from '@/lib/api'

const SECTION_IDS = [
  'profile', 'account', 'notifications',
  'connected_services', 'api', 'integrations', 'billing', 'team',
] as const

function isSectionId(v: string | null): v is SectionId {
  return v !== null && (SECTION_IDS as readonly string[]).includes(v)
}

// ── Categories ────────────────────────────────────────────────────────────────

type SectionId =
  | 'profile' | 'account' | 'notifications'
  | 'connected_services' | 'api' | 'integrations' | 'billing' | 'team'

interface Category {
  id: SectionId
  label: string
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  description: string
}

const CATEGORIES: Category[] = [
  { id: 'profile',       label: 'Profile',         icon: User,       description: 'Your name and how WebHound sees you' },
  { id: 'account',       label: 'Account',         icon: Lock,       description: 'Email, password, account deletion' },
  { id: 'notifications', label: 'Notifications',   icon: Bell,       description: 'Alert channels and delivery' },
  { id: 'connected_services', label: 'Connected Services', icon: Plug, description: 'Provider connections (Cloudflare, Vercel)' },
  { id: 'api',           label: 'API Keys',        icon: Key,        description: 'Personal access tokens' },
  { id: 'integrations',  label: 'Integrations',    icon: Plug,       description: 'Slack, webhooks, PagerDuty' },
  { id: 'billing',       label: 'Plan & Billing',  icon: CreditCard, description: 'Subscription and usage' },
  { id: 'team',          label: 'Team',            icon: Users,      description: 'Members and roles' },
]

const USE_CASES: Array<{ value: UseCase; label: string }> = [
  { value: 'developer',         label: 'Developer' },
  { value: 'security_engineer', label: 'Security engineer' },
  { value: 'founder',           label: 'Founder / owner' },
  { value: 'agency',            label: 'Agency / consultant' },
  { value: 'it_team',           label: 'IT / ops team' },
  { value: 'other',             label: 'Something else' },
]

// ── Shared bits ───────────────────────────────────────────────────────────────

function FieldLabel({ children, optional }: { children: React.ReactNode; optional?: boolean }) {
  return (
    <label className="block text-[12px] font-medium mb-1.5" style={{ color: 'rgba(255,255,255,0.55)' }}>
      {children}
      {optional && <span className="ml-1" style={{ color: 'rgba(255,255,255,0.25)' }}>(optional)</span>}
    </label>
  )
}

const INPUT_BASE: React.CSSProperties = {
  background: 'rgba(255,255,255,0.04)',
  border: '1px solid rgba(255,255,255,0.08)',
}

function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={`w-full h-10 px-3.5 rounded-xl text-[13px] text-white placeholder:text-gray-600 outline-none transition-colors ${props.className ?? ''}`}
      style={{ ...INPUT_BASE, ...(props.style ?? {}) }}
      onFocus={e => { e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)'; props.onFocus?.(e) }}
      onBlur={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'; props.onBlur?.(e) }}
    />
  )
}

function PrimaryButton(props: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className={`flex items-center justify-center gap-1.5 h-10 px-4 rounded-xl text-[12.5px] font-semibold text-[#020617] disabled:opacity-50 transition-opacity ${props.className ?? ''}`}
      style={{ background: '#8BFF3E', boxShadow: '0 0 16px rgba(139,255,62,0.15)', ...(props.style ?? {}) }}
    />
  )
}

function SectionHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="mb-5">
      <h2 className="text-[18px] font-bold text-white tracking-tight">{title}</h2>
      {subtitle && (
        <p className="text-[12.5px] mt-1" style={{ color: 'rgba(255,255,255,0.42)' }}>{subtitle}</p>
      )}
    </div>
  )
}

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="rounded-[12px] p-5"
      style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
    >
      {children}
    </div>
  )
}

function ComingSoon({ note }: { note: string }) {
  return (
    <div
      className="flex items-start gap-3 rounded-[10px] p-4"
      style={{ background: 'rgba(79,156,249,0.05)', border: '1px solid rgba(79,156,249,0.15)' }}
    >
      <Sparkles className="w-4 h-4 mt-0.5 flex-shrink-0" style={{ color: '#4F9CF9' }} />
      <div>
        <p className="text-[12.5px] font-semibold text-white">Coming soon</p>
        <p className="text-[12px] mt-0.5" style={{ color: 'rgba(255,255,255,0.5)' }}>{note}</p>
      </div>
    </div>
  )
}

function Notice({ kind, children }: { kind: 'success' | 'error'; children: React.ReactNode }) {
  const ok = kind === 'success'
  const color = ok ? '#8BFF3E' : '#ef4444'
  return (
    <p
      className="text-[12px] rounded-xl px-3 py-2 flex items-center gap-2"
      style={{
        background: `${color}10`,
        border: `1px solid ${color}30`,
        color: ok ? color : '#fca5a5',
      }}
    >
      {ok ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
      {children}
    </p>
  )
}

// ── Profile section ───────────────────────────────────────────────────────────

function ProfilePanel() {
  const { user } = useAuth()
  const [fullName, setFullName] = useState(user?.full_name ?? '')
  const [companyName, setCompanyName] = useState(user?.company_name ?? '')
  const [useCase, setUseCase] = useState<UseCase | ''>((user?.use_case ?? '') as UseCase | '')
  const [saving, setSaving] = useState(false)
  const [success, setSuccess] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setFullName(user?.full_name ?? '')
    setCompanyName(user?.company_name ?? '')
    setUseCase((user?.use_case ?? '') as UseCase | '')
  }, [user])

  async function handleSave(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    setSuccess(false)
    setError(null)
    try {
      await api.auth.updateMe({
        full_name: fullName || null,
        company_name: companyName || null,
        use_case: (useCase || null) as UseCase | null,
      })
      setSuccess(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save changes.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <SectionHeader title="Profile" subtitle="Information shown in the dashboard and on invites." />
      <Card>
        <form onSubmit={handleSave} className="space-y-4">
          <div>
            <FieldLabel>Full name</FieldLabel>
            <Input
              type="text" autoComplete="name" placeholder="Jane Doe"
              value={fullName} onChange={e => setFullName(e.target.value)}
            />
          </div>

          <div>
            <FieldLabel optional>Company / organization</FieldLabel>
            <Input
              type="text" autoComplete="organization" placeholder="Acme Inc."
              value={companyName} onChange={e => setCompanyName(e.target.value)}
            />
          </div>

          <div>
            <FieldLabel>Role</FieldLabel>
            <select
              value={useCase}
              onChange={e => setUseCase(e.target.value as UseCase | '')}
              className="w-full h-10 px-3 rounded-xl text-[13px] text-white outline-none appearance-none"
              style={{
                ...INPUT_BASE,
                backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%23a3a3a3' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E\")",
                backgroundRepeat: 'no-repeat',
                backgroundPosition: 'right 14px center',
                paddingRight: '36px',
              }}
              onFocus={e => (e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)')}
              onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
            >
              <option value="" className="bg-[#0a0f1c]">Not specified</option>
              {USE_CASES.map(opt => (
                <option key={opt.value} value={opt.value} className="bg-[#0a0f1c]">{opt.label}</option>
              ))}
            </select>
          </div>

          {success && <Notice kind="success">Profile saved.</Notice>}
          {error && <Notice kind="error">{error}</Notice>}

          <div className="flex justify-end">
            <PrimaryButton type="submit" disabled={saving}>
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Save changes'}
            </PrimaryButton>
          </div>
        </form>
      </Card>
    </>
  )
}

// ── Account section ───────────────────────────────────────────────────────────

function AccountPanel() {
  const { user, logout } = useAuth()

  // change password state
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [pwLoading, setPwLoading] = useState(false)
  const [pwSuccess, setPwSuccess] = useState(false)
  const [pwError, setPwError] = useState<string | null>(null)
  const isOAuthOnly = !user?.email_verified && !!user?.id // best-effort; backend will reject for OAuth-only

  async function handleChangePassword(e: FormEvent) {
    e.preventDefault()
    setPwLoading(true)
    setPwSuccess(false)
    setPwError(null)
    try {
      await api.auth.changePassword(current, next)
      setPwSuccess(true)
      setCurrent('')
      setNext('')
    } catch (err) {
      setPwError(err instanceof Error ? err.message : 'Could not change password.')
    } finally {
      setPwLoading(false)
    }
  }

  // delete account
  const [showDelete, setShowDelete] = useState(false)
  const [confirmPw, setConfirmPw] = useState('')
  const [delLoading, setDelLoading] = useState(false)
  const [delError, setDelError] = useState<string | null>(null)

  async function handleDelete() {
    setDelLoading(true)
    setDelError(null)
    try {
      await api.auth.deleteAccount(confirmPw)
      logout()
    } catch (err) {
      setDelError(err instanceof Error ? err.message : 'Could not delete account.')
      setDelLoading(false)
    }
  }

  return (
    <>
      <SectionHeader title="Account" subtitle="Sign-in details and security." />

      <Card>
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full flex items-center justify-center flex-shrink-0"
                 style={{ background: 'rgba(139,255,62,0.1)', color: '#8BFF3E' }}>
              <Mail className="w-4 h-4" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[13px] font-medium text-white truncate">{user?.email ?? '—'}</p>
              <p className="text-[11px]" style={{ color: 'rgba(255,255,255,0.4)' }}>
                {user?.email_verified ? 'Verified' : 'Unverified'} · signed in
              </p>
            </div>
          </div>
        </div>
      </Card>

      <div className="mt-5">
        <h3 className="text-[14px] font-semibold text-white mb-3">Change password</h3>
        <Card>
          <form onSubmit={handleChangePassword} className="space-y-4">
            <div>
              <FieldLabel>Current password</FieldLabel>
              <Input
                type="password" autoComplete="current-password"
                value={current} onChange={e => setCurrent(e.target.value)} required
              />
            </div>
            <div>
              <FieldLabel>New password</FieldLabel>
              <Input
                type="password" autoComplete="new-password" minLength={8}
                placeholder="Minimum 8 characters"
                value={next} onChange={e => setNext(e.target.value)} required
              />
            </div>

            {pwSuccess && <Notice kind="success">Password updated.</Notice>}
            {pwError && <Notice kind="error">{pwError}</Notice>}

            <div className="flex justify-end">
              <PrimaryButton type="submit" disabled={pwLoading || !current || next.length < 8}>
                {pwLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Update password'}
              </PrimaryButton>
            </div>
          </form>
        </Card>
      </div>

      <div className="mt-7">
        <h3 className="text-[14px] font-semibold text-white mb-3">Sessions</h3>
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[13px] text-white">Sign out of this device</p>
              <p className="text-[11.5px] mt-0.5" style={{ color: 'rgba(255,255,255,0.4)' }}>
                Ends the current session and clears your token.
              </p>
            </div>
            <button
              onClick={logout}
              className="flex items-center gap-1.5 px-3 h-9 rounded-[8px] text-[12px] font-semibold"
              style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: 'rgba(255,255,255,0.8)' }}
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign out
            </button>
          </div>
        </Card>
      </div>

      <div className="mt-7">
        <h3 className="text-[14px] font-semibold mb-3" style={{ color: '#ef4444' }}>Danger zone</h3>
        <div
          className="rounded-[12px] p-5"
          style={{ background: 'rgba(239,68,68,0.03)', border: '1px solid rgba(239,68,68,0.18)' }}
        >
          {!showDelete ? (
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[13px] font-semibold text-white">Delete account</p>
                <p className="text-[11.5px] mt-0.5" style={{ color: 'rgba(255,255,255,0.4)' }}>
                  Permanently removes your account, websites, scans, and history. This cannot be undone.
                </p>
              </div>
              <button
                onClick={() => setShowDelete(true)}
                className="flex items-center gap-1.5 px-3 h-9 rounded-[8px] text-[12px] font-semibold transition-all"
                style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', color: '#ef4444' }}
              >
                Delete account
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-[13px] font-semibold text-white">Confirm account deletion</p>
              <p className="text-[12px]" style={{ color: 'rgba(255,255,255,0.5)' }}>
                Type your password to confirm. {isOAuthOnly && '(Leave blank if you sign in only with Google or GitHub.)'}
              </p>
              <Input
                type="password" autoComplete="current-password"
                placeholder="Password" value={confirmPw}
                onChange={e => setConfirmPw(e.target.value)}
              />
              {delError && <Notice kind="error">{delError}</Notice>}
              <div className="flex items-center gap-2">
                <button
                  onClick={handleDelete}
                  disabled={delLoading}
                  className="h-9 px-4 rounded-[8px] text-[12px] font-semibold disabled:opacity-50"
                  style={{ background: '#ef4444', color: 'white' }}
                >
                  {delLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Yes, delete my account'}
                </button>
                <button
                  onClick={() => { setShowDelete(false); setConfirmPw(''); setDelError(null) }}
                  className="h-9 px-3 rounded-[8px] text-[12px] font-medium"
                  style={{ color: 'rgba(255,255,255,0.5)' }}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}

// ── Placeholder panels ────────────────────────────────────────────────────────

function NotificationsPanel() {
  return (
    <>
      <SectionHeader title="Notifications" subtitle="Where and when WebHound alerts you." />
      <ComingSoon note="Per-severity email digests, Slack alerts, and quiet hours. Today every account receives in-app notifications for completed scans and high-risk findings." />
    </>
  )
}

function ApiKeysPanel() {
  return (
    <>
      <SectionHeader title="API Keys" subtitle="Personal access tokens for the WebHound API." />
      <ComingSoon note="Token creation, scoping, expiry, and revocation. For now, sign in with your password — the JWT in the dashboard works for direct API calls during this preview." />
    </>
  )
}

interface SiteConnections {
  id: string
  hostname: string
  cloudflareConnected: boolean
  cloudflareStatus: string
}

function ConnectedServicesPanel() {
  const [sites, setSites] = useState<SiteConnections[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const list = await api.websites.list({ limit: 100 })
      const rows = await Promise.all((list.items ?? []).map(async (w) => {
        const cf = await api.websites.cloudflareScannerAccessStatus(w.id).catch(() => null)
        return {
          id: w.id, hostname: w.hostname,
          cloudflareConnected: !!cf?.cloudflare_connected,
          cloudflareStatus: cf?.cloudflare_scanner_access ?? 'not_connected',
        }
      }))
      setSites(rows)
    } finally {
      setLoading(false)
    }
  }, [])
  useEffect(() => { void load() }, [load])

  async function disconnectCloudflare(siteId: string, hostname: string) {
    if (!confirm(`Disconnect Cloudflare from ${hostname}? Removes the WebHound scanner rules and revokes access.`)) return
    setBusy(siteId)
    try {
      await api.websites.cloudflareScannerAccessDisconnect(siteId)
      await api.websites.trustedAccessRevoke(siteId).catch(() => null)
      toast.success(`Cloudflare disconnected from ${hostname}.`)
      await load()
    } catch (e) {
      toast.error((e as Error)?.message || 'Could not disconnect.')
    } finally {
      setBusy(null)
    }
  }

  const connected = sites.filter((s) => s.cloudflareConnected)

  return (
    <>
      <SectionHeader title="Connected Services" subtitle="Provider connections per website. Disconnect any time." />
      {loading ? (
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading connections…
        </div>
      ) : connected.length === 0 ? (
        <p className="text-sm text-gray-500">No connected providers yet. Connect Cloudflare or Vercel from a website’s setup.</p>
      ) : (
        <div className="space-y-2">
          {connected.map((s) => (
            <div key={s.id} className="rounded-[10px] p-4 flex items-center justify-between gap-3"
                 style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div className="min-w-0">
                <p className="text-[13px] text-white font-mono truncate">{s.hostname}</p>
                <p className="text-[11px] text-gray-500">
                  Cloudflare · scanner access: {s.cloudflareStatus.replace(/_/g, ' ')}
                </p>
              </div>
              <button
                type="button"
                onClick={() => disconnectCloudflare(s.id, s.hostname)}
                disabled={busy === s.id}
                className="h-8 px-3 rounded-lg text-[12px] font-medium text-red-300 border border-red-500/30 hover:bg-red-500/10 disabled:opacity-50"
              >
                {busy === s.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Disconnect'}
              </button>
            </div>
          ))}
        </div>
      )}
    </>
  )
}

function IntegrationsPanel() {
  return (
    <>
      <SectionHeader title="Integrations" subtitle="Send findings to the tools your team already uses." />
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {[
          { name: 'Slack',     desc: 'Channel alerts for high-risk findings.' },
          { name: 'Discord',   desc: 'Webhook posts on scan completion.' },
          { name: 'PagerDuty', desc: 'Page on critical findings.' },
          { name: 'Webhook',   desc: 'POST every event to your endpoint.' },
        ].map(i => (
          <div
            key={i.name}
            className="rounded-[10px] p-4 flex items-start gap-3"
            style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
          >
            <div className="w-8 h-8 rounded-[8px] flex items-center justify-center flex-shrink-0"
                 style={{ background: 'rgba(79,156,249,0.08)', border: '1px solid rgba(79,156,249,0.2)' }}>
              <Plug className="w-3.5 h-3.5" style={{ color: '#4F9CF9' }} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <p className="text-[13px] font-semibold text-white">{i.name}</p>
                <span className="text-[9px] font-black tracking-[0.12em] uppercase px-1.5 py-0.5 rounded"
                      style={{ background: 'rgba(255,255,255,0.05)', color: 'rgba(255,255,255,0.4)' }}>
                  Soon
                </span>
              </div>
              <p className="text-[11.5px] mt-0.5" style={{ color: 'rgba(255,255,255,0.4)' }}>{i.desc}</p>
            </div>
          </div>
        ))}
      </div>
    </>
  )
}

function BillingPanel({ status }: { status: string | null }) {
  const { user, refresh } = useAuth()
  const router = useRouter()
  const searchParams = useSearchParams()
  const [sub, setSub] = useState<{
    plan: string
    status: string | null
    current_period_end: string | null
    cancel_at_period_end: boolean
    usage: {
      websites_used: number; websites_limit: number
      scans_used_30d: number; scans_limit: number
    }
  } | null>(null)
  const [loading, setLoading] = useState(true)
  const [portalBusy, setPortalBusy] = useState(false)
  const [banner, setBanner] = useState<string | null>(status)

  // After a success redirect we don't wait on the webhook: /billing/sync
  // reconciles plan state directly from Stripe, so the new tier shows even if
  // webhook delivery is delayed or unconfigured. We then refresh the cached
  // auth user and poll a couple more times in case Stripe's API was briefly
  // behind. Normal loads just read /subscription.
  useEffect(() => {
    let cancelled = false
    let attempts = 0
    async function load(reconcile: boolean) {
      try {
        const s = reconcile
          ? await api.billing.sync()
          : await api.billing.subscription()
        if (cancelled) return
        setSub(s)
      } catch { /* swallow — banner will still render */ }
    }
    if (status === 'success') {
      // First call reconciles from Stripe, then sync the cached auth user.
      load(true).then(() => { if (!cancelled) refresh().catch(() => {}) })
        .finally(() => !cancelled && setLoading(false))
      const id = window.setInterval(() => {
        attempts += 1
        load(false)
        if (attempts >= 4) window.clearInterval(id)
      }, 1500)
      return () => { cancelled = true; window.clearInterval(id) }
    }
    load(false).finally(() => !cancelled && setLoading(false))
    return () => { cancelled = true }
  }, [status])  // eslint-disable-line react-hooks/exhaustive-deps

  function dismissBanner() {
    setBanner(null)
    const params = new URLSearchParams(searchParams.toString())
    params.delete('status')
    const qs = params.toString()
    router.replace(qs ? `?${qs}` : '?tab=billing', { scroll: false })
  }

  async function openPortal() {
    setPortalBusy(true)
    try {
      const { url } = await api.billing.portal({})
      window.location.href = url
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Could not open billing portal.'
      toast.error(msg)
    } finally {
      setPortalBusy(false)
    }
  }

  const planLabel: Record<string, string> = {
    free: 'Free',
    pro: 'Pro',
    shield: 'Shield',
    enterprise: 'Managed Security Review',
  }
  const statusLabel = sub?.status ?? 'free'
  const periodEnd = sub?.current_period_end
    ? new Date(sub.current_period_end).toLocaleDateString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
      })
    : null

  return (
    <>
      <SectionHeader title="Plan & Billing" subtitle="Subscription, usage, and invoices." />

      {banner === 'success' && (
        <div className="flex items-start gap-3 rounded-[10px] p-3.5 mb-4"
             style={{ background: 'rgba(139,255,62,0.06)',
                      border: '1px solid rgba(139,255,62,0.25)' }}>
          <CheckCircle2 className="w-4 h-4 mt-0.5 flex-shrink-0"
                        style={{ color: '#8BFF3E' }} />
          <div className="flex-1">
            <p className="text-[13px] font-semibold text-white">
              Subscription updated — welcome to your new plan.
            </p>
            <p className="text-[12px] mt-0.5"
               style={{ color: 'rgba(255,255,255,0.55)' }}>
              Your tier should reflect within a few seconds. New scan
              profiles, sites, and quota limits are live now.
            </p>
          </div>
          <button onClick={dismissBanner} className="p-1 rounded hover:bg-white/[0.05] transition-colors">
            <X className="w-3.5 h-3.5" style={{ color: 'rgba(255,255,255,0.45)' }} />
          </button>
        </div>
      )}
      {banner === 'cancelled' && (
        <div className="flex items-start gap-3 rounded-[10px] p-3.5 mb-4"
             style={{ background: 'rgba(255,255,255,0.03)',
                      border: '1px solid rgba(255,255,255,0.08)' }}>
          <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0"
                         style={{ color: '#f97316' }} />
          <div className="flex-1">
            <p className="text-[13px] font-semibold text-white">
              Checkout cancelled — no changes were made.
            </p>
            <p className="text-[12px] mt-0.5"
               style={{ color: 'rgba(255,255,255,0.55)' }}>
              You can pick a plan again anytime from the pricing page.
            </p>
          </div>
          <button onClick={dismissBanner} className="p-1 rounded hover:bg-white/[0.05] transition-colors">
            <X className="w-3.5 h-3.5" style={{ color: 'rgba(255,255,255,0.45)' }} />
          </button>
        </div>
      )}

      {loading ? (
        <Card>
          <div className="h-20 bg-white/[0.02] rounded animate-pulse" />
        </Card>
      ) : (
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[11px] font-black tracking-[0.12em] uppercase" style={{ color: 'rgba(255,255,255,0.32)' }}>
                Current plan
              </p>
              <p className="text-[20px] font-bold text-white mt-1">
                {planLabel[sub?.plan ?? 'free'] ?? 'Free'}
              </p>
              <p className="text-[12px] mt-0.5" style={{ color: 'rgba(255,255,255,0.45)' }}>
                {sub?.cancel_at_period_end
                  ? `Cancels on ${periodEnd}`
                  : periodEnd
                    ? `Renews ${periodEnd}`
                    : `Billed to ${user?.email ?? '—'}`}
              </p>
            </div>
            <span className="text-[10px] font-black tracking-[0.12em] uppercase px-2 py-1 rounded"
                  style={{
                    background: 'rgba(139,255,62,0.1)',
                    color: '#8BFF3E',
                    border: '1px solid rgba(139,255,62,0.25)',
                  }}>
              {statusLabel}
            </span>
          </div>
        </Card>
      )}

      {/* Usage meters */}
      {sub && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-4">
          <UsageMeter
            label="Websites"
            used={sub.usage.websites_used}
            limit={sub.usage.websites_limit}
          />
          <UsageMeter
            label="Scans (last 30 days)"
            used={sub.usage.scans_used_30d}
            limit={sub.usage.scans_limit}
          />
        </div>
      )}

      {/* Actions */}
      <div className="flex flex-wrap gap-2 mt-4">
        <Link
          href="/pricing"
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[8px] text-[12px] font-semibold transition-colors"
          style={{
            background: '#8BFF3E', color: '#020617',
          }}
        >
          {sub?.plan === 'shield' || sub?.plan === 'enterprise'
            ? 'Change plan'
            : 'Upgrade plan'}
        </Link>
        {sub?.plan !== 'free' && (
          <button
            type="button"
            onClick={openPortal}
            disabled={portalBusy}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[8px] text-[12px] font-semibold transition-colors disabled:opacity-50"
            style={{
              background: 'rgba(255,255,255,0.05)',
              color: '#fff',
              border: '1px solid rgba(255,255,255,0.12)',
            }}
          >
            {portalBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Manage subscription'}
          </button>
        )}
      </div>
    </>
  )
}

function UsageMeter({ label, used, limit }: { label: string; used: number; limit: number }) {
  const pct = limit > 0 ? Math.min(100, (used / limit) * 100) : 0
  const color = pct >= 90 ? '#ef4444' : pct >= 70 ? '#f97316' : '#8BFF3E'
  return (
    <div
      className="rounded-[12px] p-4"
      style={{
        background: 'rgba(8,12,22,0.95)',
        border: '1px solid rgba(255,255,255,0.06)',
      }}
    >
      <div className="flex items-baseline justify-between mb-2">
        <span className="text-[11px] font-black tracking-[0.12em] uppercase" style={{ color: 'rgba(255,255,255,0.32)' }}>
          {label}
        </span>
        <span className="text-[11px] font-mono" style={{ color: 'rgba(255,255,255,0.55)' }}>
          {used} / {limit}
        </span>
      </div>
      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{ width: `${pct}%`, background: color }}
        />
      </div>
    </div>
  )
}

function TeamPanel() {
  const { user } = useAuth()
  return (
    <>
      <SectionHeader title="Team" subtitle="Invite teammates and manage permissions." />
      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full flex items-center justify-center flex-shrink-0 text-[12px] font-black"
                 style={{ background: 'rgba(139,255,62,0.1)', color: '#8BFF3E' }}>
              {user?.email?.[0]?.toUpperCase() ?? '?'}
            </div>
            <div>
              <p className="text-[13px] font-medium text-white">{user?.full_name || user?.email}</p>
              <p className="text-[11.5px]" style={{ color: 'rgba(255,255,255,0.4)' }}>Owner</p>
            </div>
          </div>
          <span className="text-[10px] font-black tracking-[0.12em] uppercase px-2 py-1 rounded"
                style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.5)' }}>
            You
          </span>
        </div>
      </Card>
      <div className="mt-4">
        <ComingSoon note="Inviting members, roles (Owner / Admin / Member / Read-only), and SSO will land before general availability." />
      </div>
    </>
  )
}

// ── Page shell ────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  return (
    <Suspense fallback={null}>
      <SettingsPageInner />
    </Suspense>
  )
}

function SettingsPageInner() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const tabParam = searchParams.get('tab')
  const status = searchParams.get('status')
  const initial: SectionId = isSectionId(tabParam) ? tabParam : 'profile'
  const [active, setActive] = useState<SectionId>(initial)

  // If the URL tab changes (e.g. external link, Stripe redirect), follow it.
  useEffect(() => {
    if (isSectionId(tabParam) && tabParam !== active) setActive(tabParam)
  }, [tabParam])  // eslint-disable-line react-hooks/exhaustive-deps

  function selectTab(id: SectionId) {
    setActive(id)
    const params = new URLSearchParams(searchParams.toString())
    params.set('tab', id)
    // Once the user moves to a different tab, drop any stale ?status flag
    // so the banner doesn't reappear later.
    if (id !== 'billing') params.delete('status')
    router.replace(`?${params.toString()}`, { scroll: false })
  }

  return (
    <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
      <div className="max-w-[1080px] mx-auto px-4 py-5 sm:px-6 sm:py-8">
        <motion.div
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}
          className="mb-6"
        >
          <h1 className="text-[22px] font-bold text-white tracking-tight">Settings</h1>
          <p className="text-[13px] mt-0.5" style={{ color: 'rgba(255,255,255,0.4)' }}>
            Manage your account, preferences, and team.
          </p>
        </motion.div>

        {/* Mobile: horizontal-scroll tab strip */}
        <div className="md:hidden mb-5 -mx-4 px-4 overflow-x-auto" style={{ scrollbarWidth: 'none' }}>
          <div className="flex gap-2 w-max">
            {CATEGORIES.map(c => {
              const isActive = c.id === active
              return (
                <button
                  key={c.id}
                  onClick={() => selectTab(c.id)}
                  className="flex items-center gap-1.5 h-9 px-3 rounded-[8px] text-[12.5px] font-medium whitespace-nowrap transition-colors"
                  style={{
                    background: isActive ? 'rgba(139,255,62,0.1)' : 'rgba(255,255,255,0.03)',
                    border: `1px solid ${isActive ? 'rgba(139,255,62,0.3)' : 'rgba(255,255,255,0.06)'}`,
                    color: isActive ? '#8BFF3E' : 'rgba(255,255,255,0.55)',
                  }}
                >
                  <c.icon className="w-3.5 h-3.5" />
                  {c.label}
                </button>
              )
            })}
          </div>
        </div>

        <div className="md:grid md:grid-cols-[220px_1fr] md:gap-8">
          {/* Desktop: left side nav */}
          <aside className="hidden md:block">
            <nav className="flex flex-col gap-0.5 sticky top-0">
              {CATEGORIES.map(c => {
                const isActive = c.id === active
                const Icon = c.icon
                return (
                  <button
                    key={c.id}
                    onClick={() => selectTab(c.id)}
                    className="group flex items-center gap-2.5 px-3 py-2 rounded-[9px] text-left transition-colors"
                    style={{
                      background: isActive ? 'rgba(139,255,62,0.07)' : 'transparent',
                      color: isActive ? '#ffffff' : 'rgba(255,255,255,0.55)',
                    }}
                    onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = 'rgba(255,255,255,0.03)' }}
                    onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = 'transparent' }}
                  >
                    <Icon
                      className="w-[15px] h-[15px] flex-shrink-0"
                      style={{ color: isActive ? '#8BFF3E' : 'currentColor' }}
                    />
                    <span className="text-[13px] font-medium">{c.label}</span>
                    {isActive && (
                      <ChevronRight className="w-3 h-3 ml-auto" style={{ color: '#8BFF3E' }} />
                    )}
                  </button>
                )
              })}
            </nav>
          </aside>

          {/* Panel */}
          <motion.div
            key={active}
            initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.22 }}
          >
            {active === 'profile'       && <ProfilePanel />}
            {active === 'account'       && <AccountPanel />}
            {active === 'notifications' && <NotificationsPanel />}
            {active === 'connected_services' && <ConnectedServicesPanel />}
            {active === 'api'           && <ApiKeysPanel />}
            {active === 'integrations'  && <IntegrationsPanel />}
            {active === 'billing'       && <BillingPanel status={status} />}
            {active === 'team'          && <TeamPanel />}
          </motion.div>
        </div>
      </div>
    </div>
  )
}
