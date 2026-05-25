'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { Play, Lock, Sparkles } from 'lucide-react'
import { api, type ScanJobResponse, type ScanProfile } from '@/lib/api'
import { Button } from './ui/button'
import { cn } from '@/lib/utils'

const PROFILES: { value: ScanProfile; label: string; description: string }[] = [
  { value: 'quick',    label: 'Quick',    description: 'Fast surface-level check (5 pages)' },
  { value: 'standard', label: 'Standard', description: 'Balanced depth and speed (25 pages)' },
  { value: 'deep',     label: 'Deep',     description: 'Thorough analysis (100 pages)' },
  { value: 'monitor',  label: 'Monitor',  description: 'Lightweight recurring check' },
]

// User-facing scan profiles. "monitor" is the scheduler's internal
// profile — never shown in the manual launch picker.
const USER_PROFILES = PROFILES.filter(p => p.value !== 'monitor')

interface ScanLaunchFormProps {
  websiteId: string
  onStarted: (job: ScanJobResponse) => void
}

export function ScanLaunchForm({ websiteId, onStarted }: ScanLaunchFormProps) {
  const [profile, setProfile] = useState<ScanProfile>('quick')
  const [saveBaseline, setSaveBaseline] = useState(true)
  const [useLatestBaseline, setUseLatestBaseline] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [allowedProfiles, setAllowedProfiles] = useState<string[] | null>(null)
  const [planName, setPlanName] = useState<string>('Free')
  const [scansUsed, setScansUsed] = useState<number | null>(null)
  const [scansLimit, setScansLimit] = useState<number | null>(null)

  // Pull the current user's plan to know which profiles to unlock,
  // and the current 30-day scan usage so we can show a meter + block
  // the button when the cap is already reached.
  useEffect(() => {
    api.billing.subscription()
      .then(async sub => {
        const plans = await api.billing.plans()
        const my = plans.find(p => p.tier === sub.plan)
        setAllowedProfiles(my?.scan_profiles_allowed ?? ['quick'])
        setPlanName(my?.name ?? 'Free')
        setScansUsed(sub.usage?.scans_used_30d ?? null)
        setScansLimit(sub.usage?.scans_limit ?? null)
        // If the default 'quick' isn't allowed (shouldn't happen but
        // defensive), pick the first allowed.
        if (my && !my.scan_profiles_allowed.includes(profile)) {
          const first = my.scan_profiles_allowed.find(p => p !== 'monitor')
          if (first) setProfile(first as ScanProfile)
        }
      })
      .catch(() => {
        // Couldn't load — assume Free defaults so we don't accidentally
        // let unauthed users pick deep.
        setAllowedProfiles(['quick'])
      })
  }, [websiteId])  // eslint-disable-line react-hooks/exhaustive-deps

  const quotaExhausted =
    scansUsed !== null && scansLimit !== null && scansUsed >= scansLimit

  async function handleStart() {
    if (allowedProfiles && !allowedProfiles.includes(profile)) {
      setError(`The ${profile} profile isn't on your ${planName} plan. Upgrade or pick a lighter profile.`)
      return
    }
    if (quotaExhausted) {
      setError(
        `You've used all ${scansLimit} scans on your ${planName} plan in the last 30 days. ` +
        `Upgrade for more scans or wait for the window to roll over.`,
      )
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      const job = await api.scanJobs.create(websiteId, profile, {
        save_baseline: saveBaseline,
        use_latest_baseline: useLatestBaseline,
      })
      onStarted(job)
    } catch (err: unknown) {
      // Surface server quota errors directly (HTTP 402 → message).
      const detail = (err as { data?: { detail?: unknown } }).data?.detail
      const msg =
        (detail && typeof detail === 'object' && 'message' in detail
          && typeof (detail as { message?: unknown }).message === 'string')
          ? (detail as { message: string }).message
        : err instanceof Error ? err.message
        : 'Failed to start scan.'
      setError(msg)
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-4">
      {/* Profile selector */}
      <div>
        <p className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">
          Scan Profile
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {USER_PROFILES.map(p => {
            const locked = allowedProfiles !== null
              && !allowedProfiles.includes(p.value)
            const active = profile === p.value
            return (
              <button
                key={p.value}
                type="button"
                onClick={() => !locked && setProfile(p.value)}
                disabled={locked}
                className={cn(
                  'relative text-left p-3 rounded-lg border transition-colors',
                  locked
                    ? 'cursor-not-allowed'
                    : active
                      ? 'border-accent-green bg-accent-green/5 text-white'
                      : 'border-app-border text-gray-400 hover:border-app-border-subtle hover:text-gray-300',
                )}
                style={locked ? {
                  background: 'rgba(255,255,255,0.015)',
                  borderColor: 'rgba(255,255,255,0.06)',
                  color: 'rgba(255,255,255,0.32)',
                } : undefined}
              >
                <div className="flex items-center gap-1.5">
                  <span className="text-sm font-medium font-mono">{p.label}</span>
                  {locked && <Lock className="w-3 h-3" style={{ color: '#f97316' }} />}
                </div>
                <div className="text-xs mt-0.5"
                     style={{ color: locked ? 'rgba(255,255,255,0.22)' : undefined }}>
                  {p.description}
                </div>
                {locked && (
                  <div className="text-[10px] font-semibold mt-1 flex items-center gap-1"
                       style={{ color: '#f97316' }}>
                    <Sparkles className="w-2.5 h-2.5" />
                    Requires upgrade
                  </div>
                )}
              </button>
            )
          })}
        </div>
        {allowedProfiles && USER_PROFILES.some(p => !allowedProfiles.includes(p.value)) && (
          <p className="text-[11px] mt-2" style={{ color: 'rgba(255,255,255,0.4)' }}>
            On the <span className="text-white">{planName}</span> plan.{' '}
            <Link href="/pricing" className="hover:underline" style={{ color: '#8BFF3E' }}>
              Upgrade to unlock more profiles →
            </Link>
          </p>
        )}
      </div>

      {/* Options */}
      <div>
        <p className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">Options</p>
        <div className="space-y-2">
          <label className="flex items-center gap-3 cursor-pointer group">
            <input
              type="checkbox"
              checked={saveBaseline}
              onChange={e => setSaveBaseline(e.target.checked)}
              className="w-4 h-4 rounded border-app-border bg-app-bg accent-accent-green"
            />
            <span className="text-sm text-gray-300 group-hover:text-white transition-colors">
              Save as baseline
            </span>
          </label>
          <label className="flex items-center gap-3 cursor-pointer group">
            <input
              type="checkbox"
              checked={useLatestBaseline}
              onChange={e => setUseLatestBaseline(e.target.checked)}
              className="w-4 h-4 rounded border-app-border bg-app-bg accent-accent-green"
            />
            <span className="text-sm text-gray-300 group-hover:text-white transition-colors">
              Compare against latest baseline
            </span>
          </label>
        </div>
      </div>

      {/* Quota meter */}
      {scansUsed !== null && scansLimit !== null && (
        <div className="text-[11px] flex items-center justify-between"
             style={{ color: 'rgba(255,255,255,0.45)' }}>
          <span>
            <span className="text-white">{scansUsed}</span>
            {' / '}
            <span className="text-white">{scansLimit}</span>
            {' scans used (30 days)'}
          </span>
          {quotaExhausted && (
            <Link href="/pricing" className="hover:underline"
                  style={{ color: '#f97316' }}>
              Limit reached — upgrade →
            </Link>
          )}
        </div>
      )}

      {error && (
        <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
          {error}
        </p>
      )}

      <Button
        onClick={handleStart}
        disabled={submitting || quotaExhausted}
        className="w-full"
      >
        <Play className="w-4 h-4 mr-2" />
        {submitting ? 'Starting…' : quotaExhausted ? 'Monthly limit reached' : 'Start Scan'}
      </Button>
    </div>
  )
}
