'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter, useParams } from 'next/navigation'
import {
  ArrowLeft, Globe, ExternalLink, Trash2,
  ScanLine, Clock, CheckCircle, XCircle, Loader2, ChevronRight,
  ShieldCheck, Copy, Check, RefreshCw,
} from 'lucide-react'
import { toast } from 'sonner'
import { api, type WebsiteResponse, type ScanJobResponse } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ScanLaunchForm } from '@/components/scan-launch-form'
import { LoadingState } from '@/components/loading-state'
import { ErrorState } from '@/components/error-state'
import { EmptyState } from '@/components/empty-state'

type VerifyMethod = 'dns_txt' | 'meta_tag' | 'html_file'

const METHOD_INFO: Record<VerifyMethod, { label: string; audience: string; desc: string }> = {
  dns_txt:   { label: 'DNS Record',   audience: 'Best for domain owners', desc: 'Add a TXT record to your domain. Works even if the site is down.' },
  html_file: { label: 'HTML File',    audience: 'Best for developers',    desc: 'Upload a small text file to your web server.' },
  meta_tag:  { label: 'Meta Tag',     audience: 'Best for CMS users',     desc: 'Paste one line of code into your homepage.' },
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  function handle() {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button onClick={handle} className="p-1.5 rounded-md transition-colors hover:bg-white/10"
            style={{ color: copied ? '#8BFF3E' : 'rgba(255,255,255,0.4)' }}>
      {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  )
}

function VerificationCard({ site, onVerified }: { site: WebsiteResponse; onVerified: () => void }) {
  const [method, setMethod] = useState<VerifyMethod>('dns_txt')
  const [token, setToken] = useState<string | null>(null)
  const [step, setStep] = useState<'pick' | 'instructions' | 'checking' | 'failed'>('pick')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleStart() {
    setLoading(true)
    setError(null)
    try {
      const res = await api.websites.verifyInitiate(site.id, method)
      if (res.already_verified) { onVerified(); return }
      setToken(res.token)
      setStep('instructions')
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to start verification')
    } finally {
      setLoading(false)
    }
  }

  async function handleCheck() {
    setStep('checking')
    setError(null)
    try {
      const res = await api.websites.verifyCheck(site.id)
      if (res.verified) {
        onVerified()
      } else {
        setStep('failed')
        setError('Verification check failed. Make sure you completed the step below, then try again.')
      }
    } catch (e: unknown) {
      setStep('failed')
      setError(e instanceof Error ? e.message : 'Check failed')
    }
  }

  const codeStyle: React.CSSProperties = {
    background: 'rgba(255,255,255,0.04)',
    border: '1px solid rgba(255,255,255,0.08)',
  }

  function Instructions() {
    if (!token) return null
    if (method === 'dns_txt') return (
      <div className="space-y-3 text-[12.5px]">
        <p style={{ color: 'rgba(255,255,255,0.55)' }}>
          Log in to wherever you manage your domain (GoDaddy, Namecheap, Cloudflare, etc.) and add this DNS record:
        </p>
        <div className="rounded-xl p-3.5 space-y-2" style={codeStyle}>
          {[
            { label: 'Type', value: 'TXT' },
            { label: 'Name / Host', value: `_webhound-verify.${site.hostname}` },
            { label: 'Value', value: token },
            { label: 'TTL', value: '300' },
          ].map(({ label, value }) => (
            <div key={label} className="flex items-center justify-between gap-3">
              <span style={{ color: 'rgba(255,255,255,0.4)' }} className="w-28 flex-shrink-0">{label}</span>
              <span className="font-mono text-white flex-1 truncate">{value}</span>
              <CopyButton text={value} />
            </div>
          ))}
        </div>
        <p style={{ color: 'rgba(255,255,255,0.35)' }}>DNS changes can take up to 5 minutes to propagate.</p>
      </div>
    )
    if (method === 'html_file') return (
      <div className="space-y-3 text-[12.5px]">
        <p style={{ color: 'rgba(255,255,255,0.55)' }}>
          Create a file called <span className="font-mono text-white">webhound-verify.txt</span> and upload it to:
        </p>
        <div className="rounded-xl p-3.5 flex items-center justify-between gap-3" style={codeStyle}>
          <span className="font-mono text-white truncate">{site.url.replace(/\/$/, '')}/.well-known/webhound-verify.txt</span>
          <CopyButton text={`${site.url.replace(/\/$/, '')}/.well-known/webhound-verify.txt`} />
        </div>
        <p style={{ color: 'rgba(255,255,255,0.4)' }}>File contents must be exactly:</p>
        <div className="rounded-xl p-3.5 flex items-center justify-between gap-3" style={codeStyle}>
          <span className="font-mono text-white">{token}</span>
          <CopyButton text={token} />
        </div>
      </div>
    )
    return (
      <div className="space-y-3 text-[12.5px]">
        <p style={{ color: 'rgba(255,255,255,0.55)' }}>
          Paste this tag inside the <span className="font-mono text-white">&lt;head&gt;</span> section of your homepage:
        </p>
        <div className="rounded-xl p-3.5 flex items-center justify-between gap-3" style={codeStyle}>
          <span className="font-mono text-[11px] text-white break-all">{`<meta name="webhound-site-verification" content="${token}">`}</span>
          <CopyButton text={`<meta name="webhound-site-verification" content="${token}">`} />
        </div>
      </div>
    )
  }

  return (
    <Card className="p-5 col-span-2">
      <div className="flex items-center gap-2 mb-4">
        <ShieldCheck className="w-4 h-4" style={{ color: '#f97316' }} />
        <h2 className="font-medium text-white">Verify Ownership</h2>
      </div>

      {step === 'pick' && (
        <div className="space-y-4">
          <p className="text-[12.5px]" style={{ color: 'rgba(255,255,255,0.45)' }}>
            Choose how you want to prove you own <span className="text-white font-mono">{site.hostname}</span>:
          </p>
          <div className="grid gap-2 sm:grid-cols-3">
            {(Object.entries(METHOD_INFO) as [VerifyMethod, typeof METHOD_INFO[VerifyMethod]][]).map(([key, info]) => (
              <button
                key={key}
                onClick={() => setMethod(key)}
                className="text-left p-3.5 rounded-xl transition-all"
                style={{
                  background: method === key ? 'rgba(139,255,62,0.06)' : 'rgba(255,255,255,0.03)',
                  border: `1px solid ${method === key ? 'rgba(139,255,62,0.25)' : 'rgba(255,255,255,0.07)'}`,
                }}
              >
                <p className="text-[12.5px] font-semibold text-white mb-0.5">{info.label}</p>
                <p className="text-[11px] mb-1.5" style={{ color: '#8BFF3E' }}>{info.audience}</p>
                <p className="text-[11px]" style={{ color: 'rgba(255,255,255,0.4)' }}>{info.desc}</p>
              </button>
            ))}
          </div>
          {error && <p className="text-[12px] text-red-400">{error}</p>}
          <button
            onClick={handleStart}
            disabled={loading}
            className="flex items-center gap-2 h-9 px-4 rounded-xl text-[12.5px] font-semibold text-[#020617] disabled:opacity-50"
            style={{ background: '#8BFF3E' }}
          >
            {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            Continue with {METHOD_INFO[method].label}
          </button>
        </div>
      )}

      {(step === 'instructions' || step === 'failed') && token && (
        <div className="space-y-4">
          <Instructions />
          {error && <p className="text-[12px] text-red-400">{error}</p>}
          <div className="flex items-center gap-3">
            <button
              onClick={handleCheck}
              className="flex items-center gap-2 h-9 px-4 rounded-xl text-[12.5px] font-semibold text-[#020617]"
              style={{ background: '#8BFF3E' }}
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Check now
            </button>
            <button
              onClick={() => { setStep('pick'); setToken(null); setError(null) }}
              className="text-[12px] transition-opacity hover:opacity-70"
              style={{ color: 'rgba(255,255,255,0.4)' }}
            >
              Change method
            </button>
          </div>
        </div>
      )}

      {step === 'checking' && (
        <div className="flex items-center gap-2 text-[12.5px]" style={{ color: 'rgba(255,255,255,0.5)' }}>
          <Loader2 className="w-4 h-4 animate-spin text-accent-green" />
          Checking verification…
        </div>
      )}
    </Card>
  )
}

const VERIFICATION_STYLE: Record<string, string> = {
  verified: 'bg-accent-green/10 text-accent-green border-accent-green/20',
  pending: 'bg-accent-blue/10 text-accent-blue border-accent-blue/20',
  failed: 'bg-red-500/10 text-red-400 border-red-500/20',
  unverified: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
}

const SCAN_STATUS_STYLE: Record<string, { label: string; className: string; icon: React.FC<{ className?: string }> }> = {
  queued: { label: 'Queued', className: 'bg-gray-500/10 text-gray-400 border-gray-500/20', icon: Clock },
  running: { label: 'Running', className: 'bg-accent-blue/10 text-accent-blue border-accent-blue/20', icon: Loader2 },
  completed: { label: 'Completed', className: 'bg-accent-green/10 text-accent-green border-accent-green/20', icon: CheckCircle },
  failed: { label: 'Failed', className: 'bg-red-500/10 text-red-400 border-red-500/20', icon: XCircle },
  cancelled: { label: 'Cancelled', className: 'bg-gray-500/10 text-gray-400 border-gray-500/20', icon: XCircle },
}

function formatDate(s: string) {
  return new Date(s).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export default function WebsiteDetailPage() {
  const params = useParams()
  const id = params.id as string
  const router = useRouter()

  const [site, setSite] = useState<WebsiteResponse | null>(null)
  const [scans, setScans] = useState<ScanJobResponse[]>([])
  const [siteLoading, setSiteLoading] = useState(true)
  const [scansLoading, setScansLoading] = useState(true)
  const [siteError, setSiteError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)

  async function loadSite() {
    setSiteLoading(true)
    setSiteError(null)
    try {
      const w = await api.websites.get(id)
      setSite(w)
    } catch {
      setSiteError('Website not found.')
    } finally {
      setSiteLoading(false)
    }
  }

  async function loadScans() {
    setScansLoading(true)
    try {
      const res = await api.scanJobs.list({ website_id: id, limit: 20 })
      setScans(res.items)
    } catch {
      // non-critical
    } finally {
      setScansLoading(false)
    }
  }

  useEffect(() => {
    loadSite()
    loadScans()
  }, [id])

  async function handleDelete() {
    if (!confirm(`Remove ${site?.hostname ?? 'this website'}? This cannot be undone.`)) return
    setDeleting(true)
    try {
      await api.websites.delete(id)
      toast.success('Website removed.')
      router.replace('/dashboard/websites')
    } catch (e: unknown) {
      // Surface the actual API error so the user can see what failed
      // instead of the previous silent "Failed to delete website." alert.
      const status = (e as { status?: number }).status
      const data = (e as { data?: { detail?: unknown } }).data
      const detail = data?.detail
      const msg =
        typeof detail === 'string' ? detail
        : (detail && typeof detail === 'object' && 'message' in detail
            && typeof (detail as { message?: unknown }).message === 'string')
          ? (detail as { message: string }).message
        : e instanceof Error ? e.message
        : 'Could not remove this website.'
      toast.error(
        status ? `Delete failed (HTTP ${status}): ${msg}` : `Delete failed: ${msg}`,
      )
      setDeleting(false)
    }
  }

  function handleScanStarted(job: ScanJobResponse) {
    router.push(`/dashboard/scans/${job.id}`)
  }

  if (siteLoading) {
    return (
      <div className="p-4 sm:p-6">
        <LoadingState />
      </div>
    )
  }

  if (siteError || !site) {
    return (
      <div className="p-4 sm:p-6">
        <ErrorState message={siteError ?? 'Website not found.'} />
        <div className="mt-4 flex justify-center">
          <Button variant="ghost" asChild>
            <Link href="/dashboard/websites">
              <ArrowLeft className="w-4 h-4 mr-1.5" />
              Back to Websites
            </Link>
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-3xl">
      {/* Back */}
      <Button variant="ghost" size="sm" asChild>
        <Link href="/dashboard/websites">
          <ArrowLeft className="w-4 h-4 mr-1" />
          Websites
        </Link>
      </Button>

      {/* Website header */}
      <Card className="p-5">
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 rounded-lg bg-app-bg border border-app-border flex items-center justify-center flex-shrink-0 mt-0.5">
            <Globe className="w-5 h-5 text-gray-400" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-lg font-semibold text-white font-mono">{site.hostname}</h1>
              <Badge className={VERIFICATION_STYLE[site.verification_status]}>
                {site.verification_status}
              </Badge>
            </div>
            <div className="flex items-center gap-3 mt-1 flex-wrap">
              <a
                href={site.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-gray-400 hover:text-accent-blue flex items-center gap-1 transition-colors font-mono"
              >
                {site.url}
                <ExternalLink className="w-3 h-3" />
              </a>
              {site.display_name && (
                <span className="text-xs text-gray-500">{site.display_name}</span>
              )}
            </div>
            <p className="text-xs text-gray-600 mt-1">Added {formatDate(site.created_at)}</p>
          </div>
          <Button
            variant="danger"
            size="sm"
            onClick={handleDelete}
            disabled={deleting}
            className="flex-shrink-0"
          >
            <Trash2 className="w-3.5 h-3.5 mr-1" />
            {deleting ? 'Removing…' : 'Remove'}
          </Button>
        </div>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Verification — shown until verified */}
        {site.verification_status !== 'verified' && (
          <VerificationCard
            site={site}
            onVerified={() => setSite(s => s ? { ...s, verification_status: 'verified' } : s)}
          />
        )}

        {/* Start scan */}
        <Card className="p-5">
          <div className="flex items-center gap-2 mb-4">
            <ScanLine className="w-4 h-4 text-accent-green" />
            <h2 className="font-medium text-white">Start Scan</h2>
          </div>
          <ScanLaunchForm websiteId={id} onStarted={handleScanStarted} />
        </Card>

        {/* Scan history */}
        <Card className="p-5">
          <div className="flex items-center gap-2 mb-4">
            <Clock className="w-4 h-4 text-gray-400" />
            <h2 className="font-medium text-white">Scan History</h2>
          </div>

          {scansLoading ? (
            <LoadingState />
          ) : scans.length === 0 ? (
            <EmptyState
              title="No scans yet"
              description="Run your first scan to see history here."
            />
          ) : (
            <div className="space-y-1.5">
              {scans.map(job => {
                const cfg = SCAN_STATUS_STYLE[job.status] ?? SCAN_STATUS_STYLE.queued
                const Icon = cfg.icon
                return (
                  <Link key={job.id} href={`/dashboard/scans/${job.id}`}>
                    <div className="flex items-center gap-3 p-2 rounded-lg hover:bg-white/5 transition-colors cursor-pointer">
                      <Icon
                        className={`w-3.5 h-3.5 flex-shrink-0 ${
                          job.status === 'running' ? 'animate-spin text-accent-blue' : 'text-gray-400'
                        }`}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5">
                          <Badge className={`${cfg.className} text-[10px] py-0`}>{cfg.label}</Badge>
                          <Badge className="bg-gray-500/10 text-gray-500 border-gray-500/20 text-[10px] py-0">
                            {job.profile}
                          </Badge>
                        </div>
                        <span className="text-[11px] text-gray-600">{formatDate(job.created_at)}</span>
                      </div>
                      <ChevronRight className="w-3.5 h-3.5 text-gray-600 flex-shrink-0" />
                    </div>
                  </Link>
                )
              })}
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
