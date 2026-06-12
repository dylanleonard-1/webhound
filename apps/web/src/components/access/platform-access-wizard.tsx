'use client'

import { useEffect, useState } from 'react'
import {
  ShieldCheck, ShieldAlert, Loader2, CheckCircle2, XCircle, Copy, Check,
  ExternalLink, LifeBuoy, Zap,
} from 'lucide-react'
import { api, type PlatformAccessView } from '@/lib/api'

const ACCENT = '#8BFF3E'

// State → presentation. The ONLY place states are interpreted; everything else
// is provider-agnostic data from the server.
const STATE_META: Record<string, { label: string; color: string; icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }> }> = {
  not_required:          { label: 'No action needed',        color: ACCENT,             icon: ShieldCheck },
  detected:              { label: 'Provider detected',       color: '#22d3ee',          icon: ShieldCheck },
  access_required:       { label: 'Scanner access required', color: '#f5c451',          icon: ShieldAlert },
  configuring:           { label: 'Configuring…',            color: '#4F9CF9',          icon: Loader2 },
  verification_running:  { label: 'Verifying access…',       color: '#4F9CF9',          icon: Loader2 },
  verified:              { label: 'Access verified',         color: ACCENT,             icon: CheckCircle2 },
  complete:              { label: 'Access configured',       color: ACCENT,             icon: CheckCircle2 },
  failed:                { label: 'Verification failed',     color: '#ef4444',          icon: XCircle },
  support_required:      { label: 'Support needed',          color: '#f97316',          icon: LifeBuoy },
}

function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(value); setDone(true); setTimeout(() => setDone(false), 1500) }}
      className="inline-flex items-center gap-1 px-2 py-1 rounded-[6px] text-[11px] font-medium transition-colors flex-shrink-0"
      style={{ background: done ? `${ACCENT}1a` : 'rgba(255,255,255,0.05)', border: `1px solid ${done ? ACCENT + '40' : 'rgba(255,255,255,0.1)'}`, color: done ? ACCENT : 'rgba(255,255,255,0.7)' }}
    >
      {done ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
      {done ? 'Copied' : label}
    </button>
  )
}

export function PlatformAccessWizard({ websiteId }: { websiteId: string }) {
  const [view, setView] = useState<PlatformAccessView | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [verifying, setVerifying] = useState(false)

  const load = () => api.websites.platformAccess(websiteId).then(setView).catch(() => setView(null)).finally(() => setLoaded(true))
  useEffect(() => { load() }, [websiteId])

  async function verify() {
    setVerifying(true)
    try { await api.websites.accessValidationRun(websiteId) } catch { /* surfaced via reload */ }
    await load()
    setVerifying(false)
  }

  if (!loaded || !view) return null
  // Nothing to show the customer when access isn't required and nothing's configured.
  if (view.state === 'not_required') return null

  const meta = STATE_META[view.state] ?? STATE_META.access_required
  const Icon = meta.icon
  const rem = view.remediation
  const spinning = view.state === 'configuring' || view.state === 'verification_running' || verifying

  return (
    <div className="rounded-[12px] p-4 space-y-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}>
      {/* Header / state */}
      <div className="flex items-start gap-3">
        <div className="w-9 h-9 rounded-[9px] flex items-center justify-center flex-shrink-0" style={{ background: `${meta.color}14`, border: `1px solid ${meta.color}30` }}>
          <Icon className={`w-4 h-4 ${spinning ? 'animate-spin' : ''}`} style={{ color: meta.color }} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-[14px] font-semibold text-white">{meta.label}</h3>
            {view.provider_name && (
              <span className="text-[10px] px-1.5 py-0.5 rounded-full font-medium" style={{ background: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.6)' }}>{view.provider_name}</span>
            )}
            {view.confidence != null && view.access_required && (
              <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.35)' }}>{view.confidence}% confidence</span>
            )}
          </div>
          {rem && <p className="text-[12px] mt-1" style={{ color: 'rgba(255,255,255,0.6)' }}>{rem.problem}</p>}
          {rem && <p className="text-[11px] mt-1" style={{ color: 'rgba(255,255,255,0.4)' }}>{rem.impact}</p>}
        </div>
      </div>

      {/* Verified / complete */}
      {(view.state === 'verified' || view.state === 'complete') && (
        <p className="text-[12px]" style={{ color: ACCENT }}>The scanner now has access — coverage is confirmed on the next scan.</p>
      )}

      {/* Remediation steps */}
      {rem && (view.state === 'access_required' || view.state === 'failed' || view.state === 'support_required' || view.state === 'configuring') && (
        <div className="space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-white">Steps</span>
            {view.scanner_ips.length > 0 && <CopyButton value={rem.copy_all} label="Copy all IPs" />}
          </div>
          <ol className="space-y-2">
            {rem.steps.map(s => (
              <li key={s.n} className="flex items-start gap-2.5">
                <span className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0 mt-0.5" style={{ background: 'rgba(255,255,255,0.05)', color: 'rgba(255,255,255,0.6)', border: '1px solid rgba(255,255,255,0.1)' }}>{s.n}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-[12px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.75)' }}>{s.text}</p>
                  {s.copyable && s.copy_value && (
                    <div className="flex items-center gap-2 mt-1.5">
                      <code className="text-[11px] font-mono px-2 py-1 rounded-[6px] truncate" style={{ background: 'rgba(0,0,0,0.3)', color: ACCENT, border: '1px solid rgba(139,255,62,0.2)' }}>{s.copy_value}</code>
                      <CopyButton value={s.copy_value} />
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* Actions */}
      <div className="flex flex-wrap items-center gap-2 pt-1">
        {view.can_automate && view.state === 'access_required' && (
          <a href={rem?.support_url ?? '#'} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[8px] text-[12px] font-semibold" style={{ background: ACCENT, color: '#0a0a0a' }}>
            <Zap className="w-3.5 h-3.5" /> Connect {view.provider_name}
          </a>
        )}
        {(view.state === 'access_required' || view.state === 'failed') && (
          <button onClick={verify} disabled={verifying} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[8px] text-[12px] font-semibold transition-colors disabled:opacity-50" style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.12)', color: '#fff' }}>
            {verifying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />} Verify Access
          </button>
        )}
        {(view.state === 'failed' || view.state === 'support_required') && (
          <SupportButton websiteId={websiteId} view={view} onCreated={load} />
        )}
        {rem?.support_url && (
          <a href={rem.support_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-[11px]" style={{ color: 'rgba(255,255,255,0.4)' }}>
            {view.provider_name} docs <ExternalLink className="w-3 h-3" />
          </a>
        )}
      </div>
    </div>
  )
}

function SupportButton({ websiteId, view, onCreated }: { websiteId: string; view: PlatformAccessView; onCreated: () => void }) {
  const [sending, setSending] = useState(false)
  const [sent, setSent] = useState(false)
  async function create() {
    setSending(true)
    try {
      await api.websites.platformAccessSupportTicket(websiteId)
      setSent(true); onCreated()
    } catch { /* noop */ } finally { setSending(false) }
  }
  if (sent) return <span className="text-[11px]" style={{ color: ACCENT }}>Ticket created — we’ll follow up.</span>
  return (
    <button onClick={create} disabled={sending} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[8px] text-[12px] font-semibold disabled:opacity-50" style={{ background: 'rgba(249,115,22,0.12)', border: '1px solid rgba(249,115,22,0.3)', color: '#f97316' }}>
      {sending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <LifeBuoy className="w-3.5 h-3.5" />} Create Support Ticket
    </button>
  )
}
