'use client'

import { useEffect, useState } from 'react'
import { ShieldAlert, Loader2, LifeBuoy, X } from 'lucide-react'
import { toast } from 'sonner'
import { api, type CloudflareScannerAccessView } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { scanBlockedView } from '@/lib/scan-blocked'

// Scan-time blocked POPUP (modal-style): when the latest scan was blocked by a
// provider challenge, surface it prominently. Names the provider ONLY when detection
// confidence is high; otherwise a generic message. Always offers "Create ticket for
// assistance". Read-only fetch; nothing rendered when not blocking.
export function ScanBlockedBanner({
  websiteId, latestScanId,
}: { websiteId: string; latestScanId?: string | null }) {
  const [diag, setDiag] = useState<CloudflareScannerAccessView | null>(null)
  const [validationStatus, setValidationStatus] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [done, setDone] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    // Only show after a COMPLETED scan that's blocked/limited — gate on the access
    // validation status ('limited'/'failed'); 'pending' (no scan) / 'ready' (clean)
    // must NOT trigger the popup.
    Promise.all([
      api.websites.accessValidation(websiteId).catch(() => null),
      api.websites.cloudflareScannerAccessStatus(websiteId).catch(() => null),
    ]).then(([val, d]) => {
      if (!active) return
      setValidationStatus(val?.status ?? null)
      setDiag(d)
      if (scanBlockedView(d, val?.status).blocked) setOpen(true)
    })
    return () => { active = false }
  }, [websiteId])

  const view = scanBlockedView(diag, validationStatus)
  if (!view.blocked || !open) return null

  async function createTicket() {
    setSubmitting(true)
    try {
      const t = await api.createTicket({
        kind: 'scan_blocked',
        subject: view.provider ? `Scan blocked by ${view.provider}` : 'Scan blocked / limited',
        description: view.body,
        website_id: websiteId,
        scan_id: latestScanId ?? undefined,
        blocker: view.ticketBlocker,
        diagnosis: diag?.diagnosis ?? undefined,
        evidence: diag?.evidence ?? undefined,
      })
      setDone(t.number)
      toast.success(`Support ticket ${t.number} created — we’ll help you allowlist the scanner.`)
    } catch (e) {
      toast.error((e as Error)?.message || 'Could not create the support ticket.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
         style={{ background: 'rgba(2,6,23,0.7)' }}
         role="dialog" aria-modal="true">
      <div className="w-full max-w-md rounded-2xl p-5"
           style={{ background: '#0b1120', border: '1px solid rgba(249,115,22,0.35)' }}>
        <div className="flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 mt-0.5 flex-shrink-0" style={{ color: '#f97316' }} />
          <div className="flex-1 min-w-0">
            <div className="flex items-start justify-between gap-2">
              <h2 className="text-base font-semibold text-white">{view.title}</h2>
              <button onClick={() => setOpen(false)} className="text-gray-500 hover:text-gray-300" aria-label="Close">
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-sm text-gray-300 mt-2 leading-relaxed">{view.body}</p>
            <div className="mt-4 flex items-center gap-3 flex-wrap">
              {done ? (
                <span className="text-[13px] text-[#8BFF3E]">Ticket {done} created — support will follow up.</span>
              ) : (
                <Button onClick={createTicket} disabled={submitting}>
                  {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <><LifeBuoy className="w-4 h-4 mr-1.5" /> Create ticket for assistance</>}
                </Button>
              )}
              <button type="button" onClick={() => setOpen(false)}
                      className="text-xs text-gray-500 hover:text-gray-300">
                Dismiss
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
