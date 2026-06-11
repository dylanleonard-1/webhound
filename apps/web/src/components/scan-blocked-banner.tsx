'use client'

import { useEffect, useState } from 'react'
import { ShieldAlert, Loader2, LifeBuoy } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'

// Scan-time blocked popup: when the latest scan/validation came back blocked by a
// provider challenge (e.g. Vercel), surface it with a "Create ticket for assistance"
// action that files a support ticket (reusing the existing system). Read-only fetch;
// hides itself when nothing is blocking.
export function ScanBlockedBanner({
  websiteId, latestScanId,
}: { websiteId: string; latestScanId?: string | null }) {
  const [blocker, setBlocker] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [done, setDone] = useState<string | null>(null)
  const [dismissed, setDismissed] = useState(false)

  useEffect(() => {
    let active = true
    api.websites.cloudflareScannerAccessStatus(websiteId)
      .then((d) => {
        // Blocked when another provider is the wall, or CF rules aren't resolving it.
        const blocking = d?.cloudflare_scanner_access === 'blocked_by_other_provider'
          || (!!d?.blocker && d.blocker !== 'cloudflare')
        if (active) setBlocker(blocking ? (d.blocker ?? 'a security challenge') : null)
      })
      .catch(() => { /* no diagnosis -> no banner */ })
    return () => { active = false }
  }, [websiteId])

  if (!blocker || dismissed) return null

  const who = blocker.charAt(0).toUpperCase() + blocker.slice(1)

  async function createTicket() {
    setSubmitting(true)
    try {
      const t = await api.createTicket({
        kind: 'scan_blocked',
        subject: `Scan blocked by ${who}`,
        description: `The scan was blocked by ${who} on this website. Requesting assistance to allow the WebHound scanner.`,
        website_id: websiteId,
        scan_id: latestScanId ?? undefined,
        blocker,
      })
      setDone(t.number)
      toast.success(`Support ticket ${t.number} created — we’ll help you get the scanner allowlisted.`)
    } catch (e) {
      toast.error((e as Error)?.message || 'Could not create the support ticket.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="rounded-xl p-4" style={{ background: 'rgba(249,115,22,0.07)', border: '1px solid rgba(249,115,22,0.3)' }}>
      <div className="flex items-start gap-2.5">
        <ShieldAlert className="w-4 h-4 mt-0.5 flex-shrink-0" style={{ color: '#f97316' }} />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-white">Your scan was blocked by {who}</p>
          <p className="text-xs text-gray-300 mt-1 leading-relaxed">
            {who} served a security challenge to the WebHound scanner, so coverage is limited.
            We can help you allowlist the scanner.
          </p>
          <div className="mt-3 flex items-center gap-3 flex-wrap">
            {done ? (
              <span className="text-[12px] text-[#8BFF3E]">Ticket {done} created — support will follow up.</span>
            ) : (
              <Button onClick={createTicket} disabled={submitting} className="h-8 px-3 text-[12px]">
                {submitting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <><LifeBuoy className="w-3.5 h-3.5 mr-1" /> Create ticket for assistance</>}
              </Button>
            )}
            <button
              type="button"
              onClick={() => setDismissed(true)}
              className="text-[11px] text-gray-500 hover:text-gray-300"
            >
              Dismiss
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
