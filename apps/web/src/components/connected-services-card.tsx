'use client'

import { useCallback, useEffect, useState } from 'react'
import { Plug, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { api, type CloudflareScannerAccessView } from '@/lib/api'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'

// Connected Services — provider connection management, available ANY time (not on the
// onboarding card, which hides at 100%). Wires the existing disconnect endpoints:
// Cloudflare scanner-access disconnect (removes rules + reverts) and trusted-access
// revoke. Per-website (disconnect endpoints are website-scoped).
export function ConnectedServicesCard({ websiteId }: { websiteId: string }) {
  const [cf, setCf] = useState<CloudflareScannerAccessView | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const load = useCallback(() => {
    api.websites.cloudflareScannerAccessStatus(websiteId)
      .then(setCf).catch(() => setCf(null))
  }, [websiteId])
  useEffect(() => { load() }, [load])

  if (!cf?.cloudflare_connected) return null

  async function disconnectCloudflare() {
    if (!confirm('Disconnect Cloudflare? This removes the WebHound scanner rules and revokes access.')) return
    setBusy('cloudflare')
    try {
      await api.websites.cloudflareScannerAccessDisconnect(websiteId)
      await api.websites.trustedAccessRevoke(websiteId).catch(() => null)
      toast.success('Cloudflare disconnected.')
      load()
    } catch (e) {
      toast.error((e as Error)?.message || 'Could not disconnect Cloudflare.')
    } finally {
      setBusy(null)
    }
  }

  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-3">
        <Plug className="w-4 h-4 text-gray-400" />
        <h2 className="font-medium text-white">Connected Services</h2>
      </div>
      <div className="flex items-center justify-between gap-3 rounded-lg bg-white/5 p-3">
        <div>
          <p className="text-[13px] text-white">Cloudflare</p>
          <p className="text-[11px] text-gray-500">
            Scanner access: {cf.cloudflare_scanner_access.replace(/_/g, ' ')}
          </p>
        </div>
        <Button
          variant="danger"
          onClick={disconnectCloudflare}
          disabled={busy === 'cloudflare'}
          className="h-8 px-3 text-[12px]"
        >
          {busy === 'cloudflare' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Disconnect'}
        </Button>
      </div>
    </Card>
  )
}
