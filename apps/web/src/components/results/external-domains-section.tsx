'use client'

import { Globe2, ShieldCheck, AlertTriangle } from 'lucide-react'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import {
  TRUSTED_SCRIPT_DOMAINS,
  getDomainCategory,
  type DomainCategory,
} from '@/lib/trusted-domains'

interface ExternalDomainsSectionProps {
  scriptDomains: string[]
  linkDomains: string[]
}

const CATEGORY_COLOR: Record<DomainCategory, string> = {
  CDN:        'bg-blue-500/10 text-blue-300 border-blue-500/20',
  Analytics:  'bg-purple-500/10 text-purple-300 border-purple-500/20',
  Tracking:   'bg-orange-500/10 text-orange-300 border-orange-500/20',
  Payments:   'bg-green-500/10 text-green-300 border-green-500/20',
  Marketing:  'bg-pink-500/10 text-pink-300 border-pink-500/20',
  Monitoring: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/20',
  Support:    'bg-teal-500/10 text-teal-300 border-teal-500/20',
  Social:     'bg-indigo-500/10 text-indigo-300 border-indigo-500/20',
  Video:      'bg-red-500/10 text-red-300 border-red-500/20',
  Security:   'bg-emerald-500/10 text-emerald-300 border-emerald-500/20',
  CMS:        'bg-violet-500/10 text-violet-300 border-violet-500/20',
  Maps:       'bg-lime-500/10 text-lime-300 border-lime-500/20',
  Community:  'bg-amber-500/10 text-amber-300 border-amber-500/20',
  Unknown:    'bg-yellow-500/10 text-yellow-300 border-yellow-500/20',
}

function classifyDomain(host: string): 'trusted' | 'unknown' {
  const parts = host.split('.')
  for (let i = parts.length - 2; i >= 0; i--) {
    if (TRUSTED_SCRIPT_DOMAINS.has(parts.slice(i).join('.'))) return 'trusted'
  }
  return 'unknown'
}

export function ExternalDomainsSection({
  scriptDomains,
  linkDomains,
}: ExternalDomainsSectionProps) {
  if (scriptDomains.length === 0 && linkDomains.length === 0) return null

  const classified = scriptDomains.map(host => ({
    host,
    trusted: classifyDomain(host) === 'trusted',
    category: getDomainCategory(host),
  }))

  const unknown = classified.filter(d => !d.trusted)
  const trusted = classified.filter(d => d.trusted)

  const trustedByCategory = trusted.reduce<Record<string, typeof trusted>>(
    (acc, d) => {
      const cat = d.category as string
      ;(acc[cat] ??= []).push(d)
      return acc
    },
    {},
  )
  const sortedCategories = Object.keys(trustedByCategory).sort()

  return (
    <Card>
      <div className="flex items-center gap-2 p-4 border-b border-app-border">
        <Globe2 className="w-4 h-4 text-gray-400" />
        <h2 className="font-medium text-white">External Domains Observed</h2>
        {scriptDomains.length > 0 && (
          <Badge className="bg-gray-500/10 text-gray-400 border-gray-500/20">
            {scriptDomains.length} {scriptDomains.length === 1 ? 'source' : 'sources'}
          </Badge>
        )}
      </div>

      <div className="p-4 space-y-5">
        {unknown.length > 0 && (
          <div>
            <div className="flex items-center gap-1.5 mb-2.5">
              <AlertTriangle className="w-3.5 h-3.5 text-yellow-400" />
              <span className="text-xs font-medium text-gray-300">Unrecognized Script Sources</span>
              <span className="text-xs text-gray-500">— verify these are intentional</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {unknown.map(({ host }) => (
                <span
                  key={host}
                  className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded border bg-yellow-500/10 text-yellow-300 border-yellow-500/20"
                >
                  {host}
                </span>
              ))}
            </div>
          </div>
        )}

        {sortedCategories.length > 0 && (
          <div>
            <div className="flex items-center gap-1.5 mb-2.5">
              <ShieldCheck className="w-3.5 h-3.5 text-accent-green" />
              <span className="text-xs font-medium text-gray-300">Recognized Third-Party Services</span>
            </div>
            <div className="space-y-3">
              {sortedCategories.map(cat => (
                <div key={cat}>
                  <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">{cat}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {trustedByCategory[cat].map(({ host, category }) => (
                      <span
                        key={host}
                        className={cn(
                          'inline-flex items-center text-[10px] font-mono px-2 py-0.5 rounded border',
                          CATEGORY_COLOR[category] ?? CATEGORY_COLOR.Unknown,
                        )}
                      >
                        {host}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </Card>
  )
}
