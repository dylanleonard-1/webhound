import { Globe, Clock, FileSearch, Activity, Link2 } from 'lucide-react'
import { Card } from '@/components/ui/card'
import { cn } from '@/lib/utils'

interface PerformanceSummaryProps {
  pagesCrawled: number
  durationSeconds: number | null
  totalFindings: number
  scanProfile: string
  externalScriptDomainCount?: number
}

function formatDuration(s: number | null) {
  if (s === null) return '—'
  if (s < 60) return `${s.toFixed(1)}s`
  const m = Math.floor(s / 60)
  const rem = (s % 60).toFixed(0).padStart(2, '0')
  return `${m}m ${rem}s`
}

export function PerformanceSummary({
  pagesCrawled,
  durationSeconds,
  totalFindings,
  scanProfile,
  externalScriptDomainCount,
}: PerformanceSummaryProps) {
  const stats: Array<{ icon: React.FC<{ className?: string }>; label: string; value: string; subtitle?: string }> = [
    { icon: Globe, label: 'Pages Crawled', value: pagesCrawled.toLocaleString() },
    { icon: Clock, label: 'Duration', value: formatDuration(durationSeconds) },
    { icon: FileSearch, label: 'Total Findings', value: totalFindings.toLocaleString() },
    { icon: Activity, label: 'Profile', value: scanProfile },
  ]

  if (externalScriptDomainCount !== undefined) {
    stats.push({
      icon: Link2,
      label: 'Ext. Script Domains',
      value: externalScriptDomainCount.toLocaleString(),
      subtitle: externalScriptDomainCount === 0 ? 'none observed' : 'script sources',
    })
  }

  return (
    <Card className="p-5">
      <p className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-4">
        Performance
      </p>
      <div className={cn('grid gap-4', stats.length > 4 ? 'grid-cols-2 sm:grid-cols-3' : 'grid-cols-2')}>
        {stats.map(({ icon: Icon, label, value, subtitle }) => (
          <div key={label}>
            <div className="flex items-center gap-1.5 mb-0.5">
              <Icon className="w-3 h-3 text-gray-500" />
              <span className="text-[11px] text-gray-500">{label}</span>
            </div>
            <span className="text-lg font-semibold font-mono text-white">{value}</span>
            {subtitle && <p className="text-[10px] text-gray-600 mt-0.5">{subtitle}</p>}
          </div>
        ))}
      </div>
    </Card>
  )
}
