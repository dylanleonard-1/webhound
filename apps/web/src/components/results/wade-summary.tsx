import { Waves, AlertTriangle, CheckCircle, Info } from 'lucide-react'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

interface WADESummaryProps {
  metadata: Record<string, unknown> | null
}

export function WADESummary({ metadata }: WADESummaryProps) {
  if (!metadata) return null

  const anomalyCount = (metadata.wade_anomaly_count as number | undefined) ?? 0
  const baselineGenerated = metadata.wade_baseline_generated as boolean | undefined
  const comparedToBaseline = metadata.wade_compared_to_previous as boolean | undefined
  const anomalies = metadata.wade_anomalies as Array<{ url?: string; score?: number; type?: string }> | undefined

  if (baselineGenerated === undefined) return null

  const hasAnomalies = anomalyCount > 0

  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-4">
        <Waves className="w-4 h-4 text-accent-blue" />
        <h2 className="font-medium text-white">Behavioral Analysis</h2>
        <span className="text-xs text-gray-500">Detects structural changes between scans</span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
        {/* Baseline card */}
        <div className={cn(
          'rounded-lg p-3 border',
          baselineGenerated
            ? 'bg-accent-green/5 border-accent-green/20'
            : 'bg-gray-500/5 border-gray-500/20',
        )}>
          <div className="flex items-center gap-1.5 mb-1">
            {baselineGenerated
              ? <CheckCircle className="w-3.5 h-3.5 text-accent-green" />
              : <Info className="w-3.5 h-3.5 text-gray-500" />
            }
            <span className="text-xs font-medium text-gray-300">Site Snapshot</span>
          </div>
          <p className="text-[11px] text-gray-400 leading-relaxed">
            {baselineGenerated
              ? 'A behavioral baseline was captured from this scan and saved for future comparison.'
              : 'No baseline was captured — the crawl returned no pages.'
            }
          </p>
        </div>

        {/* Comparison card */}
        <div className={cn(
          'rounded-lg p-3 border',
          comparedToBaseline
            ? 'bg-accent-blue/5 border-accent-blue/20'
            : 'bg-gray-500/5 border-gray-500/20',
        )}>
          <div className="flex items-center gap-1.5 mb-1">
            {comparedToBaseline
              ? <CheckCircle className="w-3.5 h-3.5 text-accent-blue" />
              : <Info className="w-3.5 h-3.5 text-gray-500" />
            }
            <span className="text-xs font-medium text-gray-300">Change Detection</span>
          </div>
          <p className="text-[11px] text-gray-400 leading-relaxed">
            {comparedToBaseline
              ? 'This scan was compared against a previous baseline to identify changes.'
              : 'No previous baseline existed — run a second scan to enable change detection.'
            }
          </p>
        </div>

        {/* Anomaly card */}
        <div className={cn(
          'rounded-lg p-3 border',
          !comparedToBaseline
            ? 'bg-gray-500/5 border-gray-500/20'
            : hasAnomalies
              ? 'bg-yellow-500/5 border-yellow-500/20'
              : 'bg-accent-green/5 border-accent-green/20',
        )}>
          <div className="flex items-center gap-1.5 mb-1">
            {!comparedToBaseline
              ? <Info className="w-3.5 h-3.5 text-gray-500" />
              : hasAnomalies
                ? <AlertTriangle className="w-3.5 h-3.5 text-yellow-400" />
                : <CheckCircle className="w-3.5 h-3.5 text-accent-green" />
            }
            <span className="text-xs font-medium text-gray-300">Anomalies</span>
            {comparedToBaseline && (
              <Badge className={cn(
                'text-[10px] ml-auto',
                hasAnomalies
                  ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
                  : 'bg-accent-green/10 text-accent-green border-accent-green/20',
              )}>
                {anomalyCount}
              </Badge>
            )}
          </div>
          <p className="text-[11px] text-gray-400 leading-relaxed">
            {!comparedToBaseline
              ? 'Available after a second scan runs against the saved baseline.'
              : hasAnomalies
                ? `${anomalyCount} page${anomalyCount !== 1 ? 's' : ''} changed significantly since the last scan. Review for unexpected modifications.`
                : 'No significant changes detected since the previous scan.'
            }
          </p>
        </div>
      </div>

      {/* Anomaly list */}
      {hasAnomalies && anomalies && anomalies.length > 0 && (
        <div>
          <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Changed Pages</p>
          <div className="space-y-1.5">
            {anomalies.slice(0, 5).map((a, i) => (
              <div key={i} className="flex items-center gap-2 text-xs bg-yellow-500/5 border border-yellow-500/10 rounded px-2.5 py-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 flex-shrink-0" />
                <span className="text-gray-400 font-mono truncate flex-1">{a.url ?? a.type ?? 'Unknown page'}</span>
                {a.score !== undefined && (
                  <span className="font-mono text-yellow-400 flex-shrink-0 text-[11px]">
                    score {a.score.toFixed(2)}
                  </span>
                )}
              </div>
            ))}
            {anomalyCount > 5 && (
              <p className="text-[11px] text-gray-500 pl-1">+ {anomalyCount - 5} more changed pages</p>
            )}
          </div>
        </div>
      )}
    </Card>
  )
}
