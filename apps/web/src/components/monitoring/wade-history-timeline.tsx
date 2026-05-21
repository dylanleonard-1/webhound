'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { Waves, ChevronDown, ChevronRight } from 'lucide-react'
import { api, type WadeHistoryItem } from '@/lib/api'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { LoadingState } from '@/components/loading-state'
import { EmptyState } from '@/components/empty-state'
import { ErrorState } from '@/components/error-state'
import { cn } from '@/lib/utils'

interface WadeHistoryTimelineProps {
  websiteId: string
}

const RISK_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-accent-green',
  none: 'bg-gray-600',
}

const RISK_SCORE_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-accent-green',
  none: 'text-gray-400',
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function TimelineItem({ item, isLast }: { item: WadeHistoryItem; isLast: boolean }) {
  const [expanded, setExpanded] = useState(false)
  const dotColor = RISK_DOT[item.risk_level] ?? RISK_DOT.none
  const scoreColor = RISK_SCORE_COLOR[item.risk_level] ?? RISK_SCORE_COLOR.none
  const hasAnomalies = item.top_anomaly_titles.length > 0

  return (
    <div className="flex gap-4">
      {/* Timeline spine */}
      <div className="flex flex-col items-center flex-shrink-0">
        <div className={cn('w-2.5 h-2.5 rounded-full mt-1 flex-shrink-0', dotColor)} />
        {!isLast && <div className="w-px flex-1 bg-app-border mt-1" />}
      </div>

      {/* Content */}
      <div className={cn('pb-5 flex-1 min-w-0', isLast && 'pb-1')}>
        <div className="flex items-start justify-between gap-2 flex-wrap">
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={cn('text-base font-mono font-bold', scoreColor)}>{item.risk_score}</span>
              <span className="text-xs text-gray-500 font-mono">/100</span>
              {item.anomaly_count > 0 && (
                <Badge className="bg-yellow-500/10 text-yellow-400 border-yellow-500/20 text-[10px]">
                  {item.anomaly_count} anomal{item.anomaly_count === 1 ? 'y' : 'ies'}
                </Badge>
              )}
            </div>
            <p className="text-[11px] text-gray-500 mt-0.5">{formatDate(item.created_at)}</p>
          </div>
          <Link
            href={`/dashboard/results/${item.scan_result_id}`}
            className="text-[11px] text-accent-blue hover:text-accent-blue/80 flex items-center gap-1 flex-shrink-0"
          >
            View <ChevronRight className="w-3 h-3" />
          </Link>
        </div>

        {hasAnomalies && (
          <div className="mt-2">
            <button
              onClick={() => setExpanded(e => !e)}
              className="flex items-center gap-1 text-[11px] text-gray-500 hover:text-gray-300 transition-colors"
            >
              {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
              Top anomalies
            </button>
            {expanded && (
              <ul className="mt-1.5 space-y-1 pl-1">
                {item.top_anomaly_titles.map((t, i) => (
                  <li key={i} className="flex items-start gap-2 text-[11px] text-gray-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-yellow-500/60 flex-shrink-0 mt-1" />
                    {t}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export function WadeHistoryTimeline({ websiteId }: WadeHistoryTimelineProps) {
  const [items, setItems] = useState<WadeHistoryItem[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  const LIMIT = 10

  const load = useCallback(async () => {
    setLoading(true)
    setError(false)
    setItems([])
    setTotal(0)
    try {
      const r = await api.wade.history(websiteId, { limit: LIMIT, offset: 0 })
      setItems(r.items)
      setTotal(r.total)
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }, [websiteId])

  useEffect(() => { load() }, [load])

  async function loadMore() {
    setLoadingMore(true)
    try {
      const r = await api.wade.history(websiteId, { limit: LIMIT, offset: items.length })
      setItems(prev => [...prev, ...r.items])
    } catch { /* ignore */ } finally {
      setLoadingMore(false)
    }
  }

  return (
    <Card>
      <div className="flex items-center gap-2 p-4 border-b border-app-border">
        <Waves className="w-4 h-4 text-accent-blue" />
        <h2 className="font-medium text-white">WADE History</h2>
        <span className="text-xs text-gray-500">Weighted Anomaly Detection Engine</span>
      </div>

      {loading ? (
        <div className="p-6"><LoadingState /></div>
      ) : error ? (
        <div className="p-6">
          <ErrorState message="Failed to load WADE history." onRetry={load} />
        </div>
      ) : items.length === 0 ? (
        <div className="p-6">
          <EmptyState title="No WADE history" description="Run scans with baseline enabled to build anomaly history." />
        </div>
      ) : (
        <div className="p-5">
          {items.map((item, i) => (
            <TimelineItem key={item.scan_result_id} item={item} isLast={i === items.length - 1} />
          ))}

          {items.length < total && (
            <button
              onClick={loadMore}
              disabled={loadingMore}
              className="mt-2 text-xs text-gray-500 hover:text-gray-300 transition-colors"
            >
              {loadingMore ? 'Loading…' : `Load more (${total - items.length} remaining)`}
            </button>
          )}
        </div>
      )}
    </Card>
  )
}
