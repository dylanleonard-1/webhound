'use client'

import { useCallback, useEffect, useState } from 'react'
import { Database, Trash2 } from 'lucide-react'
import { api, type BaselineSummary } from '@/lib/api'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { LoadingState } from '@/components/loading-state'
import { EmptyState } from '@/components/empty-state'
import { ErrorState } from '@/components/error-state'

interface BaselineListProps {
  websiteId: string
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

export function BaselineList({ websiteId }: BaselineListProps) {
  const [baselines, setBaselines] = useState<BaselineSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [deleting, setDeleting] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(false)
    try {
      const r = await api.baselines.list(websiteId)
      setBaselines(r.items)
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }, [websiteId])

  useEffect(() => { load() }, [load])

  async function handleDelete(id: string) {
    if (!confirm('Delete this baseline? Anomaly comparisons using it will be affected.')) return
    setDeleting(id)
    try {
      await api.baselines.delete(id)
      setBaselines(prev => prev.filter(b => b.id !== id))
    } catch { /* ignore */ } finally {
      setDeleting(null)
    }
  }

  return (
    <Card>
      <div className="flex items-center gap-2 p-4 border-b border-app-border">
        <Database className="w-4 h-4 text-gray-400" />
        <h2 className="font-medium text-white">Baselines</h2>
        <Badge className="bg-gray-500/10 text-gray-400 border-gray-500/20">{baselines.length}</Badge>
      </div>

      {loading ? (
        <div className="p-6"><LoadingState /></div>
      ) : error ? (
        <div className="p-6">
          <ErrorState message="Failed to load baselines." onRetry={load} />
        </div>
      ) : baselines.length === 0 ? (
        <div className="p-6">
          <EmptyState title="No baselines" description="Enable 'Save baseline' on a scan to create one." />
        </div>
      ) : (
        <>
          <div className="grid grid-cols-[auto_1fr_auto_auto] gap-3 px-4 py-2 border-b border-app-border text-[10px] text-gray-500 uppercase tracking-wider">
            <span className="w-10 text-center">Ver</span>
            <span>Baseline ID</span>
            <span className="hidden sm:block">Created</span>
            <span className="w-6" />
          </div>
          <div className="divide-y divide-app-border">
            {baselines.map((b, i) => (
              <div key={b.id} className="grid grid-cols-[auto_1fr_auto_auto] gap-3 items-center px-4 py-3">
                <div className="w-10 flex justify-center">
                  <Badge className={`text-[10px] ${i === 0 ? 'bg-accent-green/10 text-accent-green border-accent-green/20' : 'bg-gray-500/10 text-gray-400 border-gray-500/20'}`}>
                    v{b.baseline_version}
                  </Badge>
                </div>
                <span className="text-xs font-mono text-gray-400 truncate">{b.baseline_id}</span>
                <span className="text-xs text-gray-500 hidden sm:block">{formatDate(b.created_at)}</span>
                <button
                  onClick={() => handleDelete(b.id)}
                  disabled={deleting === b.id}
                  className="w-6 flex justify-center text-gray-600 hover:text-red-400 transition-colors disabled:opacity-40"
                  title="Delete baseline"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        </>
      )}
    </Card>
  )
}
