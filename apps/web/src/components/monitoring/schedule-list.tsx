'use client'

import { useCallback, useEffect, useState } from 'react'
import { CalendarClock, Plus, Pencil, Trash2, Power } from 'lucide-react'
import { api, type ScanScheduleResponse } from '@/lib/api'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { LoadingState } from '@/components/loading-state'
import { EmptyState } from '@/components/empty-state'
import { ErrorState } from '@/components/error-state'
import { ScheduleForm } from './schedule-form'
import { cn } from '@/lib/utils'

interface ScheduleListProps {
  websiteId: string
}

const FREQ_BADGE: Record<string, string> = {
  daily: 'bg-accent-blue/10 text-accent-blue border-accent-blue/20',
  weekly: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  monthly: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
}

const PROFILE_BADGE: Record<string, string> = {
  quick: 'bg-accent-green/10 text-accent-green border-accent-green/20',
  standard: 'bg-accent-blue/10 text-accent-blue border-accent-blue/20',
  deep: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  monitor: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

export function ScheduleList({ websiteId }: ScheduleListProps) {
  const [schedules, setSchedules] = useState<ScanScheduleResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<ScanScheduleResponse | null>(null)
  const [toggling, setToggling] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(false)
    try {
      const r = await api.schedules.list({ website_id: websiteId })
      setSchedules(r.items)
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }, [websiteId])

  useEffect(() => { load() }, [load])

  async function handleToggle(s: ScanScheduleResponse) {
    setToggling(s.id)
    try {
      const updated = await api.schedules.update(s.id, { is_enabled: !s.is_enabled })
      setSchedules(prev => prev.map(x => x.id === s.id ? updated : x))
    } catch { /* ignore */ } finally {
      setToggling(null)
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this schedule?')) return
    setDeleting(id)
    try {
      await api.schedules.delete(id)
      setSchedules(prev => prev.filter(s => s.id !== id))
    } catch { /* ignore */ } finally {
      setDeleting(null)
    }
  }

  function handleSaved(s: ScanScheduleResponse) {
    setSchedules(prev => {
      const idx = prev.findIndex(x => x.id === s.id)
      return idx >= 0 ? prev.map(x => x.id === s.id ? s : x) : [s, ...prev]
    })
    setFormOpen(false)
    setEditing(null)
  }

  return (
    <>
      <Card>
        <div className="flex items-center justify-between p-4 border-b border-app-border">
          <div className="flex items-center gap-2">
            <CalendarClock className="w-4 h-4 text-gray-400" />
            <h2 className="font-medium text-white">Scan Schedules</h2>
            <Badge className="bg-gray-500/10 text-gray-400 border-gray-500/20">{schedules.length}</Badge>
          </div>
          <Button
            variant="primary"
            size="sm"
            onClick={() => { setEditing(null); setFormOpen(true) }}
          >
            <Plus className="w-3.5 h-3.5 mr-1" />
            New Schedule
          </Button>
        </div>

        {loading ? (
          <div className="p-6"><LoadingState /></div>
        ) : error ? (
          <div className="p-6">
            <ErrorState message="Failed to load schedules." onRetry={load} />
          </div>
        ) : schedules.length === 0 ? (
          <div className="p-6">
            <EmptyState
              title="No schedules"
              description="Create a schedule to automatically run scans on this website."
            />
          </div>
        ) : (
          <div className="divide-y divide-app-border">
            {schedules.map(s => (
              <div key={s.id} className="flex items-center gap-3 px-4 py-3">
                {/* Enable toggle */}
                <button
                  onClick={() => handleToggle(s)}
                  disabled={toggling === s.id}
                  title={s.is_enabled ? 'Disable' : 'Enable'}
                  className={cn(
                    'p-1.5 rounded transition-colors flex-shrink-0',
                    s.is_enabled ? 'text-accent-green hover:text-accent-green/70' : 'text-gray-600 hover:text-gray-400',
                  )}
                >
                  <Power className="w-4 h-4" />
                </button>

                {/* Info */}
                <div className="flex-1 min-w-0 space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge className={cn('text-[10px]', FREQ_BADGE[s.frequency] ?? FREQ_BADGE.weekly)}>
                      {s.frequency}
                    </Badge>
                    <Badge className={cn('text-[10px]', PROFILE_BADGE[s.profile] ?? PROFILE_BADGE.standard)}>
                      {s.profile}
                    </Badge>
                    {!s.is_enabled && (
                      <Badge className="text-[10px] bg-gray-700/50 text-gray-500 border-gray-700">
                        paused
                      </Badge>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-[11px] text-gray-500">
                    <span>Next: <span className="text-gray-400">{formatDate(s.next_run_at)}</span></span>
                    {s.last_run_at && (
                      <span>Last: <span className="text-gray-400">{formatDate(s.last_run_at)}</span></span>
                    )}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-1 flex-shrink-0">
                  <button
                    onClick={() => { setEditing(s); setFormOpen(true) }}
                    className="p-1.5 text-gray-500 hover:text-white rounded transition-colors"
                    title="Edit"
                  >
                    <Pencil className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => handleDelete(s.id)}
                    disabled={deleting === s.id}
                    className="p-1.5 text-gray-500 hover:text-red-400 rounded transition-colors"
                    title="Delete"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {formOpen && (
        <ScheduleForm
          websiteId={websiteId}
          schedule={editing}
          onSave={handleSaved}
          onClose={() => { setFormOpen(false); setEditing(null) }}
        />
      )}
    </>
  )
}
