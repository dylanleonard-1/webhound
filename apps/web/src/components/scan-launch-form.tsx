'use client'

import { useState } from 'react'
import { Play } from 'lucide-react'
import { api, type ScanJobResponse, type ScanProfile } from '@/lib/api'
import { Button } from './ui/button'
import { cn } from '@/lib/utils'

const PROFILES: { value: ScanProfile; label: string; description: string }[] = [
  { value: 'quick', label: 'Quick', description: 'Fast surface-level check' },
  { value: 'standard', label: 'Standard', description: 'Balanced depth and speed' },
  { value: 'deep', label: 'Deep', description: 'Thorough analysis' },
  { value: 'monitor', label: 'Monitor', description: 'Lightweight recurring check' },
]

interface ScanLaunchFormProps {
  websiteId: string
  onStarted: (job: ScanJobResponse) => void
}

export function ScanLaunchForm({ websiteId, onStarted }: ScanLaunchFormProps) {
  const [profile, setProfile] = useState<ScanProfile>('standard')
  const [saveBaseline, setSaveBaseline] = useState(true)
  const [useLatestBaseline, setUseLatestBaseline] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleStart() {
    setSubmitting(true)
    setError(null)
    try {
      const job = await api.scanJobs.create(websiteId, profile, {
        save_baseline: saveBaseline,
        use_latest_baseline: useLatestBaseline,
      })
      onStarted(job)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to start scan.')
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-4">
      {/* Profile selector */}
      <div>
        <p className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">Scan Profile</p>
        <div className="grid grid-cols-2 gap-2">
          {PROFILES.map(p => (
            <button
              key={p.value}
              type="button"
              onClick={() => setProfile(p.value)}
              className={cn(
                'text-left p-3 rounded-lg border transition-colors',
                profile === p.value
                  ? 'border-accent-green bg-accent-green/5 text-white'
                  : 'border-app-border text-gray-400 hover:border-app-border-subtle hover:text-gray-300',
              )}
            >
              <div className="text-sm font-medium font-mono">{p.label}</div>
              <div className="text-xs text-gray-500 mt-0.5">{p.description}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Options */}
      <div>
        <p className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">Options</p>
        <div className="space-y-2">
          <label className="flex items-center gap-3 cursor-pointer group">
            <input
              type="checkbox"
              checked={saveBaseline}
              onChange={e => setSaveBaseline(e.target.checked)}
              className="w-4 h-4 rounded border-app-border bg-app-bg accent-accent-green"
            />
            <span className="text-sm text-gray-300 group-hover:text-white transition-colors">
              Save as baseline
            </span>
          </label>
          <label className="flex items-center gap-3 cursor-pointer group">
            <input
              type="checkbox"
              checked={useLatestBaseline}
              onChange={e => setUseLatestBaseline(e.target.checked)}
              className="w-4 h-4 rounded border-app-border bg-app-bg accent-accent-green"
            />
            <span className="text-sm text-gray-300 group-hover:text-white transition-colors">
              Compare against latest baseline
            </span>
          </label>
        </div>
      </div>

      {error && (
        <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
          {error}
        </p>
      )}

      <Button onClick={handleStart} disabled={submitting} className="w-full">
        <Play className="w-4 h-4 mr-2" />
        {submitting ? 'Starting…' : 'Start Scan'}
      </Button>
    </div>
  )
}
