'use client'

import { useState } from 'react'
import { X } from 'lucide-react'
import { api, type ScanScheduleResponse, type ScanProfile, type ScheduleFrequency } from '@/lib/api'
import { Button } from '@/components/ui/button'

interface ScheduleFormProps {
  websiteId: string
  schedule?: ScanScheduleResponse | null
  onSave: (s: ScanScheduleResponse) => void
  onClose: () => void
}

const PROFILES: { value: ScanProfile; label: string; desc: string }[] = [
  { value: 'quick', label: 'Quick', desc: '~2 min' },
  { value: 'standard', label: 'Standard', desc: '~10 min' },
  { value: 'deep', label: 'Deep', desc: '~30 min' },
  { value: 'monitor', label: 'Monitor', desc: 'Lightweight' },
]

const FREQUENCIES: { value: ScheduleFrequency; label: string }[] = [
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
]

function toLocalDatetimeValue(iso: string): string {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function defaultNextRun(): string {
  const d = new Date()
  d.setDate(d.getDate() + 1)
  d.setHours(9, 0, 0, 0)
  return toLocalDatetimeValue(d.toISOString())
}

export function ScheduleForm({ websiteId, schedule, onSave, onClose }: ScheduleFormProps) {
  const editing = !!schedule
  const [profile, setProfile] = useState<ScanProfile>(schedule?.profile ?? 'monitor')
  const [frequency, setFrequency] = useState<ScheduleFrequency>(schedule?.frequency ?? 'weekly')
  const [nextRunAt, setNextRunAt] = useState(
    schedule ? toLocalDatetimeValue(schedule.next_run_at) : defaultNextRun()
  )
  const [useBaseline, setUseBaseline] = useState(schedule?.use_latest_baseline ?? true)
  const [saveBaseline, setSaveBaseline] = useState(schedule?.save_baseline ?? true)
  const [isEnabled, setIsEnabled] = useState(schedule?.is_enabled ?? true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError('')
    try {
      const next_run_at = new Date(nextRunAt).toISOString()
      let result: ScanScheduleResponse
      if (editing && schedule) {
        result = await api.schedules.update(schedule.id, {
          profile, frequency, is_enabled: isEnabled,
          use_latest_baseline: useBaseline, save_baseline: saveBaseline, next_run_at,
        })
      } else {
        result = await api.schedules.create({
          website_id: websiteId, profile, frequency,
          is_enabled: isEnabled, use_latest_baseline: useBaseline,
          save_baseline: saveBaseline, next_run_at,
        })
      }
      onSave(result)
    } catch {
      setError('Failed to save schedule.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-[2px] z-40" onClick={onClose} />
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div className="bg-[#0D1220] border border-app-border rounded-xl w-full max-w-md shadow-2xl">
          <div className="flex items-center justify-between p-5 border-b border-app-border">
            <h2 className="font-semibold text-white">{editing ? 'Edit Schedule' : 'New Schedule'}</h2>
            <button onClick={onClose} className="p-1.5 text-gray-500 hover:text-white rounded transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="p-5 space-y-5">
            {/* Profile */}
            <div>
              <label className="text-xs text-gray-400 uppercase tracking-wider block mb-2">Profile</label>
              <div className="grid grid-cols-2 gap-2">
                {PROFILES.map(p => (
                  <button
                    key={p.value}
                    type="button"
                    onClick={() => setProfile(p.value)}
                    className={`flex flex-col items-start p-3 rounded-lg border text-left transition-colors ${
                      profile === p.value
                        ? 'border-accent-green bg-accent-green/10'
                        : 'border-app-border hover:border-gray-600'
                    }`}
                  >
                    <span className={`text-sm font-medium ${profile === p.value ? 'text-accent-green' : 'text-white'}`}>
                      {p.label}
                    </span>
                    <span className="text-[11px] text-gray-500">{p.desc}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Frequency */}
            <div>
              <label className="text-xs text-gray-400 uppercase tracking-wider block mb-2">Frequency</label>
              <div className="flex gap-2">
                {FREQUENCIES.map(f => (
                  <button
                    key={f.value}
                    type="button"
                    onClick={() => setFrequency(f.value)}
                    className={`flex-1 py-2 rounded-lg border text-sm font-medium transition-colors ${
                      frequency === f.value
                        ? 'border-accent-green bg-accent-green/10 text-accent-green'
                        : 'border-app-border text-gray-400 hover:border-gray-600'
                    }`}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Next run */}
            <div>
              <label className="text-xs text-gray-400 uppercase tracking-wider block mb-2">First Run At</label>
              <input
                type="datetime-local"
                value={nextRunAt}
                onChange={e => setNextRunAt(e.target.value)}
                required
                className="w-full bg-app-bg border border-app-border rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-accent-green"
              />
            </div>

            {/* Options */}
            <div className="space-y-2.5">
              {[
                { id: 'useBaseline', label: 'Use latest baseline', checked: useBaseline, set: setUseBaseline },
                { id: 'saveBaseline', label: 'Save baseline after scan', checked: saveBaseline, set: setSaveBaseline },
                { id: 'isEnabled', label: 'Enabled', checked: isEnabled, set: setIsEnabled },
              ].map(({ id, label, checked, set }) => (
                <label key={id} className="flex items-center gap-3 cursor-pointer">
                  <div
                    onClick={() => set(!checked)}
                    className={`w-9 h-5 rounded-full transition-colors flex-shrink-0 ${
                      checked ? 'bg-accent-green' : 'bg-gray-700'
                    } flex items-center px-0.5`}
                  >
                    <div className={`w-4 h-4 rounded-full bg-white shadow transition-transform ${checked ? 'translate-x-4' : ''}`} />
                  </div>
                  <span className="text-sm text-gray-300">{label}</span>
                </label>
              ))}
            </div>

            {error && <p className="text-xs text-red-400">{error}</p>}

            <div className="flex gap-3 pt-1">
              <Button type="button" variant="ghost" size="sm" className="flex-1" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" size="sm" className="flex-1" disabled={saving}>
                {saving ? 'Saving…' : editing ? 'Save Changes' : 'Create Schedule'}
              </Button>
            </div>
          </form>
        </div>
      </div>
    </>
  )
}
