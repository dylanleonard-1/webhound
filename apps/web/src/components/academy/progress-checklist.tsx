'use client'

import { useEffect, useState } from 'react'
import { CheckCircle2, Circle } from 'lucide-react'
import { cn } from '@/lib/utils'

// Local-only progress (useState + localStorage). No database, no network.
export function ProgressChecklist({ items, storageKey }: { items: string[]; storageKey: string }) {
  const [done, setDone] = useState<Record<string, boolean>>({})
  const [ready, setReady] = useState(false)

  useEffect(() => {
    // Hydration-safe load: render empty on the server, then sync from
    // localStorage once mounted (the canonical client-only-storage pattern).
    let restored: Record<string, boolean> | null = null
    try {
      const raw = localStorage.getItem(storageKey)
      if (raw) restored = JSON.parse(raw) as Record<string, boolean>
    } catch {
      /* ignore corrupt/unavailable storage */
    }
    // eslint-disable-next-line react-hooks/set-state-in-effect -- one-time post-mount storage sync
    if (restored) setDone(restored)
    setReady(true)
  }, [storageKey])

  function toggle(item: string) {
    setDone((prev) => {
      const next = { ...prev, [item]: !prev[item] }
      try {
        localStorage.setItem(storageKey, JSON.stringify(next))
      } catch {
        /* ignore */
      }
      return next
    })
  }

  const count = items.filter((i) => done[i]).length

  return (
    <div>
      <div className="mb-3 flex items-center justify-between">
        <span className="text-xs text-slate-500">{count} / {items.length} done</span>
        <div className="h-1.5 w-28 overflow-hidden rounded-full bg-white/10">
          <div
            className="h-full rounded-full bg-accent-green transition-all"
            style={{ width: ready ? `${(count / items.length) * 100}%` : '0%' }}
          />
        </div>
      </div>
      <ul className="space-y-1.5">
        {items.map((item) => {
          const isDone = !!done[item]
          return (
            <li key={item}>
              <button
                type="button"
                onClick={() => toggle(item)}
                className="flex w-full items-start gap-2.5 rounded-lg px-2 py-1.5 text-left text-sm hover:bg-white/5"
              >
                {isDone ? (
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-accent-green" />
                ) : (
                  <Circle className="mt-0.5 h-4 w-4 shrink-0 text-slate-600" />
                )}
                <span className={cn(isDone ? 'text-slate-500 line-through' : 'text-slate-200')}>{item}</span>
              </button>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
