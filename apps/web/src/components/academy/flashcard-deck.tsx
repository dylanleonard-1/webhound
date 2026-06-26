'use client'

import { useMemo, useState } from 'react'
import { ChevronLeft, ChevronRight, RotateCcw } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { FlashcardGroup } from '@/lib/academy/pca-risk'

export function FlashcardDeck({ groups }: { groups: FlashcardGroup[] }) {
  const moduleNames = useMemo(() => groups.map((g) => g.module), [groups])
  const [moduleName, setModuleName] = useState(moduleNames[0])
  const [idx, setIdx] = useState(0)
  const [flipped, setFlipped] = useState(false)

  const deck = groups.find((g) => g.module === moduleName)?.cards ?? []
  const card = deck[idx]

  function go(delta: number) {
    setFlipped(false)
    setIdx((i) => {
      const n = deck.length
      return ((i + delta) % n + n) % n
    })
  }

  function pickModule(name: string) {
    setModuleName(name)
    setIdx(0)
    setFlipped(false)
  }

  return (
    <div>
      <div className="mb-4 flex flex-wrap gap-1.5">
        {moduleNames.map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => pickModule(m)}
            className={cn(
              'rounded-full px-3 py-1 text-xs transition-colors',
              m === moduleName ? 'bg-accent-green/15 text-accent-green'
                               : 'bg-white/5 text-slate-400 hover:text-white',
            )}
          >
            {m}
          </button>
        ))}
      </div>

      {card ? (
        <>
          <button
            type="button"
            onClick={() => setFlipped((f) => !f)}
            className="flex min-h-[220px] w-full flex-col items-center justify-center rounded-2xl border border-app-border bg-app-card p-8 text-center transition-colors hover:border-accent-green/40"
          >
            <span className="mb-3 text-[11px] font-mono uppercase tracking-widest text-slate-500">
              {flipped ? 'Answer' : 'Question'} · tap to flip
            </span>
            <span className={cn('text-lg leading-relaxed', flipped ? 'text-slate-200' : 'font-semibold text-white')}>
              {flipped ? card.back : card.front}
            </span>
          </button>

          <div className="mt-4 flex items-center justify-between">
            <button type="button" onClick={() => go(-1)}
              className="inline-flex items-center gap-1 rounded-lg border border-app-border px-3 py-2 text-sm text-slate-300 hover:bg-white/5">
              <ChevronLeft className="h-4 w-4" /> Prev
            </button>
            <span className="text-xs text-slate-500">
              {idx + 1} / {deck.length}
            </span>
            <div className="flex gap-2">
              <button type="button" onClick={() => setFlipped((f) => !f)}
                className="inline-flex items-center gap-1 rounded-lg border border-app-border px-3 py-2 text-sm text-slate-300 hover:bg-white/5">
                <RotateCcw className="h-4 w-4" /> Flip
              </button>
              <button type="button" onClick={() => go(1)}
                className="inline-flex items-center gap-1 rounded-lg bg-accent-green/15 px-3 py-2 text-sm text-accent-green hover:bg-accent-green/25">
                Next <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        </>
      ) : null}
    </div>
  )
}
