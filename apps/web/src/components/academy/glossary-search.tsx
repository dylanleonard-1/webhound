'use client'

import { useMemo, useState } from 'react'
import { Search } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { GlossaryTerm } from '@/lib/academy/pca-risk'

export function GlossarySearch({ terms }: { terms: GlossaryTerm[] }) {
  const [q, setQ] = useState('')
  const [cat, setCat] = useState('All')

  const categories = useMemo(
    () => ['All', ...Array.from(new Set(terms.map((t) => t.category))).sort()],
    [terms],
  )

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return terms.filter((t) => {
      if (cat !== 'All' && t.category !== cat) return false
      if (!needle) return true
      return (
        t.term.toLowerCase().includes(needle) ||
        t.short.toLowerCase().includes(needle) ||
        t.definition.toLowerCase().includes(needle)
      )
    })
  }, [terms, q, cat])

  return (
    <div>
      <div className="sticky top-16 z-10 -mx-1 mb-4 bg-app-bg/90 px-1 py-2 backdrop-blur">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search terms, e.g. roll-forward, CUEC, RTO…"
            className="w-full rounded-lg border border-app-border bg-app-surface py-2.5 pl-9 pr-3 text-sm text-white placeholder:text-slate-500 focus:border-accent-green/50 focus:outline-none"
          />
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {categories.map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => setCat(c)}
              className={cn(
                'rounded-full px-2.5 py-1 text-xs transition-colors',
                cat === c ? 'bg-accent-green/15 text-accent-green'
                          : 'bg-white/5 text-slate-400 hover:text-white',
              )}
            >
              {c}
            </button>
          ))}
        </div>
      </div>

      <p className="mb-3 text-xs text-slate-500">{filtered.length} of {terms.length} terms</p>

      <div className="space-y-3">
        {filtered.map((t) => (
          <div key={t.term} className="rounded-xl border border-app-border bg-app-card p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h3 className="font-semibold text-white">{t.term}</h3>
              <span className="rounded-full bg-white/5 px-2 py-0.5 text-[11px] text-slate-400">{t.category}</span>
            </div>
            <p className="mt-0.5 text-xs font-medium text-accent-green">{t.short}</p>
            <p className="mt-2 text-sm leading-relaxed text-slate-300">{t.definition}</p>
            {t.also ? <p className="mt-2 text-xs italic text-slate-500">{t.also}</p> : null}
          </div>
        ))}
        {filtered.length === 0 ? (
          <p className="py-8 text-center text-sm text-slate-500">No terms match “{q}”.</p>
        ) : null}
      </div>
    </div>
  )
}
