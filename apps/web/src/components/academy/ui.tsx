import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

// Small presentational primitives shared across academy pages. Server components.

export function AcademyCard({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <div className={cn('rounded-xl border border-app-border bg-app-card p-5', className)}>
      {children}
    </div>
  )
}

export function SectionHeading({ kicker, title, sub }: { kicker?: string; title: string; sub?: string }) {
  return (
    <div className="mb-5">
      {kicker ? (
        <p className="text-xs font-mono uppercase tracking-widest text-accent-green">{kicker}</p>
      ) : null}
      <h1 className="mt-1 text-2xl font-bold text-white sm:text-3xl">{title}</h1>
      {sub ? <p className="mt-2 max-w-2xl text-sm leading-relaxed text-slate-400">{sub}</p> : null}
    </div>
  )
}

export function Pill({ children, tone = 'default' }: { children: ReactNode; tone?: 'default' | 'green' | 'blue' }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium',
        tone === 'green' && 'bg-accent-green/10 text-accent-green',
        tone === 'blue' && 'bg-accent-blue/10 text-accent-blue',
        tone === 'default' && 'bg-white/5 text-slate-300',
      )}
    >
      {children}
    </span>
  )
}

export function QABlock({ q, a }: { q: string; a: string }) {
  return (
    <details className="group rounded-lg border border-app-border bg-app-surface p-4 [&_summary]:list-none">
      <summary className="flex cursor-pointer items-start justify-between gap-3">
        <span className="text-sm font-semibold text-white">{q}</span>
        <span className="mt-0.5 shrink-0 text-accent-green transition-transform group-open:rotate-45">+</span>
      </summary>
      <p className="mt-3 text-sm leading-relaxed text-slate-300">{a}</p>
    </details>
  )
}
