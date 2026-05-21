import { type CSSProperties } from 'react'
import { cn } from '@/lib/utils'

interface SkeletonProps {
  className?: string
  style?: CSSProperties
  /** Show the animated shimmer sweep (default true) */
  shimmer?: boolean
}

/**
 * Glass-style skeleton loader for empty and loading states.
 * Matches the cybersec design system — dark surface, neon green shimmer.
 */
export function Skeleton({ className, style, shimmer = true }: SkeletonProps) {
  return (
    <div
      aria-busy="true"
      aria-label="Loading"
      style={style}
      className={cn(
        'relative overflow-hidden rounded-[10px]',
        'bg-[rgba(6,13,26,0.7)] border border-[rgba(139,255,62,0.06)]',
        className,
      )}
    >
      {shimmer && (
        <div
          aria-hidden
          className="absolute inset-0"
          style={{
            background:
              'linear-gradient(105deg, transparent 30%, rgba(139,255,62,0.06) 50%, transparent 70%)',
            backgroundSize: '250% 100%',
            animation: 'shimmer 2.2s linear infinite',
          }}
        />
      )}
    </div>
  )
}

// ── Preset compositions ───────────────────────────────────────────────────────

export function SkeletonCard({ className }: { className?: string }) {
  return (
    <div className={cn('rounded-[20px] border border-[rgba(139,255,62,0.07)] p-5 space-y-3 bg-[rgba(6,13,26,0.6)]', className)}>
      <Skeleton className="h-3 w-[45%]" />
      <Skeleton className="h-6 w-[70%]" />
      <Skeleton className="h-3 w-full" />
      <Skeleton className="h-3 w-[80%]" />
    </div>
  )
}

export function SkeletonMetric({ className }: { className?: string }) {
  return (
    <div className={cn('space-y-2', className)}>
      <Skeleton className="h-7 w-16" />
      <Skeleton className="h-2.5 w-24" />
    </div>
  )
}

export function SkeletonText({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <div className={cn('space-y-2', className)}>
      {Array.from({ length: lines }, (_, i) => (
        <Skeleton
          key={i}
          className="h-3"
          style={{ width: i === lines - 1 ? '65%' : '100%' }}
        />
      ))}
    </div>
  )
}
