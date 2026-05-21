import { cn } from '@/lib/utils'

interface GradientDividerProps {
  className?: string
  orientation?: 'horizontal' | 'vertical'
  glow?: boolean
  opacity?: number
}

export function GradientDivider({
  className,
  orientation = 'horizontal',
  glow = false,
  opacity = 1,
}: GradientDividerProps) {
  if (orientation === 'vertical') {
    return (
      <div
        style={{ opacity }}
        className={cn(
          'w-px shrink-0',
          'bg-gradient-to-b from-transparent via-[rgba(139,255,62,0.18)] to-transparent',
          className,
        )}
      />
    )
  }

  return (
    <div style={{ opacity }} className={cn('relative h-px w-full', className)}>
      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-[rgba(139,255,62,0.2)] to-transparent" />
      {glow && (
        <div className="absolute inset-0 blur-[6px] bg-gradient-to-r from-transparent via-[rgba(139,255,62,0.15)] to-transparent" />
      )}
    </div>
  )
}
