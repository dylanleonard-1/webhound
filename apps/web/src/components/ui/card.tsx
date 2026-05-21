import { cn } from '@/lib/utils'
import { type HTMLAttributes, forwardRef } from 'react'

export const Card = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, style, ...props }, ref) => (
    <div
      ref={ref}
      className={cn('rounded-[12px]', className)}
      style={{
        background: 'rgba(8,12,22,0.95)',
        border: '1px solid rgba(255,255,255,0.06)',
        ...style,
      }}
      {...props}
    />
  ),
)

Card.displayName = 'Card'
