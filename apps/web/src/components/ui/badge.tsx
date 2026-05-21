import { cn } from '@/lib/utils'
import { type HTMLAttributes } from 'react'

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'outline' | 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success'
}

const VARIANT_STYLES: Record<NonNullable<BadgeProps['variant']>, string> = {
  default:  'bg-[rgba(255,255,255,0.05)] border-[rgba(255,255,255,0.08)] text-[rgba(255,255,255,0.55)]',
  outline:  'bg-transparent border-[rgba(255,255,255,0.10)] text-[rgba(255,255,255,0.5)]',
  critical: 'bg-[rgba(239,68,68,0.1)] border-[rgba(239,68,68,0.25)] text-[#ef4444]',
  high:     'bg-[rgba(249,115,22,0.1)] border-[rgba(249,115,22,0.25)] text-[#f97316]',
  medium:   'bg-[rgba(234,179,8,0.1)] border-[rgba(234,179,8,0.25)] text-[#eab308]',
  low:      'bg-[rgba(59,130,246,0.1)] border-[rgba(59,130,246,0.25)] text-[#3b82f6]',
  info:     'bg-[rgba(107,114,128,0.1)] border-[rgba(107,114,128,0.2)] text-[#9ca3af]',
  success:  'bg-[rgba(139,255,62,0.08)] border-[rgba(139,255,62,0.22)] text-[#8BFF3E]',
}

export function Badge({ className, variant = 'default', ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-[5px] text-[10px] font-bold font-mono border tracking-wide',
        VARIANT_STYLES[variant],
        className,
      )}
      {...props}
    />
  )
}
