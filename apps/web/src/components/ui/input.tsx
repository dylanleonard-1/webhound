import { cn } from '@/lib/utils'
import { type InputHTMLAttributes, forwardRef } from 'react'

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        'w-full bg-app-bg border border-app-border rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500',
        'focus:outline-none focus:border-accent-green transition-colors',
        'disabled:opacity-40',
        className,
      )}
      {...props}
    />
  ),
)

Input.displayName = 'Input'
