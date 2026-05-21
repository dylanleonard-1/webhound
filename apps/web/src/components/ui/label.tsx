import { cn } from '@/lib/utils'
import { type LabelHTMLAttributes, forwardRef } from 'react'

export const Label = forwardRef<HTMLLabelElement, LabelHTMLAttributes<HTMLLabelElement>>(
  ({ className, ...props }, ref) => (
    <label
      ref={ref}
      className={cn('block text-sm font-medium text-gray-300 mb-1.5', className)}
      {...props}
    />
  ),
)

Label.displayName = 'Label'
