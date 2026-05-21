import { cn } from '@/lib/utils'
import { type ButtonHTMLAttributes, Children, cloneElement, forwardRef, isValidElement } from 'react'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'ghost' | 'outline' | 'danger'
  size?: 'sm' | 'md' | 'lg'
  asChild?: boolean
}

const variantStyles: Record<NonNullable<ButtonProps['variant']>, string> = {
  primary: 'bg-accent-green text-app-bg hover:bg-accent-green-dim font-medium',
  ghost: 'text-gray-400 hover:text-white hover:bg-white/5',
  outline: 'border border-app-border text-gray-300 hover:border-app-border-subtle hover:text-white',
  danger: 'border border-red-500/40 text-red-400 hover:bg-red-500/10',
}

const sizeStyles: Record<NonNullable<ButtonProps['size']>, string> = {
  sm: 'px-2.5 py-1.5 text-xs',
  md: 'px-3.5 py-2 text-sm',
  lg: 'px-5 py-2.5 text-base',
}

const baseClass =
  'inline-flex items-center justify-center rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-accent-green/40 disabled:opacity-40 disabled:pointer-events-none'

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', disabled, asChild, children, ...props }, ref) => {
    const classes = cn(baseClass, variantStyles[variant], sizeStyles[size], className)

    if (asChild) {
      const child = Children.only(children)
      if (isValidElement(child)) {
        return cloneElement(child as React.ReactElement<{ className?: string }>, {
          className: cn(classes, (child.props as { className?: string }).className),
        })
      }
    }

    return (
      <button ref={ref} disabled={disabled} className={classes} {...props}>
        {children}
      </button>
    )
  },
)

Button.displayName = 'Button'
