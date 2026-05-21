'use client'

import { motion, type HTMLMotionProps } from 'framer-motion'
import { type ReactNode } from 'react'
import { cn } from '@/lib/utils'

interface SecondaryButtonProps extends Omit<HTMLMotionProps<'button'>, 'children'> {
  children?: ReactNode
}

export function SecondaryButton({ children, className, ...props }: SecondaryButtonProps) {
  return (
    <motion.button
      className={cn(
        'relative inline-flex items-center justify-center gap-2 overflow-hidden',
        'px-7 py-3.5 rounded-[16px]',
        'bg-[rgba(139,255,62,0.04)] text-white',
        'border border-[rgba(139,255,62,0.22)]',
        'font-semibold text-sm tracking-tight',
        'cursor-pointer select-none',
        'transition-all duration-300',
        'hover:border-[rgba(139,255,62,0.55)] hover:text-[#8BFF3E]',
        'hover:shadow-[0_0_24px_rgba(139,255,62,0.14),inset_0_0_20px_rgba(139,255,62,0.04)]',
        'hover:bg-[rgba(139,255,62,0.06)]',
        'disabled:opacity-40 disabled:cursor-not-allowed',
        className,
      )}
      whileHover={{ y: -2 }}
      whileTap={{ scale: 0.97 }}
      transition={{ duration: 0.25, ease: [0.25, 0.46, 0.45, 0.94] }}
      {...props}
    >
      {/* Glass top reflection */}
      <span
        aria-hidden
        className="absolute inset-x-0 top-0 h-[45%] rounded-t-[16px] pointer-events-none"
        style={{ background: 'linear-gradient(180deg, rgba(255,255,255,0.05) 0%, transparent 100%)' }}
      />
      {/* Border glow edge on hover — inset ring */}
      <span
        aria-hidden
        className="absolute inset-0 rounded-[16px] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{ boxShadow: 'inset 0 0 0 1px rgba(139,255,62,0.4)' }}
      />
      {children}
    </motion.button>
  )
}
