'use client'

import { motion, type HTMLMotionProps } from 'framer-motion'
import { type ReactNode } from 'react'
import { cn } from '@/lib/utils'

interface PrimaryButtonProps extends Omit<HTMLMotionProps<'button'>, 'children'> {
  children?: ReactNode
}

export function PrimaryButton({ children, className, ...props }: PrimaryButtonProps) {
  return (
    <motion.button
      className={cn(
        'relative inline-flex items-center justify-center gap-2 overflow-hidden',
        'px-7 py-3.5 rounded-[16px]',
        'bg-[#8BFF3E] text-[#020617]',
        'font-semibold text-sm tracking-tight',
        'cursor-pointer select-none',
        'shadow-[0_0_20px_rgba(139,255,62,0.3)]',
        'transition-shadow duration-300',
        'hover:shadow-[0_0_40px_rgba(139,255,62,0.55),0_0_80px_rgba(139,255,62,0.18)]',
        'disabled:opacity-40 disabled:cursor-not-allowed',
        className,
      )}
      whileHover={{ y: -2, filter: 'brightness(1.1)' }}
      whileTap={{ scale: 0.97, filter: 'brightness(0.97)' }}
      transition={{ duration: 0.25, ease: [0.25, 0.46, 0.45, 0.94] }}
      {...props}
    >
      {/* Continuous light sweep */}
      <span
        aria-hidden
        className="absolute top-0 bottom-0 w-[45%] pointer-events-none"
        style={{
          background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent)',
          animation: 'sweepLight 4s ease-in-out infinite',
        }}
      />
      {/* Top edge highlight */}
      <span
        aria-hidden
        className="absolute inset-x-4 top-0 h-px bg-white/20 pointer-events-none"
      />
      {children}
    </motion.button>
  )
}
