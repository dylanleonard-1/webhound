'use client'

import { motion, type HTMLMotionProps } from 'framer-motion'
import { type ReactNode } from 'react'
import { cn } from '@/lib/utils'

interface FloatingPanelProps extends Omit<HTMLMotionProps<'div'>, 'children'> {
  children?: ReactNode
  elevated?: boolean
  animate?: boolean
}

export function FloatingPanel({
  children,
  className,
  elevated = true,
  animate = true,
  ...props
}: FloatingPanelProps) {
  return (
    <motion.div
      className={cn(
        'relative overflow-hidden rounded-[20px]',
        'bg-[rgba(10,15,25,0.78)] backdrop-blur-[24px]',
        'border border-[rgba(139,255,62,0.08)]',
        elevated && 'shadow-[0_24px_64px_rgba(0,0,0,0.45),0_0_0_1px_rgba(139,255,62,0.04)]',
        className,
      )}
      initial={animate ? { opacity: 0, y: 12, scale: 0.98 } : undefined}
      animate={animate ? { opacity: 1, y: 0, scale: 1 } : undefined}
      transition={{ duration: 0.5, ease: [0.25, 0.46, 0.45, 0.94] }}
      {...props}
    >
      {/* Top highlight edge */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-[rgba(139,255,62,0.18)] to-transparent"
      />
      {children}
    </motion.div>
  )
}
