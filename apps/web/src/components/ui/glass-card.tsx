'use client'

import { motion, type HTMLMotionProps } from 'framer-motion'
import { type ReactNode } from 'react'
import { cn } from '@/lib/utils'

interface GlassCardProps extends Omit<HTMLMotionProps<'div'>, 'children'> {
  children?: ReactNode
  glow?: boolean
  hover?: boolean
}

export function GlassCard({
  children,
  className,
  glow = false,
  hover = true,
  ...props
}: GlassCardProps) {
  return (
    <motion.div
      className={cn(
        'relative overflow-hidden rounded-[20px] group',
        'bg-[rgba(10,15,25,0.55)] backdrop-blur-[20px]',
        'border border-[rgba(139,255,62,0.08)]',
        glow && 'shadow-[0_0_40px_rgba(139,255,62,0.06)]',
        className,
      )}
      whileHover={
        hover
          ? {
              y: -4,
              boxShadow: [
                '0 0 0 1px rgba(139,255,62,0.14)',
                '0 0 48px rgba(139,255,62,0.1)',
                '0 28px 60px rgba(0,0,0,0.35)',
              ].join(', '),
            }
          : undefined
      }
      transition={{ duration: 0.3, ease: [0.25, 0.46, 0.45, 0.94] }}
      {...props}
    >
      {/* Inner top-edge highlight */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-6 top-0 h-px bg-gradient-to-r from-transparent via-[rgba(139,255,62,0.15)] to-transparent transition-opacity duration-300 group-hover:via-[rgba(139,255,62,0.35)]"
      />
      {/* Subtle inner gradient */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 rounded-[20px] bg-gradient-to-b from-[rgba(139,255,62,0.015)] to-transparent"
      />
      {/* Hover: diagonal shimmer overlay */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 rounded-[20px] opacity-0 group-hover:opacity-100 transition-opacity duration-400"
        style={{
          background: 'linear-gradient(135deg, rgba(139,255,62,0.04) 0%, transparent 55%)',
        }}
      />
      {children}
    </motion.div>
  )
}
