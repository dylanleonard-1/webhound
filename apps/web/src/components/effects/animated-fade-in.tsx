'use client'

import { motion, type HTMLMotionProps, type TargetAndTransition } from 'framer-motion'
import { type ReactNode } from 'react'
import { cn } from '@/lib/utils'

type Direction = 'up' | 'down' | 'left' | 'right' | 'none'

interface AnimatedFadeInProps extends Omit<HTMLMotionProps<'div'>, 'initial' | 'whileInView' | 'viewport' | 'children'> {
  children?: ReactNode
  delay?: number
  direction?: Direction
  duration?: number
  distance?: number
  once?: boolean
  blur?: boolean
}

const getInitial = (direction: Direction, distance: number, blur: boolean): TargetAndTransition => {
  const blurVal = blur ? 'blur(8px)' : undefined
  const map: Record<Direction, TargetAndTransition> = {
    up:    { y: distance, opacity: 0, ...(blurVal && { filter: blurVal }) },
    down:  { y: -distance, opacity: 0, ...(blurVal && { filter: blurVal }) },
    left:  { x: distance, opacity: 0, ...(blurVal && { filter: blurVal }) },
    right: { x: -distance, opacity: 0, ...(blurVal && { filter: blurVal }) },
    none:  { opacity: 0, ...(blurVal && { filter: blurVal }) },
  }
  return map[direction]
}

export function AnimatedFadeIn({
  children,
  className,
  delay = 0,
  direction = 'up',
  duration = 0.65,
  distance = 24,
  once = true,
  blur = false,
  ...props
}: AnimatedFadeInProps) {
  return (
    <motion.div
      className={cn(className)}
      initial={getInitial(direction, distance, blur)}
      whileInView={{ x: 0, y: 0, opacity: 1, ...(blur && { filter: 'blur(0px)' }) }}
      viewport={{ once, margin: '-60px' }}
      transition={{
        duration,
        delay,
        ease: [0.25, 0.46, 0.45, 0.94],
      }}
      {...props}
    >
      {children}
    </motion.div>
  )
}
