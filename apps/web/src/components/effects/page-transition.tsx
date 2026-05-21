'use client'

import { usePathname } from 'next/navigation'
import { AnimatePresence, motion } from 'framer-motion'
import { type ReactNode } from 'react'

interface PageTransitionProps {
  children: ReactNode
}

/**
 * Wraps page content with a cinematic fade transition on route changes.
 * Uses pathname as AnimatePresence key — on navigation, old content exits
 * while new content enters, creating a seamless blend.
 *
 * `initial={false}` prevents animation on the very first render so that
 * PageReveal (the boot-up overlay) is the sole initial experience.
 */
export function PageTransition({ children }: PageTransitionProps) {
  const pathname = usePathname()

  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={pathname}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.35, ease: [0.25, 0.46, 0.45, 0.94] }}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  )
}
