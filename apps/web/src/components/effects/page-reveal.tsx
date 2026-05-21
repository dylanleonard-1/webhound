'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

export function PageReveal() {
  const [visible, setVisible] = useState(true)

  useEffect(() => {
    const id = setTimeout(() => setVisible(false), 420)
    return () => clearTimeout(id)
  }, [])

  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          className="fixed inset-0 z-[200] flex items-center justify-center pointer-events-none"
          style={{ background: '#020617' }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.65, ease: [0.25, 0.46, 0.45, 0.94] }}
        >
          {/* Logo mark */}
          <motion.div
            initial={{ scale: 0.75, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 1.08, opacity: 0 }}
            transition={{ duration: 0.35, ease: [0.25, 0.46, 0.45, 0.94] }}
          >
            <div
              className="w-[52px] h-[52px] rounded-[15px] bg-[#8BFF3E] flex items-center justify-center"
              style={{
                boxShadow: [
                  '0 0 0 1px rgba(139,255,62,0.3)',
                  '0 0 48px rgba(139,255,62,0.65)',
                  '0 0 100px rgba(139,255,62,0.3)',
                  '0 0 180px rgba(139,255,62,0.12)',
                ].join(', '),
              }}
            >
              <span className="text-[#020617] text-[10px] font-black tracking-[0.18em]">CS</span>
            </div>
          </motion.div>

          {/* Radial glow bloom behind logo */}
          <motion.div
            className="absolute inset-0 pointer-events-none"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
            style={{
              background: 'radial-gradient(ellipse 30% 30% at 50% 50%, rgba(139,255,62,0.08) 0%, transparent 70%)',
            }}
          />
        </motion.div>
      )}
    </AnimatePresence>
  )
}
