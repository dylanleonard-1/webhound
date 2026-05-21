'use client'

import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import Lenis from 'lenis'

interface LenisContextValue {
  lenis: Lenis | null
}

const LenisContext = createContext<LenisContextValue>({ lenis: null })

export function useLenis() {
  return useContext(LenisContext)
}

export function LenisProvider({ children }: { children: ReactNode }) {
  const [lenis, setLenis] = useState<Lenis | null>(null)
  const rafRef = useRef<number>(0)

  useEffect(() => {
    const reducedMotion =
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches

    const lenisInstance = new Lenis({
      duration: reducedMotion ? 0 : 0.75,
      easing: (t: number) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      smoothWheel: !reducedMotion,
      wheelMultiplier: 0.85,
      touchMultiplier: 1.4,
      // Prevent Lenis from touching touch-action — let browser handle it natively on mobile
      infinite: false,
    })

    setLenis(lenisInstance)

    // Dispatch a real scroll event each time Lenis scrolls so Framer Motion
    // useScroll() and IntersectionObserver-based hooks pick up the position.
    lenisInstance.on('scroll', () => {
      window.dispatchEvent(new Event('scroll', { bubbles: false }))
    })

    function raf(time: number) {
      lenisInstance.raf(time)
      rafRef.current = requestAnimationFrame(raf)
    }

    rafRef.current = requestAnimationFrame(raf)

    return () => {
      cancelAnimationFrame(rafRef.current)
      lenisInstance.destroy()
      setLenis(null)
    }
  }, [])

  return (
    <LenisContext.Provider value={{ lenis }}>
      {children}
    </LenisContext.Provider>
  )
}
