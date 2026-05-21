import { type ReactNode } from 'react'
import { cn } from '@/lib/utils'

type GlowVariant = 'default' | 'hero' | 'subtle' | 'none'

interface GlowBackgroundProps {
  children: ReactNode
  className?: string
  variant?: GlowVariant
}

const noiseDataUri =
  "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='300' height='300'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='300' height='300' filter='url(%23n)'/%3E%3C/svg%3E\")"

export function GlowBackground({ children, className, variant = 'default' }: GlowBackgroundProps) {
  return (
    <div className={cn('relative overflow-hidden bg-[#020617]', className)}>
      {/* Primary radial glow */}
      {variant !== 'none' && variant !== 'subtle' && (
        <div
          aria-hidden
          className="pointer-events-none absolute -top-[200px] left-1/2 -translate-x-1/2 w-[1000px] h-[700px] rounded-full blur-[120px]"
          style={{ background: 'rgba(139,255,62,0.04)' }}
        />
      )}

      {/* Hero gets a secondary offset glow */}
      {variant === 'hero' && (
        <>
          <div
            aria-hidden
            className="pointer-events-none absolute top-[30%] -left-[200px] w-[600px] h-[400px] rounded-full blur-[100px]"
            style={{ background: 'rgba(139,255,62,0.025)' }}
          />
          <div
            aria-hidden
            className="pointer-events-none absolute top-[20%] -right-[150px] w-[500px] h-[300px] rounded-full blur-[80px]"
            style={{ background: 'rgba(10,30,60,0.6)' }}
          />
        </>
      )}

      {/* Noise texture overlay */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{ backgroundImage: noiseDataUri, opacity: 0.018 }}
      />

      {/* Vignette */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            'radial-gradient(ellipse 80% 60% at 50% 0%, transparent 40%, rgba(2,6,23,0.7) 100%)',
        }}
      />

      <div className="relative z-10">{children}</div>
    </div>
  )
}
