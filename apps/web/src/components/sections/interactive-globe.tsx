'use client'

import { cn } from '@/lib/utils'

interface InteractiveGlobeProps {
  className?: string
  size?: number
}

/* Placeholder — full R3F globe implementation comes in a future phase. */
export function InteractiveGlobe({ className, size = 600 }: InteractiveGlobeProps) {
  return (
    <div
      className={cn('relative mx-auto flex items-center justify-center', className)}
      style={{ width: size, height: size, maxWidth: '100%' }}
    >
      {/* Outer ambient ring */}
      <div
        aria-hidden
        className="absolute inset-0 rounded-full"
        style={{
          background:
            'radial-gradient(circle at 50% 50%, rgba(139,255,62,0.06) 0%, rgba(139,255,62,0.02) 40%, transparent 70%)',
          boxShadow: '0 0 80px rgba(139,255,62,0.08)',
        }}
      />

      {/* Globe shell */}
      <div
        className="relative rounded-full border border-[rgba(139,255,62,0.1)] bg-[rgba(6,17,31,0.6)] backdrop-blur-sm"
        style={{ width: '80%', height: '80%' }}
      >
        {/* Inner grid lines suggestion */}
        <div
          aria-hidden
          className="absolute inset-0 rounded-full opacity-20"
          style={{
            background:
              'repeating-linear-gradient(0deg, transparent, transparent 29px, rgba(139,255,62,0.07) 30px), repeating-linear-gradient(90deg, transparent, transparent 29px, rgba(139,255,62,0.07) 30px)',
          }}
        />

        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2">
          <div className="w-2 h-2 rounded-full bg-[#8BFF3E] shadow-[0_0_12px_rgba(139,255,62,0.8)]" />
          <p className="font-mono text-[10px] tracking-[0.25em] text-[rgba(139,255,62,0.4)] uppercase">
            Globe Loading
          </p>
        </div>
      </div>

      {/* Orbiting dot accent */}
      <div
        aria-hidden
        className="absolute inset-0 animate-spin"
        style={{ animationDuration: '12s' }}
      >
        <div
          className="absolute top-[8%] left-1/2 -translate-x-1/2 w-1.5 h-1.5 rounded-full bg-[#8BFF3E]"
          style={{ boxShadow: '0 0 8px rgba(139,255,62,0.9)' }}
        />
      </div>
    </div>
  )
}
