'use client'

import Image from 'next/image'
import { Cpu, Shield, Radar, Building2, Eye } from 'lucide-react'
import { cn } from '@/lib/utils'

// ── Floating label badges ─────────────────────────────────────────────────────

interface Tag {
  icon: React.FC<{ className?: string }>
  label: string
  pos: { top?: string; left?: string; right?: string; bottom?: string }
}

// Positions are tuned against /public/hero-globe.jpg. They sit on or near the
// brighter green nodes in the underlying artwork.
const TAGS: Tag[] = [
  { icon: Cpu,        label: 'AI-DRIVEN',           pos: { top: '14%',    left: '20%'  } },
  { icon: Shield,     label: '24/7 PROTECTION',     pos: { top: '34%',    right: '4%'  } },
  { icon: Radar,      label: 'REAL-TIME DETECTION', pos: { top: '54%',    left: '12%'  } },
  { icon: Building2,  label: 'ENTERPRISE GRADE',    pos: { top: '64%',    right: '6%'  } },
  { icon: Eye,        label: 'ZERO BLIND SPOTS',    pos: { bottom: '18%', left: '36%'  } },
]

// ── Animated pulse dots ───────────────────────────────────────────────────────

// Tiny green dots scattered on top of the static image. Each pulses on its own
// timing so the globe feels alive without any heavy animation.
const PULSES: Array<{
  pos: { top: string; left: string }
  delay: number
  size: number
}> = [
  { pos: { top: '24%',  left: '62%' }, delay: 0,   size: 5 },
  { pos: { top: '38%',  left: '78%' }, delay: 0.7, size: 7 },
  { pos: { top: '46%',  left: '55%' }, delay: 1.4, size: 4 },
  { pos: { top: '58%',  left: '70%' }, delay: 0.3, size: 6 },
  { pos: { top: '68%',  left: '50%' }, delay: 1.1, size: 5 },
  { pos: { top: '78%',  left: '64%' }, delay: 1.8, size: 4 },
  { pos: { top: '32%',  left: '48%' }, delay: 2.0, size: 6 },
  { pos: { top: '52%',  left: '88%' }, delay: 0.5, size: 5 },
]

function PulseDot({ top, left, delay, size }: { top: string; left: string; delay: number; size: number }) {
  return (
    <span
      aria-hidden
      className="absolute rounded-full"
      style={{
        top,
        left,
        width: size,
        height: size,
        background: '#9CFF3E',
        boxShadow: '0 0 8px rgba(124,255,0,0.85), 0 0 16px rgba(124,255,0,0.4)',
        animation: `globePulse 3.2s ease-in-out ${delay}s infinite`,
      }}
    />
  )
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function CyberGlobe({ className }: { className?: string }) {
  return (
    <div className={cn('relative w-full h-full overflow-hidden', className)}>
      {/* Static globe artwork. object-position pushes it right so the
          left edge gives breathing room for the headline text. */}
      <Image
        src="/hero-globe.jpg"
        alt=""
        fill
        priority
        sizes="(max-width: 1024px) 100vw, 68vw"
        className="object-cover"
        style={{ objectPosition: '60% center' }}
      />

      {/* Slow rotation strip — gives a hint of motion without ever drawing
          attention away from the underlying art. */}
      <div
        aria-hidden
        className="absolute inset-0 pointer-events-none"
        style={{
          animation: 'globeDrift 24s linear infinite',
          background:
            'radial-gradient(circle at 62% 50%, transparent 38%, rgba(124,255,0,0.04) 40%, transparent 42%)',
        }}
      />

      {/* Pulse dots */}
      <div className="absolute inset-0 pointer-events-none">
        {PULSES.map((p, i) => (
          <PulseDot key={i} top={p.pos.top} left={p.pos.left} delay={p.delay} size={p.size} />
        ))}
      </div>

      {/* Label pills */}
      <div className="absolute inset-0 pointer-events-none">
        {TAGS.map(({ icon: Icon, label, pos }) => (
          <div
            key={label}
            className="absolute flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-bold tracking-[0.12em] uppercase whitespace-nowrap"
            style={{
              ...pos,
              background: 'rgba(8,12,22,0.78)',
              border: '1px solid rgba(124,255,0,0.28)',
              color: '#9CFF3E',
              backdropFilter: 'blur(4px)',
              boxShadow: '0 0 14px rgba(124,255,0,0.12), 0 4px 14px rgba(0,0,0,0.45)',
            }}
          >
            <Icon className="w-3 h-3" />
            {label}
          </div>
        ))}
      </div>

      <style jsx>{`
        @keyframes globePulse {
          0%, 100% { transform: scale(1);   opacity: 0.55; }
          50%      { transform: scale(1.7); opacity: 1; }
        }
        @keyframes globeDrift {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  )
}
