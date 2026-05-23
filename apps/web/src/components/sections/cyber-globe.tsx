'use client'

import Image from 'next/image'
import { cn } from '@/lib/utils'

// Hero background globe — just the artwork, with edges fading into the
// surrounding dark so it doesn't sit on the page as a hard rectangle.

const FADE_MASK =
  // Fade out left edge (toward headline text) and a softer fade on the
  // top / bottom / right so the image blends into the page background.
  'linear-gradient(to right,  transparent 0%, black 28%, black 100%), ' +
  'linear-gradient(to bottom, transparent 0%, black 12%, black 88%, transparent 100%)'

export default function CyberGlobe({ className }: { className?: string }) {
  return (
    <div className={cn('relative w-full h-full overflow-hidden', className)}>
      <div
        className="absolute inset-0"
        style={{
          WebkitMaskImage: FADE_MASK,
          maskImage: FADE_MASK,
          WebkitMaskComposite: 'source-in',
          maskComposite: 'intersect',
        }}
      >
        <Image
          src="/hero-globe.jpg"
          alt=""
          fill
          priority
          sizes="(max-width: 1024px) 100vw, 68vw"
          className="object-cover"
          style={{ objectPosition: '60% center' }}
        />
      </div>
    </div>
  )
}
