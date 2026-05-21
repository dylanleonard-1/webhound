import { cn } from '@/lib/utils'

interface LogoProps {
  variant?: 'mark' | 'full'
  size?: 'sm' | 'md' | 'lg' | 'xl'
  className?: string
}

const SIZE_MAP = {
  sm: { mark: 24, text: 'text-base' },
  md: { mark: 32, text: 'text-xl' },
  lg: { mark: 40, text: 'text-2xl' },
  xl: { mark: 56, text: 'text-3xl' },
}

function HoundMark({ size }: { size: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      {/* Shield outline */}
      <path
        d="M16 1L30 8V25L16 31L2 25V8L16 1Z"
        stroke="#00E5A8"
        strokeWidth="1.5"
        fill="rgba(0,229,168,0.05)"
        strokeLinejoin="round"
      />
      {/* Hound head: two pointed ears, forehead dip, rounded muzzle */}
      <path
        d="M8 22L9 16L12 9L16 13L20 9L23 16L24 22Q24 27 16 28Q8 27 8 22Z"
        stroke="#00E5A8"
        strokeWidth="1.4"
        fill="none"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      {/* Eyes */}
      <circle cx="12.5" cy="19" r="1.5" fill="#00E5A8" />
      <circle cx="19.5" cy="19" r="1.5" fill="#00E5A8" />
      {/* Scan arc — monitoring signal */}
      <path
        d="M5 27.5Q16 23.5 27 27.5"
        stroke="#00E5A8"
        strokeWidth="0.75"
        strokeLinecap="round"
        fill="none"
        opacity="0.4"
      />
    </svg>
  )
}

export function Logo({ variant = 'full', size = 'md', className }: LogoProps) {
  const { mark, text } = SIZE_MAP[size]

  if (variant === 'mark') {
    return (
      <span className={cn('inline-flex flex-shrink-0', className)}>
        <HoundMark size={mark} />
      </span>
    )
  }

  return (
    <span className={cn('inline-flex items-center gap-2.5 select-none', className)}>
      <HoundMark size={mark} />
      <span className={cn('font-semibold tracking-tight text-white leading-none', text)}>
        WebHound
      </span>
    </span>
  )
}
