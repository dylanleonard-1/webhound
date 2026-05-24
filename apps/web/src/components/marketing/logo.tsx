import Image from 'next/image'
import { cn } from '@/lib/utils'

interface LogoProps {
  variant?: 'mark' | 'full'
  size?: 'sm' | 'md' | 'lg' | 'xl'
  className?: string
  /** Override the text shown next to the mark. Defaults to "WebHound". */
  text?: string
}

const SIZE_MAP = {
  sm: { mark: 24, text: 'text-base' },
  md: { mark: 32, text: 'text-xl' },
  lg: { mark: 40, text: 'text-2xl' },
  xl: { mark: 56, text: 'text-3xl' },
}

function HoundMark({ size }: { size: number }) {
  return (
    <Image
      src="/logo.png"
      alt="WebHound"
      width={size}
      height={size}
      priority={size >= 40}
      className="flex-shrink-0 select-none"
      style={{ width: size, height: size, objectFit: 'contain' }}
    />
  )
}

export function Logo({
  variant = 'full', size = 'md', className, text = 'WebHound',
}: LogoProps) {
  const { mark, text: textSize } = SIZE_MAP[size]

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
      <span className={cn('font-semibold tracking-tight text-white leading-none', textSize)}>
        {text}
      </span>
    </span>
  )
}
