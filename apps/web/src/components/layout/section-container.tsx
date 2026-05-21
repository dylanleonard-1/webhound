import { createElement, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

type ContainerSize = 'sm' | 'md' | 'lg' | 'xl' | 'full'
type ValidTag = 'section' | 'div' | 'article' | 'main' | 'aside' | 'header' | 'footer'

interface SectionContainerProps {
  children: ReactNode
  className?: string
  innerClassName?: string
  size?: ContainerSize
  as?: ValidTag
}

const maxWidths: Record<ContainerSize, string> = {
  sm: 'max-w-3xl',
  md: 'max-w-5xl',
  lg: 'max-w-7xl',
  xl: 'max-w-[1440px]',
  full: 'max-w-full',
}

export function SectionContainer({
  children,
  className,
  innerClassName,
  size = 'lg',
  as = 'section',
}: SectionContainerProps) {
  return createElement(
    as,
    { className: cn('px-5 sm:px-8 lg:px-12 xl:px-16', className) },
    <div className={cn('mx-auto w-full', maxWidths[size], innerClassName)}>
      {children}
    </div>,
  )
}
