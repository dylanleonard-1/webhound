'use client'

import { usePathname } from 'next/navigation'
import { PublicNav } from '@/components/marketing/public-nav'

export function HomepageNav() {
  const pathname = usePathname()
  return pathname === '/' ? <PublicNav /> : null
}
