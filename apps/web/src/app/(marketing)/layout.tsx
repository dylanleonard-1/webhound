import type { ReactNode } from 'react'
import { PublicNav } from '@/components/marketing/public-nav'
import { PublicFooter } from '@/components/marketing/public-footer'
import { LenisProvider } from '@/lib/lenis-provider'

export default function MarketingLayout({ children }: { children: ReactNode }) {
  return (
    <LenisProvider>
      <div className="min-h-screen flex flex-col">
        <PublicNav />
        <main className="flex-1 pt-16">{children}</main>
        <PublicFooter />
      </div>
    </LenisProvider>
  )
}
