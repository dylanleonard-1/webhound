import type { ReactNode } from 'react'
import { Logo } from '@/components/marketing/logo'

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-app-bg flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center justify-center mb-8">
          <Logo size="md" />
        </div>
        {children}
      </div>
    </div>
  )
}
