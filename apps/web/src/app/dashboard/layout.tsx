'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/contexts/auth'
import { AppShell } from '@/components/app-shell'
import { LoadingState } from '@/components/loading-state'

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!loading && !user) {
      router.replace('/login')
    }
  }, [user, loading, router])

  if (loading) {
    return (
      <div className="min-h-screen bg-app-bg flex items-center justify-center">
        <LoadingState />
      </div>
    )
  }

  if (!user) return null

  return (
    <AppShell>
      {children}
    </AppShell>
  )
}
