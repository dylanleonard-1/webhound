'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/contexts/auth'
import { LoadingState } from '@/components/loading-state'

/**
 * Route-level auth gate for /academy/* — mirrors the dashboard layout guard
 * exactly (same useAuth({ user, loading }) check and /login redirect). Scoped
 * to the academy route group only; introduces no new auth scheme.
 */
export function AcademyGuard({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!loading && !user) {
      router.replace('/login')
    }
  }, [user, loading, router])

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-app-bg">
        <LoadingState />
      </div>
    )
  }

  if (!user) return null

  return <>{children}</>
}
