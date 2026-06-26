'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/contexts/auth'
import { LoadingState } from '@/components/loading-state'

// Dev-bypass: `npm run dev` runs ONLY the Next frontend — the FastAPI auth
// backend + DB aren't up locally, so useAuth never resolves a user and the gate
// would redirect forever, blocking local content/mobile review. So in non-production
// (or with an explicit opt-in flag) we render the academy without auth. In a real
// production build (NODE_ENV === 'production') the full gate stays in force.
// process.env.NODE_ENV / NEXT_PUBLIC_* are statically inlined by Next at build time.
const DEV_OPEN =
  process.env.NODE_ENV !== 'production' ||
  process.env.NEXT_PUBLIC_ACADEMY_DEV_OPEN === '1'

/**
 * Route-level auth gate for /academy/* — in PRODUCTION it mirrors the dashboard
 * layout guard exactly (useAuth({ user, loading }) → redirect to /login when
 * unauthenticated). In local dev it bypasses (see DEV_OPEN above). Scoped to the
 * academy route group only; introduces no new auth scheme.
 */
export function AcademyGuard({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (DEV_OPEN) return
    if (!loading && !user) {
      router.replace('/login')
    }
  }, [user, loading, router])

  // Local dev / opt-in: render without auth so content can be reviewed offline.
  if (DEV_OPEN) return <>{children}</>

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
