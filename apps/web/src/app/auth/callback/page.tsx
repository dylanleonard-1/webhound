'use client'

import { useEffect, useState, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { Loader2, AlertCircle } from 'lucide-react'
import { useAuth } from '@/contexts/auth'
import { Logo } from '@/components/marketing/logo'
import { resolvePostLoginPath } from '@/lib/post-login'

function CallbackInner() {
  const { loginWithToken } = useAuth()
  const router = useRouter()
  const params = useSearchParams()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const token = params.get('token')
    const err   = params.get('error')

    if (err) {
      const messages: Record<string, string> = {
        google_auth_failed: 'Google sign-in failed. Please try again.',
        github_auth_failed: 'GitHub sign-in failed. Please try again.',
      }
      setError(messages[err] ?? 'Sign-in failed. Please try again.')
      return
    }

    if (!token) {
      setError('No authentication token received.')
      return
    }

    // OAuth flow has no ?next= param of its own; pass '/dashboard' as the
    // default and let resolvePostLoginPath escalate to /control for staff.
    loginWithToken(token)
      .then(() => resolvePostLoginPath('/dashboard'))
      .then(dest => router.replace(dest))
      .catch(() => setError('Failed to complete sign-in. Please try again.'))
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  if (error) {
    return (
      <div className="text-center">
        <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-red-500/10 border border-red-500/20 mb-4">
          <AlertCircle className="w-5 h-5 text-red-400" />
        </div>
        <p className="text-[13.5px] text-red-400 mb-6">{error}</p>
        <Link
          href="/login"
          className="text-[13px] font-medium text-accent-green hover:underline"
        >
          Back to sign in
        </Link>
      </div>
    )
  }

  return (
    <div className="text-center">
      <Loader2 className="w-6 h-6 animate-spin text-accent-green mx-auto mb-3" />
      <p className="text-[13px]" style={{ color: 'rgba(255,255,255,0.38)' }}>
        Completing sign-in…
      </p>
    </div>
  )
}

export default function AuthCallbackPage() {
  return (
    <div className="min-h-screen bg-app-bg flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center justify-center mb-8">
          <Logo size="md" />
        </div>
        <Suspense fallback={
          <div className="text-center">
            <Loader2 className="w-6 h-6 animate-spin text-accent-green mx-auto" />
          </div>
        }>
          <CallbackInner />
        </Suspense>
      </div>
    </div>
  )
}
