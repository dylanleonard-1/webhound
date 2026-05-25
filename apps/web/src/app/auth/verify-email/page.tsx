'use client'

import { useEffect, useState, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { Loader2, CheckCircle2, AlertCircle } from 'lucide-react'
import { api } from '@/lib/api'
import { Logo } from '@/components/marketing/logo'

function VerifyInner() {
  const router = useRouter()
  const params = useSearchParams()
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading')
  const [message, setMessage] = useState('')

  useEffect(() => {
    const token = params.get('token')
    if (!token) {
      setStatus('error')
      setMessage('No verification token found.')
      return
    }
    api.auth.verifyEmail(token)
      .then(() => {
        setStatus('success')
        // Honor a previously-stashed ?next= from the register flow.
        const stored = sessionStorage.getItem('webhound:auth_next')
        sessionStorage.removeItem('webhound:auth_next')
        const dest = stored && stored.startsWith('/') && !stored.startsWith('//')
          && !stored.includes('://') ? stored : '/dashboard'
        setTimeout(() => router.replace(dest), 2500)
      })
      .catch((err: Error) => {
        setStatus('error')
        setMessage(err.message || 'Verification failed. The link may have expired.')
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  if (status === 'loading') {
    return (
      <div className="text-center">
        <Loader2 className="w-6 h-6 animate-spin text-accent-green mx-auto mb-3" />
        <p className="text-[13px]" style={{ color: 'rgba(255,255,255,0.38)' }}>
          Verifying your email…
        </p>
      </div>
    )
  }

  if (status === 'success') {
    return (
      <div className="text-center">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl mb-5"
             style={{ background: 'rgba(139,255,62,0.08)', border: '1px solid rgba(139,255,62,0.18)' }}>
          <CheckCircle2 className="w-6 h-6 text-accent-green" />
        </div>
        <h1 className="text-[20px] font-bold text-white mb-2">Email verified!</h1>
        <p className="text-[13px]" style={{ color: 'rgba(255,255,255,0.45)' }}>
          Redirecting you to your dashboard…
        </p>
      </div>
    )
  }

  return (
    <div className="text-center">
      <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-red-500/10 border border-red-500/20 mb-4">
        <AlertCircle className="w-5 h-5 text-red-400" />
      </div>
      <p className="text-[13.5px] text-red-400 mb-6">{message}</p>
      <Link href="/login" className="text-[13px] font-medium text-accent-green hover:underline">
        Back to sign in
      </Link>
    </div>
  )
}

export default function VerifyEmailPage() {
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
          <VerifyInner />
        </Suspense>
      </div>
    </div>
  )
}
