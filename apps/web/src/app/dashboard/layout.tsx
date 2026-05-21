'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Mail, X, Loader2 } from 'lucide-react'
import { useAuth } from '@/contexts/auth'
import { AppShell } from '@/components/app-shell'
import { LoadingState } from '@/components/loading-state'
import { api } from '@/lib/api'

function EmailVerificationBanner() {
  const [dismissed, setDismissed] = useState(false)
  const [resent, setResent] = useState(false)
  const [loading, setLoading] = useState(false)

  async function handleResend() {
    setLoading(true)
    try {
      await api.auth.resendVerification()
      setResent(true)
    } finally {
      setLoading(false)
    }
  }

  if (dismissed) return null

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 text-[12.5px]"
         style={{ background: 'rgba(251,191,36,0.08)', borderBottom: '1px solid rgba(251,191,36,0.18)' }}>
      <Mail className="w-3.5 h-3.5 flex-shrink-0" style={{ color: '#fbbf24' }} />
      <span style={{ color: 'rgba(255,255,255,0.65)' }}>
        Please verify your email address to unlock all features.
      </span>
      {!resent ? (
        <button
          onClick={handleResend}
          disabled={loading}
          className="flex items-center gap-1 font-medium transition-opacity hover:opacity-80 disabled:opacity-50 ml-1"
          style={{ color: '#fbbf24' }}
        >
          {loading && <Loader2 className="w-3 h-3 animate-spin" />}
          Resend email
        </button>
      ) : (
        <span className="font-medium ml-1" style={{ color: '#4ade80' }}>Sent!</span>
      )}
      <button
        onClick={() => setDismissed(true)}
        className="ml-auto transition-opacity hover:opacity-60"
        style={{ color: 'rgba(255,255,255,0.35)' }}
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}

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
      {!user.email_verified && <EmailVerificationBanner />}
      {children}
    </AppShell>
  )
}
