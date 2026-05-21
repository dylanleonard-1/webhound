'use client'

import { useState } from 'react'
import Link from 'next/link'
import { Mail, Loader2, CheckCircle2 } from 'lucide-react'
import { api } from '@/lib/api'

export default function VerifyEmailPage() {
  const [resent, setResent] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleResend() {
    setLoading(true)
    setError(null)
    try {
      await api.auth.resendVerification()
      setResent(true)
    } catch {
      setError('Could not resend email. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="text-center">
      <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl mb-5"
           style={{ background: 'rgba(139,255,62,0.08)', border: '1px solid rgba(139,255,62,0.18)' }}>
        <Mail className="w-6 h-6 text-accent-green" />
      </div>

      <h1 className="text-[20px] font-bold text-white tracking-tight mb-2">
        Check your email
      </h1>
      <p className="text-[13px] mb-8 leading-relaxed" style={{ color: 'rgba(255,255,255,0.45)' }}>
        We sent a verification link to your email address.<br />
        Click the link to activate your account.
      </p>

      {resent ? (
        <div className="flex items-center justify-center gap-2 text-[13px] text-accent-green mb-6">
          <CheckCircle2 className="w-4 h-4" />
          Verification email resent
        </div>
      ) : (
        <div className="mb-6">
          <p className="text-[12px] mb-3" style={{ color: 'rgba(255,255,255,0.30)' }}>
            Didn&apos;t receive it?
          </p>
          <button
            onClick={handleResend}
            disabled={loading}
            className="text-[13px] font-medium text-accent-green hover:underline disabled:opacity-50 flex items-center gap-1.5 mx-auto"
          >
            {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            Resend verification email
          </button>
        </div>
      )}

      {error && (
        <p className="text-[12px] text-red-400 mb-4">{error}</p>
      )}

      <p className="text-[12px]" style={{ color: 'rgba(255,255,255,0.22)' }}>
        <Link href="/login" className="hover:text-white transition-colors">
          Back to sign in
        </Link>
      </p>
    </div>
  )
}
