'use client'

import { useEffect, useState, type FormEvent, Suspense } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { ArrowRight, CheckCircle2, Eye, EyeOff, Loader2 } from 'lucide-react'
import { api } from '@/lib/api'

function ResetPasswordContent() {
  const router = useRouter()
  const params = useSearchParams()
  const [token, setToken] = useState<string | null>(null)
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  useEffect(() => {
    const t = params.get('token')
    setToken(t)
    if (!t) setError('Missing reset token. Please request a new password reset link.')
  }, [params])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }
    if (!token) return
    setLoading(true)
    try {
      await api.auth.resetPassword(token, password)
      setSuccess(true)
      setTimeout(() => router.replace('/login'), 1800)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not reset password.')
    } finally {
      setLoading(false)
    }
  }

  if (success) {
    return (
      <div>
        <div
          className="w-12 h-12 rounded-full flex items-center justify-center mb-5"
          style={{ background: 'rgba(139,255,62,0.12)' }}
        >
          <CheckCircle2 className="w-6 h-6" style={{ color: '#8BFF3E' }} />
        </div>
        <h1 className="text-[22px] font-bold text-white tracking-tight mb-2">Password reset</h1>
        <p className="text-[13px]" style={{ color: 'rgba(255,255,255,0.5)' }}>
          Redirecting you to sign in…
        </p>
      </div>
    )
  }

  return (
    <div>
      <h1 className="text-[22px] font-bold text-white tracking-tight mb-1">Choose a new password</h1>
      <p className="text-[13px] mb-8" style={{ color: 'rgba(255,255,255,0.38)' }}>
        Pick something strong — at least 8 characters.
      </p>

      <form onSubmit={handleSubmit} className="space-y-3">
        <div>
          <label htmlFor="password" className="block text-[12px] font-medium text-gray-400 mb-1.5">
            New password
          </label>
          <div className="relative">
            <input
              id="password"
              type={showPw ? 'text' : 'password'}
              autoComplete="new-password"
              placeholder="Minimum 8 characters"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              minLength={8}
              className="w-full h-11 px-3.5 pr-11 rounded-xl text-[13.5px] text-white placeholder:text-gray-600 outline-none transition-colors"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
              onFocus={e => (e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)')}
              onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
            />
            <button
              type="button"
              tabIndex={-1}
              onClick={() => setShowPw(v => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2"
              style={{ color: 'rgba(255,255,255,0.28)' }}
            >
              {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        <div>
          <label htmlFor="confirm" className="block text-[12px] font-medium text-gray-400 mb-1.5">
            Confirm password
          </label>
          <input
            id="confirm"
            type={showPw ? 'text' : 'password'}
            autoComplete="new-password"
            placeholder="Re-enter your new password"
            value={confirm}
            onChange={e => setConfirm(e.target.value)}
            required
            minLength={8}
            className="w-full h-11 px-3.5 rounded-xl text-[13.5px] text-white placeholder:text-gray-600 outline-none transition-colors"
            style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
            onFocus={e => (e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)')}
            onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
          />
        </div>

        {error && (
          <p className="text-[12.5px] text-red-400 bg-red-500/10 border border-red-500/20 rounded-xl px-3.5 py-2.5">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={loading || !token}
          className="flex items-center justify-center gap-2 w-full h-[44px] rounded-xl text-[13.5px] font-semibold text-[#020617] transition-all duration-200 disabled:opacity-50 mt-1"
          style={{ background: '#8BFF3E', boxShadow: '0 0 20px rgba(139,255,62,0.18)' }}
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <>Reset password<ArrowRight className="w-4 h-4" /></>}
        </button>
      </form>

      <p className="mt-6 text-center text-[13px]" style={{ color: 'rgba(255,255,255,0.38)' }}>
        Back to{' '}
        <Link href="/login" className="text-accent-green font-medium hover:underline">sign in</Link>
      </p>
    </div>
  )
}

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={<div className="text-gray-500 text-[13px]">Loading…</div>}>
      <ResetPasswordContent />
    </Suspense>
  )
}
