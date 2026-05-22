'use client'

import { useState, type FormEvent } from 'react'
import Link from 'next/link'
import { ArrowRight, Loader2, MailCheck } from 'lucide-react'
import { api } from '@/lib/api'

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [devResetUrl, setDevResetUrl] = useState<string | null>(null)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const res = await api.auth.forgotPassword(email)
      setDevResetUrl(res.dev_reset_url ?? null)
      setSubmitted(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong.')
    } finally {
      setLoading(false)
    }
  }

  if (submitted) {
    return (
      <div>
        <div
          className="w-12 h-12 rounded-full flex items-center justify-center mb-5"
          style={{ background: 'rgba(139,255,62,0.12)' }}
        >
          <MailCheck className="w-6 h-6" style={{ color: '#8BFF3E' }} />
        </div>
        <h1 className="text-[22px] font-bold text-white tracking-tight mb-2">Check your email</h1>
        <p className="text-[13px] leading-relaxed mb-6" style={{ color: 'rgba(255,255,255,0.5)' }}>
          If an account exists for <span className="text-white">{email}</span>, we&apos;ve sent a link to reset your password.
          The link expires in 1 hour.
        </p>
        {devResetUrl && (
          <div
            className="mb-6 p-3 rounded-xl text-[12px] break-all"
            style={{ background: 'rgba(139,255,62,0.05)', border: '1px solid rgba(139,255,62,0.2)', color: 'rgba(255,255,255,0.7)' }}
          >
            <p className="font-medium mb-1" style={{ color: '#8BFF3E' }}>Dev mode reset link:</p>
            <Link href={devResetUrl.replace(/^.*?\/reset-password/, '/reset-password')} className="underline">
              {devResetUrl}
            </Link>
          </div>
        )}
        <Link
          href="/login"
          className="block w-full text-center h-[44px] leading-[44px] rounded-xl text-[13.5px] font-semibold text-[#020617]"
          style={{ background: '#8BFF3E', boxShadow: '0 0 20px rgba(139,255,62,0.18)' }}
        >
          Back to sign in
        </Link>
      </div>
    )
  }

  return (
    <div>
      <h1 className="text-[22px] font-bold text-white tracking-tight mb-1">Forgot your password?</h1>
      <p className="text-[13px] mb-8" style={{ color: 'rgba(255,255,255,0.38)' }}>
        Enter your email and we&apos;ll send you a link to reset it.
      </p>

      <form onSubmit={handleSubmit} className="space-y-3">
        <div>
          <label htmlFor="email" className="block text-[12px] font-medium text-gray-400 mb-1.5">
            Email address
          </label>
          <input
            id="email"
            type="email"
            placeholder="you@example.com"
            autoComplete="email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            required
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
          disabled={loading}
          className="flex items-center justify-center gap-2 w-full h-[44px] rounded-xl text-[13.5px] font-semibold text-[#020617] transition-all duration-200 disabled:opacity-50 mt-1"
          style={{ background: '#8BFF3E', boxShadow: '0 0 20px rgba(139,255,62,0.18)' }}
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <>Send reset link<ArrowRight className="w-4 h-4" /></>}
        </button>
      </form>

      <p className="mt-6 text-center text-[13px]" style={{ color: 'rgba(255,255,255,0.38)' }}>
        Remembered it?{' '}
        <Link href="/login" className="text-accent-green font-medium hover:underline">Sign in</Link>
      </p>
    </div>
  )
}
