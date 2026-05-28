'use client'

import { useState, useRef, useEffect, useMemo, type FormEvent } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { ArrowRight, Eye, EyeOff, Loader2 } from 'lucide-react'
import { useAuth } from '@/contexts/auth'
import type { LoginChallenge, UseCase } from '@/lib/api'
import { resolvePostLoginPath } from '@/lib/post-login'

const USE_CASES: Array<{ value: UseCase; label: string }> = [
  { value: 'developer',         label: 'Developer' },
  { value: 'security_engineer', label: 'Security engineer' },
  { value: 'founder',           label: 'Founder / owner' },
  { value: 'agency',            label: 'Agency / consultant' },
  { value: 'it_team',           label: 'IT / ops team' },
  { value: 'other',             label: 'Something else' },
]

const API_BASE =
  (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_API_URL) ||
  'https://api.webhoundsecurity.com'

// ── Brand icons ───────────────────────────────────────────────────────────────

function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden>
      <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
      <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
      <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
      <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
    </svg>
  )
}

function GitHubIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
    </svg>
  )
}

const PROVIDERS = [
  {
    id: 'google',
    label: 'Continue with Google',
    Icon: GoogleIcon,
    style: { background: '#ffffff', color: '#1f1f1f', border: '1px solid rgba(0,0,0,0.12)' },
  },
  {
    id: 'github',
    label: 'Continue with GitHub',
    Icon: GitHubIcon,
    style: { background: 'rgba(255,255,255,0.07)', color: '#ffffff', border: '1px solid rgba(255,255,255,0.12)' },
  },
]

// ── Login: 6-digit code step ──────────────────────────────────────────────────

function LoginCodeStep({
  challenge,
  onVerify,
  onResend,
  onBack,
}: {
  challenge: LoginChallenge
  onVerify: (code: string) => Promise<void>
  onResend: () => Promise<{ devCode?: string }>
  onBack: () => void
}) {
  const [digits, setDigits] = useState<string[]>(['', '', '', '', '', ''])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [resending, setResending] = useState(false)
  const [resentDev, setResentDev] = useState<string | null>(challenge.dev_code ?? null)
  const inputs = useRef<Array<HTMLInputElement | null>>([])

  useEffect(() => { inputs.current[0]?.focus() }, [])

  function setDigit(i: number, raw: string) {
    const clean = raw.replace(/\D/g, '').slice(-1)
    const next = [...digits]
    next[i] = clean
    setDigits(next)
    if (clean && i < 5) inputs.current[i + 1]?.focus()
  }

  function handlePaste(e: React.ClipboardEvent<HTMLInputElement>) {
    const text = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)
    if (!text) return
    e.preventDefault()
    const next = ['', '', '', '', '', '']
    for (let i = 0; i < text.length; i++) next[i] = text[i]
    setDigits(next)
    const focusIdx = Math.min(text.length, 5)
    inputs.current[focusIdx]?.focus()
  }

  function handleKey(i: number, e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Backspace' && !digits[i] && i > 0) {
      inputs.current[i - 1]?.focus()
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    const code = digits.join('')
    if (code.length !== 6) {
      setError('Enter all 6 digits.')
      return
    }
    setLoading(true)
    try {
      await onVerify(code)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid code.')
    } finally {
      setLoading(false)
    }
  }

  async function resend() {
    setResending(true)
    setError(null)
    try {
      const res = await onResend()
      if (res.devCode) setResentDev(res.devCode)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not resend.')
    } finally {
      setResending(false)
    }
  }

  return (
    <div>
      <h1 className="text-[22px] font-bold text-white tracking-tight mb-1">Enter your code</h1>
      <p className="text-[13px] mb-6 leading-relaxed" style={{ color: 'rgba(255,255,255,0.45)' }}>
        We sent a 6-digit code to <span className="text-white">{challenge.email}</span>.
        {challenge.delivery !== 'failed' && (
          <span className="block mt-1 text-[11.5px]" style={{ color: 'rgba(255,255,255,0.32)' }}>
            Check your spam folder if you don&apos;t see it.
          </span>
        )}
      </p>

      {resentDev && (
        <div
          className="mb-4 p-3 rounded-xl text-[12px] flex items-center justify-between"
          style={{ background: 'rgba(139,255,62,0.05)', border: '1px solid rgba(139,255,62,0.2)' }}
        >
          <span style={{ color: 'rgba(255,255,255,0.6)' }}>
            Your code: <span className="font-mono font-bold text-[15px]" style={{ color: '#8BFF3E' }}>{resentDev}</span>
          </span>
        </div>
      )}

      {challenge.delivery === 'failed' && !resentDev && (
        <div
          className="mb-4 p-3 rounded-xl text-[12px]"
          style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)', color: 'rgba(255,255,255,0.7)' }}
        >
          We couldn&apos;t send the code. Try the resend button below, or contact support if it keeps failing.
        </div>
      )}

      <form onSubmit={submit} className="space-y-4">
        <div className="flex gap-2 justify-between">
          {digits.map((d, i) => (
            <input
              key={i}
              ref={el => { inputs.current[i] = el }}
              inputMode="numeric"
              autoComplete={i === 0 ? 'one-time-code' : 'off'}
              maxLength={1}
              value={d}
              onChange={e => setDigit(i, e.target.value)}
              onKeyDown={e => handleKey(i, e)}
              onPaste={handlePaste}
              className="w-[14.5%] aspect-square text-center text-white text-[20px] font-semibold rounded-xl outline-none transition-colors"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
              onFocus={e => (e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)')}
              onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
            />
          ))}
        </div>

        {error && (
          <p className="text-[12.5px] text-red-400 bg-red-500/10 border border-red-500/20 rounded-xl px-3.5 py-2.5">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={loading}
          className="flex items-center justify-center gap-2 w-full h-[44px] rounded-xl text-[13.5px] font-semibold text-[#020617] disabled:opacity-50"
          style={{ background: '#8BFF3E', boxShadow: '0 0 20px rgba(139,255,62,0.18)' }}
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <>Verify<ArrowRight className="w-4 h-4" /></>}
        </button>
      </form>

      <div className="mt-5 flex flex-col items-center gap-2 text-[12.5px]">
        <button
          type="button"
          onClick={resend}
          disabled={resending}
          className="font-medium hover:underline disabled:opacity-50"
          style={{ color: 'rgba(139,255,62,0.85)' }}
        >
          {resending ? 'Sending…' : 'Resend code'}
        </button>
        <button
          type="button"
          onClick={onBack}
          className="hover:underline"
          style={{ color: 'rgba(255,255,255,0.38)' }}
        >
          Use a different account
        </button>
      </div>
    </div>
  )
}

// ── Auth form ─────────────────────────────────────────────────────────────────

interface AuthFormProps {
  mode: 'login' | 'register'
}

/**
 * Validate + normalise a `next` query param. Only same-origin relative
 * paths are allowed (must start with a single `/`, not `//`). Defends
 * against open-redirect via crafted `?next=https://evil.example`.
 */
function safeNext(raw: string | null | undefined): string {
  if (!raw) return '/dashboard'
  const trimmed = raw.trim()
  if (!trimmed.startsWith('/')) return '/dashboard'
  if (trimmed.startsWith('//')) return '/dashboard'
  if (trimmed.includes('://')) return '/dashboard'
  return trimmed
}

const NEXT_STORAGE_KEY = 'webhound:auth_next'

export function AuthForm({ mode }: AuthFormProps) {
  const { initiateLogin, verifyLoginCode, resendLoginCode, register } = useAuth()
  const router = useRouter()
  const searchParams = useSearchParams()

  // The `?next=` param is the post-auth destination. It can be passed
  // either as a query string or persisted across the verify-email round
  // trip via sessionStorage.
  const nextPath = useMemo(
    () => safeNext(searchParams?.get('next')),
    [searchParams],
  )

  useEffect(() => {
    // Persist for the verify-email leg (separate route).
    if (nextPath && nextPath !== '/dashboard') {
      sessionStorage.setItem(NEXT_STORAGE_KEY, nextPath)
    }
  }, [nextPath])

  function consumeNext(): string {
    if (typeof window === 'undefined') return nextPath
    const stored = sessionStorage.getItem(NEXT_STORAGE_KEY)
    sessionStorage.removeItem(NEXT_STORAGE_KEY)
    return safeNext(stored ?? nextPath)
  }

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [challenge, setChallenge] = useState<LoginChallenge | null>(null)
  // Register-only fields
  const [fullName, setFullName] = useState('')
  const [companyName, setCompanyName] = useState('')
  const [useCase, setUseCase] = useState<UseCase | ''>('')
  const [agreedTerms, setAgreedTerms] = useState(false)

  const isLogin = mode === 'login'

  function handleOAuth(provider: string) {
    window.location.href = `${API_BASE}/auth/oauth/${provider}/authorize`
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      if (isLogin) {
        const step = await initiateLogin(email, password)
        if (step.kind === 'signed_in') {
          // Legacy API path — route staff to /control, customers to /dashboard,
          // explicit ?next= always wins.
          router.replace(await resolvePostLoginPath(consumeNext()))
        } else {
          setChallenge(step.challenge)
        }
      } else {
        if (!agreedTerms) {
          setError('You must agree to the Terms, Privacy Policy, and Acceptable Use Policy before creating an account.')
          setLoading(false)
          return
        }
        const { devVerifyUrl } = await register({
          email,
          password,
          full_name: fullName || null,
          company_name: companyName || null,
          use_case: useCase || null,
        })
        if (devVerifyUrl) sessionStorage.setItem('dev_verify_url', devVerifyUrl)
        // next is preserved in sessionStorage; verify-email page consumes it.
        router.replace('/verify-email')
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong.')
    } finally {
      setLoading(false)
    }
  }

  // Login: code step
  if (isLogin && challenge) {
    return (
      <LoginCodeStep
        challenge={challenge}
        onVerify={async code => {
          await verifyLoginCode(challenge.challenge_token, code)
          router.replace(await resolvePostLoginPath(consumeNext()))
        }}
        onResend={() => resendLoginCode(challenge.challenge_token)}
        onBack={() => setChallenge(null)}
      />
    )
  }

  return (
    <div>
      {/* Header */}
      <h1 className="text-[22px] font-bold text-white tracking-tight mb-1">
        {isLogin ? 'Welcome back' : 'Create your account'}
      </h1>
      <p className="text-[13px] mb-8" style={{ color: 'rgba(255,255,255,0.38)' }}>
        {isLogin ? 'Sign in to continue to WebHound.' : 'Start monitoring your websites for free.'}
      </p>

      {/* OAuth buttons */}
      <div className="flex flex-col gap-2.5 mb-6">
        {PROVIDERS.map(({ id, label, Icon, style }) => (
          <button
            key={id}
            type="button"
            onClick={() => handleOAuth(id)}
            className="flex items-center justify-center gap-2.5 w-full h-[44px] rounded-xl text-[13.5px] font-medium transition-opacity duration-150 hover:opacity-80 active:scale-[0.98]"
            style={style}
          >
            <Icon />
            {label}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-3 mb-6">
        <div className="flex-1 h-px" style={{ background: 'rgba(255,255,255,0.07)' }} />
        <span className="text-[11px] font-medium uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.22)' }}>or</span>
        <div className="flex-1 h-px" style={{ background: 'rgba(255,255,255,0.07)' }} />
      </div>

      <form onSubmit={handleSubmit} className="space-y-3">
        {!isLogin && (
          <>
            <div>
              <label htmlFor="fullName" className="block text-[12px] font-medium text-gray-400 mb-1.5">
                Full name
              </label>
              <input
                id="fullName" type="text" placeholder="Jane Doe" autoComplete="name"
                value={fullName} onChange={e => setFullName(e.target.value)} required
                className="w-full h-11 px-3.5 rounded-xl text-[13.5px] text-white placeholder:text-gray-600 outline-none transition-colors"
                style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
                onFocus={e => (e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)')}
                onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
              />
            </div>

            <div>
              <label htmlFor="companyName" className="block text-[12px] font-medium text-gray-400 mb-1.5">
                Company <span className="text-gray-600">(optional)</span>
              </label>
              <input
                id="companyName" type="text" placeholder="Acme Inc." autoComplete="organization"
                value={companyName} onChange={e => setCompanyName(e.target.value)}
                className="w-full h-11 px-3.5 rounded-xl text-[13.5px] text-white placeholder:text-gray-600 outline-none transition-colors"
                style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
                onFocus={e => (e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)')}
                onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
              />
            </div>

            <div>
              <label htmlFor="useCase" className="block text-[12px] font-medium text-gray-400 mb-1.5">
                What best describes you?
              </label>
              <select
                id="useCase"
                value={useCase}
                onChange={e => setUseCase(e.target.value as UseCase | '')}
                required
                className="w-full h-11 px-3 rounded-xl text-[13.5px] text-white outline-none transition-colors appearance-none"
                style={{
                  background: 'rgba(255,255,255,0.04)',
                  border: '1px solid rgba(255,255,255,0.08)',
                  backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%23a3a3a3' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E\")",
                  backgroundRepeat: 'no-repeat',
                  backgroundPosition: 'right 14px center',
                  paddingRight: '36px',
                }}
                onFocus={e => (e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)')}
                onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
              >
                <option value="" disabled className="bg-[#0a0f1c] text-gray-500">Select an option</option>
                {USE_CASES.map(opt => (
                  <option key={opt.value} value={opt.value} className="bg-[#0a0f1c] text-white">
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          </>
        )}

        <div>
          <label htmlFor="email" className="block text-[12px] font-medium text-gray-400 mb-1.5">Email address</label>
          <input
            id="email" type="email" placeholder="you@example.com" autoComplete="email"
            value={email} onChange={e => setEmail(e.target.value)} required
            className="w-full h-11 px-3.5 rounded-xl text-[13.5px] text-white placeholder:text-gray-600 outline-none transition-colors"
            style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
            onFocus={e => (e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)')}
            onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
          />
        </div>

        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label htmlFor="password" className="text-[12px] font-medium text-gray-400">Password</label>
            {isLogin && (
              <Link
                href="/forgot-password"
                className="text-[11px] transition-colors"
                style={{ color: 'rgba(255,255,255,0.30)' }}
                onMouseEnter={e => (e.currentTarget.style.color = 'rgba(139,255,62,0.8)')}
                onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.30)')}
              >
                Forgot password?
              </Link>
            )}
          </div>
          <div className="relative">
            <input
              id="password"
              type={showPw ? 'text' : 'password'}
              autoComplete={isLogin ? 'current-password' : 'new-password'}
              placeholder={isLogin ? '••••••••' : 'Minimum 8 characters'}
              value={password}
              onChange={e => setPassword(e.target.value)}
              required minLength={8}
              className="w-full h-11 px-3.5 pr-11 rounded-xl text-[13.5px] text-white placeholder:text-gray-600 outline-none transition-colors"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
              onFocus={e => (e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)')}
              onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
            />
            <button
              type="button" tabIndex={-1}
              onClick={() => setShowPw(v => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
              style={{ color: 'rgba(255,255,255,0.28)' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.6)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.28)')}
            >
              {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {!isLogin && (
          <label
            htmlFor="agreedTerms"
            className="flex items-start gap-2.5 cursor-pointer select-none rounded-xl px-3.5 py-3 transition-colors"
            style={{
              background: agreedTerms ? 'rgba(139,255,62,0.06)' : 'rgba(255,255,255,0.02)',
              border: agreedTerms
                ? '1px solid rgba(139,255,62,0.3)'
                : '1px solid rgba(255,255,255,0.08)',
            }}
          >
            <input
              id="agreedTerms"
              type="checkbox"
              checked={agreedTerms}
              onChange={e => setAgreedTerms(e.target.checked)}
              required
              className="mt-0.5 flex-shrink-0 w-4 h-4 rounded cursor-pointer accent-accent-green"
              style={{ accentColor: '#8BFF3E' }}
            />
            <span className="text-[12px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.7)' }}>
              I&apos;ve read and agree to the{' '}
              <Link href="/terms" target="_blank" className="text-accent-green hover:underline">Terms of Service</Link>,{' '}
              <Link href="/privacy" target="_blank" className="text-accent-green hover:underline">Privacy Policy</Link>, and{' '}
              <Link href="/acceptable-use" target="_blank" className="text-accent-green hover:underline">Acceptable Use Policy</Link>.
              I will only scan websites I own or am authorised to test.
            </span>
          </label>
        )}

        {error && (
          <p className="text-[12.5px] text-red-400 bg-red-500/10 border border-red-500/20 rounded-xl px-3.5 py-2.5">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={loading || (!isLogin && !agreedTerms)}
          className="flex items-center justify-center gap-2 w-full h-[44px] rounded-xl text-[13.5px] font-semibold text-[#020617] transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed mt-1"
          style={{ background: '#8BFF3E', boxShadow: '0 0 20px rgba(139,255,62,0.18)' }}
          onMouseEnter={e => !loading && (e.currentTarget.style.boxShadow = '0 0 28px rgba(139,255,62,0.35)')}
          onMouseLeave={e => (e.currentTarget.style.boxShadow = '0 0 20px rgba(139,255,62,0.18)')}
        >
          {loading
            ? <Loader2 className="w-4 h-4 animate-spin" />
            : <>{isLogin ? 'Continue' : 'Create account'}<ArrowRight className="w-4 h-4" /></>
          }
        </button>
      </form>

      <p className="mt-6 text-center text-[13px]" style={{ color: 'rgba(255,255,255,0.38)' }}>
        {isLogin ? (
          <>No account?{' '}<Link
            href={nextPath !== '/dashboard'
              ? `/register?next=${encodeURIComponent(nextPath)}`
              : '/register'}
            className="text-accent-green font-medium hover:underline"
          >Sign up free</Link></>
        ) : (
          <>Already have an account?{' '}<Link
            href={nextPath !== '/dashboard'
              ? `/login?next=${encodeURIComponent(nextPath)}`
              : '/login'}
            className="text-accent-green font-medium hover:underline"
          >Sign in</Link></>
        )}
      </p>

      {!isLogin && (
        <p className="mt-4 text-center text-[11px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.22)' }}>
          By creating an account you agree to our{' '}
          <Link href="/terms" className="hover:text-gray-400 transition-colors">Terms</Link>
          {' '}and{' '}
          <Link href="/privacy" className="hover:text-gray-400 transition-colors">Privacy Policy</Link>.
        </p>
      )}
    </div>
  )
}
