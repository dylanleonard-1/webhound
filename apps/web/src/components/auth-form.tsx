'use client'

import { useState, type FormEvent } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Eye, EyeOff, ArrowRight, Loader2 } from 'lucide-react'
import { useAuth } from '@/contexts/auth'

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

// ── OAuth providers config ────────────────────────────────────────────────────

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

// ── Input field ───────────────────────────────────────────────────────────────

function Field({
  id, label, type, placeholder, autoComplete, value, onChange, minLength, extra,
}: {
  id: string; label: string; type: string; placeholder: string
  autoComplete: string; value: string; onChange: (v: string) => void
  minLength?: number; extra?: React.ReactNode
}) {
  const inputStyle: React.CSSProperties = {
    background: 'rgba(255,255,255,0.04)',
    border: '1px solid rgba(255,255,255,0.08)',
  }
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <label htmlFor={id} className="text-[12px] font-medium text-gray-400">{label}</label>
        {extra}
      </div>
      <input
        id={id} type={type} placeholder={placeholder}
        autoComplete={autoComplete} value={value}
        onChange={e => onChange(e.target.value)}
        required minLength={minLength}
        className="w-full h-11 px-3.5 rounded-xl text-[13.5px] text-white placeholder:text-gray-600 outline-none transition-colors"
        style={inputStyle}
        onFocus={e => (e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)')}
        onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
      />
    </div>
  )
}

// ── Auth form ─────────────────────────────────────────────────────────────────

interface AuthFormProps {
  mode: 'login' | 'register'
}

export function AuthForm({ mode }: AuthFormProps) {
  const { login, register } = useAuth()
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
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
        await login(email, password)
        router.replace('/dashboard')
      } else {
        const { devVerifyUrl } = await register(email, password)
        if (devVerifyUrl) sessionStorage.setItem('dev_verify_url', devVerifyUrl)
        router.replace('/verify-email')
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong.')
    } finally {
      setLoading(false)
    }
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

      {/* Divider */}
      <div className="flex items-center gap-3 mb-6">
        <div className="flex-1 h-px" style={{ background: 'rgba(255,255,255,0.07)' }} />
        <span className="text-[11px] font-medium uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.22)' }}>or</span>
        <div className="flex-1 h-px" style={{ background: 'rgba(255,255,255,0.07)' }} />
      </div>

      {/* Email / password form */}
      <form onSubmit={handleSubmit} className="space-y-3">
        <Field
          id="email" label="Email address" type="email"
          placeholder="you@example.com" autoComplete="email"
          value={email} onChange={setEmail}
        />

        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label htmlFor="password" className="text-[12px] font-medium text-gray-400">Password</label>
            {isLogin && (
              <Link href="/forgot-password" className="text-[11px] transition-colors" style={{ color: 'rgba(255,255,255,0.30)' }}
                onMouseEnter={e => (e.currentTarget.style.color = 'rgba(139,255,62,0.8)')}
                onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.30)')}>
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
              type="button"
              tabIndex={-1}
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
          onMouseEnter={e => !loading && (e.currentTarget.style.boxShadow = '0 0 28px rgba(139,255,62,0.35)')}
          onMouseLeave={e => (e.currentTarget.style.boxShadow = '0 0 20px rgba(139,255,62,0.18)')}
        >
          {loading
            ? <Loader2 className="w-4 h-4 animate-spin" />
            : <>{isLogin ? 'Sign in' : 'Create account'}<ArrowRight className="w-4 h-4" /></>
          }
        </button>
      </form>

      {/* Switch */}
      <p className="mt-6 text-center text-[13px]" style={{ color: 'rgba(255,255,255,0.38)' }}>
        {isLogin ? (
          <>No account?{' '}
            <Link href="/register" className="text-accent-green font-medium hover:underline">Sign up free</Link>
          </>
        ) : (
          <>Already have an account?{' '}
            <Link href="/login" className="text-accent-green font-medium hover:underline">Sign in</Link>
          </>
        )}
      </p>

      {/* Legal (register only) */}
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
