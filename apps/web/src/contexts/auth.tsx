'use client'

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react'
import { usePathname, useRouter } from 'next/navigation'
import {
  api,
  clearStoredToken,
  getStoredToken,
  setStoredToken,
  type LoginChallenge,
  type RegisterPayload,
  type UserResponse,
} from '@/lib/api'

// Returned by initiateLogin: either an OTP challenge (new API) or a fully
// signed-in flag (legacy API or admin bypass).
export type LoginStep =
  | { kind: 'challenge'; challenge: LoginChallenge }
  | { kind: 'signed_in' }

interface AuthContextValue {
  user: UserResponse | null
  loading: boolean
  initiateLogin: (email: string, password: string) => Promise<LoginStep>
  verifyLoginCode: (challengeToken: string, code: string) => Promise<void>
  resendLoginCode: (challengeToken: string) => Promise<{ devCode?: string }>
  register: (payload: RegisterPayload) => Promise<{ devVerifyUrl?: string }>
  loginWithToken: (token: string) => Promise<void>
  refresh: () => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const router = useRouter()
  const pathname = usePathname()

  useEffect(() => {
    const token = getStoredToken()
    if (!token) {
      setLoading(false)
      return
    }
    api.auth
      .me()
      .then(setUser)
      .catch(() => clearStoredToken())
      .finally(() => setLoading(false))
  }, [])

  // T&C gate — block any /dashboard route when the user hasn't yet agreed.
  // Admins bypass so we don't lock ourselves out. The /agreement page
  // itself is excluded so we don't infinite-loop.
  useEffect(() => {
    if (loading || !user || !pathname) return
    if (user.is_admin) return
    if (user.terms_agreed_at) return
    if (pathname.startsWith('/agreement')) return
    if (pathname.startsWith('/dashboard')) {
      router.replace(`/agreement?next=${encodeURIComponent(pathname)}`)
    }
  }, [loading, user, pathname, router])

  const initiateLogin = useCallback(async (email: string, password: string): Promise<LoginStep> => {
    // The new API returns a LoginChallenge; an older API still returns
    // { access_token, token_type } directly. Handle both so we don't strand
    // the user on a broken code-entry step when the API is mid-deploy.
    const res = await api.auth.login(email, password) as LoginChallenge & { access_token?: string }
    if (res.challenge_token) {
      return { kind: 'challenge', challenge: res }
    }
    if (res.access_token) {
      setStoredToken(res.access_token)
      const me = await api.auth.me()
      setUser(me)
      return { kind: 'signed_in' }
    }
    throw new Error('Unexpected login response shape.')
  }, [])

  const verifyLoginCode = useCallback(async (challengeToken: string, code: string) => {
    const { access_token } = await api.auth.verifyLoginCode(challengeToken, code)
    setStoredToken(access_token)
    const me = await api.auth.me()
    setUser(me)
  }, [])

  const resendLoginCode = useCallback(async (challengeToken: string) => {
    const res = await api.auth.resendLoginCode(challengeToken)
    return { devCode: res.dev_code }
  }, [])

  const register = useCallback(async (payload: RegisterPayload) => {
    const res = await api.auth.register(payload)
    setStoredToken(res.access_token)
    const me = await api.auth.me()
    setUser(me)
    return { devVerifyUrl: res.dev_verify_url }
  }, [])

  const loginWithToken = useCallback(async (token: string) => {
    setStoredToken(token)
    const me = await api.auth.me()
    setUser(me)
  }, [])

  const refresh = useCallback(async () => {
    if (!getStoredToken()) return
    const me = await api.auth.me()
    setUser(me)
  }, [])

  const logout = useCallback(() => {
    clearStoredToken()
    setUser(null)
    window.location.replace('/login')
  }, [])

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        initiateLogin,
        verifyLoginCode,
        resendLoginCode,
        register,
        loginWithToken,
        refresh,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
