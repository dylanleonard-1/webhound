'use client'

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react'
import {
  api,
  clearStoredToken,
  getStoredToken,
  setStoredToken,
  type LoginChallenge,
  type RegisterPayload,
  type UserResponse,
} from '@/lib/api'

interface AuthContextValue {
  user: UserResponse | null
  loading: boolean
  initiateLogin: (email: string, password: string) => Promise<LoginChallenge>
  verifyLoginCode: (challengeToken: string, code: string) => Promise<void>
  resendLoginCode: (challengeToken: string) => Promise<{ devCode?: string }>
  register: (payload: RegisterPayload) => Promise<{ devVerifyUrl?: string }>
  loginWithToken: (token: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserResponse | null>(null)
  const [loading, setLoading] = useState(true)

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

  const initiateLogin = useCallback(async (email: string, password: string) => {
    return api.auth.login(email, password)
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
