'use client'

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react'
import { api, clearStoredToken, getStoredToken, setStoredToken, type UserResponse } from '@/lib/api'

interface AuthContextValue {
  user: UserResponse | null
  loading: boolean
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string) => Promise<{ devVerifyUrl?: string }>
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

  const login = useCallback(async (email: string, password: string) => {
    const { access_token } = await api.auth.login(email, password)
    setStoredToken(access_token)
    const me = await api.auth.me()
    setUser(me)
  }, [])

  const register = useCallback(async (email: string, password: string) => {
    const res = await api.auth.register(email, password)
    await login(email, password)
    return { devVerifyUrl: res.dev_verify_url }
  }, [login])

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
    <AuthContext.Provider value={{ user, loading, login, register, loginWithToken, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
