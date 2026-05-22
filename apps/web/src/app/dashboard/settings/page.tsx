'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { User, Key, Bell, LogOut, Shield, Phone, CheckCircle2, Loader2, X } from 'lucide-react'
import { useAuth } from '@/contexts/auth'
import { api } from '@/lib/api'

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-2.5" style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
      <span className="text-[12px]" style={{ color: 'rgba(255,255,255,0.4)' }}>{label}</span>
      <span className="text-[12px] font-mono text-white">{value}</span>
    </div>
  )
}

interface SectionProps { icon: React.FC<{ className?: string; style?: React.CSSProperties }>; iconColor: string; title: string; children: React.ReactNode }
function Section({ icon: Icon, iconColor, title, children }: SectionProps) {
  return (
    <div
      className="rounded-[12px] overflow-hidden"
      style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
    >
      <div className="flex items-center gap-2 px-5 py-3.5" style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
        <Icon className="w-3.5 h-3.5" style={{ color: iconColor }} />
        <span className="text-[13px] font-semibold text-white">{title}</span>
      </div>
      <div className="px-5 pb-4 pt-1">{children}</div>
    </div>
  )
}

function PhoneSection() {
  const { user } = useAuth()
  const [step, setStep] = useState<'idle' | 'enter-phone' | 'enter-otp' | 'done'>('idle')
  const [phone, setPhone] = useState('')
  const [otp, setOtp] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [phoneNumber, setPhoneNumber] = useState(user?.phone_number ?? null)
  const [phoneVerified, setPhoneVerified] = useState(user?.phone_verified ?? false)

  const inputStyle: React.CSSProperties = {
    background: 'rgba(255,255,255,0.04)',
    border: '1px solid rgba(255,255,255,0.08)',
  }

  async function handleAddPhone() {
    setError(null)
    setLoading(true)
    try {
      await api.phone.add(phone)
      setPhoneNumber(phone)
      setStep('enter-otp')
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to send code')
    } finally {
      setLoading(false)
    }
  }

  async function handleVerifyOtp() {
    setError(null)
    setLoading(true)
    try {
      await api.phone.verify(otp)
      setPhoneVerified(true)
      setStep('done')
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Incorrect code')
    } finally {
      setLoading(false)
    }
  }

  async function handleRemove() {
    setLoading(true)
    try {
      await api.phone.remove()
      setPhoneNumber(null)
      setPhoneVerified(false)
      setStep('idle')
      setPhone('')
      setOtp('')
    } finally {
      setLoading(false)
    }
  }

  async function handleResend() {
    setError(null)
    setLoading(true)
    try {
      await api.phone.resend()
      setError(null)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to resend')
    } finally {
      setLoading(false)
    }
  }

  if (phoneNumber && phoneVerified) {
    return (
      <div className="pt-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <CheckCircle2 className="w-3.5 h-3.5 text-accent-green" />
          <span className="text-[12px] font-mono text-white">{phoneNumber}</span>
          <span className="text-[11px] px-1.5 py-0.5 rounded-md font-medium"
                style={{ background: 'rgba(139,255,62,0.08)', color: '#8BFF3E', border: '1px solid rgba(139,255,62,0.15)' }}>
            Verified
          </span>
        </div>
        <button
          onClick={handleRemove}
          disabled={loading}
          className="flex items-center gap-1 text-[11px] transition-opacity hover:opacity-70 disabled:opacity-40"
          style={{ color: 'rgba(255,255,255,0.35)' }}
        >
          <X className="w-3 h-3" /> Remove
        </button>
      </div>
    )
  }

  if (phoneNumber && !phoneVerified && step !== 'enter-phone') {
    return (
      <div className="pt-3 space-y-3">
        <p className="text-[12px]" style={{ color: 'rgba(255,255,255,0.45)' }}>
          Enter the 6-digit code sent to <span className="text-white font-mono">{phoneNumber}</span>
        </p>
        <div className="flex gap-2">
          <input
            type="text" inputMode="numeric" maxLength={6} placeholder="123456"
            value={otp} onChange={e => setOtp(e.target.value.replace(/\D/g, ''))}
            className="flex-1 h-10 px-3.5 rounded-xl text-[13.5px] text-white placeholder:text-gray-600 outline-none"
            style={inputStyle}
            onFocus={e => (e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)')}
            onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
          />
          <button
            onClick={handleVerifyOtp} disabled={loading || otp.length < 6}
            className="h-10 px-4 rounded-xl text-[12.5px] font-semibold text-[#020617] disabled:opacity-50 transition-opacity"
            style={{ background: '#8BFF3E' }}
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Verify'}
          </button>
        </div>
        {error && <p className="text-[12px] text-red-400">{error}</p>}
        <div className="flex items-center gap-3">
          <button onClick={handleResend} disabled={loading}
                  className="text-[11px] text-accent-green hover:underline disabled:opacity-50">
            Resend code
          </button>
          <span style={{ color: 'rgba(255,255,255,0.2)' }}>·</span>
          <button onClick={() => { setStep('enter-phone'); setOtp('') }}
                  className="text-[11px] transition-opacity hover:opacity-70"
                  style={{ color: 'rgba(255,255,255,0.35)' }}>
            Change number
          </button>
        </div>
      </div>
    )
  }

  if (step === 'enter-phone') {
    return (
      <div className="pt-3 space-y-3">
        <p className="text-[12px]" style={{ color: 'rgba(255,255,255,0.45)' }}>
          Enter your phone number in international format (e.g. +15551234567)
        </p>
        <div className="flex gap-2">
          <input
            type="tel" placeholder="+15551234567"
            value={phone} onChange={e => setPhone(e.target.value)}
            className="flex-1 h-10 px-3.5 rounded-xl text-[13.5px] text-white placeholder:text-gray-600 outline-none"
            style={inputStyle}
            onFocus={e => (e.currentTarget.style.borderColor = 'rgba(139,255,62,0.45)')}
            onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)')}
          />
          <button
            onClick={handleAddPhone} disabled={loading || !phone.startsWith('+')}
            className="h-10 px-4 rounded-xl text-[12.5px] font-semibold text-[#020617] disabled:opacity-50 transition-opacity"
            style={{ background: '#8BFF3E' }}
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Send code'}
          </button>
        </div>
        {error && <p className="text-[12px] text-red-400">{error}</p>}
      </div>
    )
  }

  return (
    <div className="pt-3">
      <p className="text-[12px] mb-3" style={{ color: 'rgba(255,255,255,0.4)' }}>
        Add a phone number for account recovery and two-factor authentication.
      </p>
      <button
        onClick={() => setStep('enter-phone')}
        className="flex items-center gap-1.5 text-[12.5px] font-medium text-accent-green hover:underline"
      >
        <Phone className="w-3.5 h-3.5" /> Add phone number
      </button>
    </div>
  )
}

export default function SettingsPage() {
  const { user, logout } = useAuth()

  return (
    <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
      <div className="max-w-[680px] mx-auto px-4 py-5 sm:px-6 sm:py-8 space-y-5">

        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}>
          <h1 className="text-[22px] font-bold text-white tracking-tight">Settings</h1>
          <p className="text-[13px] mt-0.5" style={{ color: 'rgba(255,255,255,0.35)' }}>
            Account and preferences
          </p>
        </motion.div>

        <motion.div
          className="space-y-4"
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.05 }}
        >
          {/* Account */}
          <Section icon={User} iconColor="#8BFF3E" title="Account">
            <Row label="Email" value={user?.email ?? '—'} />
            <Row label="Status" value={<span style={{ color: '#8BFF3E' }}>active</span>} />
            <div className="flex items-center justify-between py-2.5">
              <span className="text-[12px]" style={{ color: 'rgba(255,255,255,0.4)' }}>User ID</span>
              <span className="text-[10px] font-mono max-w-[240px] truncate" style={{ color: 'rgba(255,255,255,0.35)' }}>
                {user?.id ?? '—'}
              </span>
            </div>
          </Section>

          {/* API Access */}
          <Section icon={Key} iconColor="#4F9CF9" title="API Access">
            <p className="text-[12px] pt-2" style={{ color: 'rgba(255,255,255,0.35)' }}>
              API key management and personal access tokens — coming soon.
            </p>
          </Section>

          {/* Notifications */}
          <Section icon={Bell} iconColor="#a78bfa" title="Notification Preferences">
            <p className="text-[12px] pt-2" style={{ color: 'rgba(255,255,255,0.35)' }}>
              Notification delivery channels and alert thresholds — coming soon.
            </p>
          </Section>

          {/* Security */}
          <Section icon={Shield} iconColor="#f97316" title="Security">
            <PhoneSection />
          </Section>

          {/* Danger zone */}
          <div
            className="rounded-[12px] p-5"
            style={{ background: 'rgba(239,68,68,0.03)', border: '1px solid rgba(239,68,68,0.15)' }}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[13px] font-semibold text-white">Sign out</p>
                <p className="text-[11px] mt-0.5" style={{ color: 'rgba(255,255,255,0.35)' }}>
                  End your current session
                </p>
              </div>
              <button
                onClick={logout}
                className="flex items-center gap-1.5 px-3 py-[7px] rounded-[8px] text-[12px] font-semibold transition-all"
                style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', color: '#ef4444' }}
                onMouseEnter={e => { const el = e.currentTarget; el.style.background = 'rgba(239,68,68,0.14)'; el.style.borderColor = 'rgba(239,68,68,0.4)' }}
                onMouseLeave={e => { const el = e.currentTarget; el.style.background = 'rgba(239,68,68,0.08)'; el.style.borderColor = 'rgba(239,68,68,0.25)' }}
              >
                <LogOut className="w-3.5 h-3.5" />
                Sign out
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
