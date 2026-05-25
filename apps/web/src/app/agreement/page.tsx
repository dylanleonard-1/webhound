'use client'

import { Suspense, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import Image from 'next/image'
import { ArrowRight, Loader2, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/contexts/auth'

function safeNext(raw: string | null | undefined): string {
  if (!raw) return '/dashboard'
  const trimmed = raw.trim()
  if (!trimmed.startsWith('/')) return '/dashboard'
  if (trimmed.startsWith('//')) return '/dashboard'
  if (trimmed.includes('://')) return '/dashboard'
  return trimmed
}

function AgreementInner() {
  const router = useRouter()
  const params = useSearchParams()
  const { refresh } = useAuth()
  const [agreed, setAgreed] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  const nextPath = safeNext(params?.get('next'))

  async function handleSubmit() {
    if (!agreed) return
    setSubmitting(true)
    try {
      await api.auth.acceptTerms()
      // Refresh the user record so the gate in AuthProvider sees
      // terms_agreed_at populated and stops redirecting.
      await refresh()
      router.replace(nextPath)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Could not record agreement.'
      toast.error(msg)
      setSubmitting(false)
    }
  }

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center px-4 py-12"
      style={{ background: '#020617' }}
    >
      <div className="w-full max-w-md">
        <div className="flex items-center gap-2.5 mb-6 justify-center">
          <Image
            src="/logo.png"
            alt="WebHound"
            width={32}
            height={32}
            priority
            style={{ width: 32, height: 32, objectFit: 'contain' }}
          />
          <span className="text-white font-bold text-[15px] tracking-[-0.01em]">
            WebHound
          </span>
        </div>

        <div
          className="rounded-[14px] p-6"
          style={{
            background: 'rgba(8,12,22,0.95)',
            border: '1px solid rgba(255,255,255,0.06)',
          }}
        >
          <div
            className="w-10 h-10 rounded-[10px] flex items-center justify-center mb-4"
            style={{
              background: 'rgba(139,255,62,0.1)',
              border: '1px solid rgba(139,255,62,0.25)',
            }}
          >
            <ShieldCheck className="w-5 h-5" style={{ color: '#8BFF3E' }} />
          </div>

          <h1 className="text-[18px] font-bold text-white mb-1.5">
            One more step before you scan
          </h1>
          <p className="text-[13px] leading-relaxed mb-5"
             style={{ color: 'rgba(255,255,255,0.55)' }}>
            We need you to confirm you&apos;ve read and agree to the rules
            of using WebHound. The most important one: you may only scan
            websites you own or are authorised to test.
          </p>

          <label
            htmlFor="agreed"
            className="flex items-start gap-2.5 cursor-pointer select-none rounded-xl px-3.5 py-3 transition-colors mb-4"
            style={{
              background: agreed ? 'rgba(139,255,62,0.06)' : 'rgba(255,255,255,0.02)',
              border: agreed
                ? '1px solid rgba(139,255,62,0.3)'
                : '1px solid rgba(255,255,255,0.08)',
            }}
          >
            <input
              id="agreed"
              type="checkbox"
              checked={agreed}
              onChange={e => setAgreed(e.target.checked)}
              className="mt-0.5 flex-shrink-0 w-4 h-4 rounded cursor-pointer"
              style={{ accentColor: '#8BFF3E' }}
            />
            <span className="text-[12.5px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.7)' }}>
              I&apos;ve read and agree to the{' '}
              <Link href="/terms" target="_blank" className="hover:underline" style={{ color: '#8BFF3E' }}>
                Terms of Service
              </Link>,{' '}
              <Link href="/privacy" target="_blank" className="hover:underline" style={{ color: '#8BFF3E' }}>
                Privacy Policy
              </Link>, and{' '}
              <Link href="/acceptable-use" target="_blank" className="hover:underline" style={{ color: '#8BFF3E' }}>
                Acceptable Use Policy
              </Link>.
              I will only scan websites I own or am authorised to test.
            </span>
          </label>

          <button
            type="button"
            onClick={handleSubmit}
            disabled={!agreed || submitting}
            className="flex items-center justify-center gap-2 w-full h-[44px] rounded-xl text-[13.5px] font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            style={{
              background: '#8BFF3E', color: '#020617',
              boxShadow: '0 0 20px rgba(139,255,62,0.18)',
            }}
          >
            {submitting
              ? <Loader2 className="w-4 h-4 animate-spin" />
              : <>Continue to dashboard <ArrowRight className="w-4 h-4" /></>}
          </button>

          <p className="text-[11px] text-center mt-4" style={{ color: 'rgba(255,255,255,0.32)' }}>
            We added this confirmation step after launch.
            You only have to do it once.
          </p>
        </div>
      </div>
    </div>
  )
}

export default function AgreementPage() {
  return (
    <Suspense fallback={null}>
      <AgreementInner />
    </Suspense>
  )
}
