'use client'

// WebHound — apps/web/src/app/scan/page.tsx
// Slice 4.A — frictionless URL-entry experience.
//
// The visitor lands here from every "Start Free Scan" CTA on the
// public site. Their goal: scan their website. Our job: deliver on
// the promise in seconds.
//
// Flow:
//   1. URL field above the fold (G1).
//   2. Single primary action: "Scan My Website" (G1).
//   3. Three trust badges directly below the input (G1).
//   4. Posts to POST /public/scan (no signup).
//   5. On success → push to /scan/[guestToken]/status (Slice 4.A
//      polling status page; SSE lands in Slice 4.B).
//   6. On failure → inline plain-English error.

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { motion } from 'framer-motion'
import { ArrowRight, ShieldCheck, Lock, Eye, AlertCircle } from 'lucide-react'

const API_BASE =
  (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_API_URL) ||
  'https://api.webhoundsecurity.com'

interface ScanCreateResponse {
  scan_id: string
  guest_token: string
  status: string
  target_url: string
  profile: string
  rate_limit_remaining: number
}

export default function ScanEntryPage() {
  const router = useRouter()
  const [url, setUrl] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  // Auto-focus the URL field on mount so the visitor can start
  // typing immediately. Their goal is to scan; the input is the
  // path to that goal.
  useEffect(() => {
    const t = setTimeout(() => {
      const el = document.getElementById('scan-url-input')
      if (el) el.focus()
    }, 100)
    return () => clearTimeout(t)
  }, [])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (isSubmitting) return
    setErrorMessage(null)
    setIsSubmitting(true)
    try {
      const res = await fetch(`${API_BASE}/public/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      })
      const body: ScanCreateResponse | { detail?: string } =
        await res.json().catch(() => ({}))
      if (!res.ok) {
        const detail =
          (body as { detail?: string }).detail ||
          'We couldn’t start that scan. Please try again.'
        setErrorMessage(detail)
        setIsSubmitting(false)
        return
      }
      const ok = body as ScanCreateResponse
      router.push(`/scan/${ok.guest_token}/status`)
    } catch (err) {
      setErrorMessage(
        'We couldn’t reach the WebHound servers. Please check your connection and try again.',
      )
      setIsSubmitting(false)
    }
  }

  return (
    <section
      className="relative min-h-screen flex items-center justify-center px-6 py-16"
      style={{ background: '#020617' }}
    >
      {/* Subtle background — restrained, no decoration overload */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.012]"
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='300' height='300'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='300' height='300' filter='url(%23n)'/%3E%3C/svg%3E\")",
        }}
      />

      <div className="relative max-w-[640px] w-full">
        {/* Eyebrow */}
        <motion.div
          className="inline-flex items-center gap-2 mb-5 w-fit"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
        >
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: '#7CFF00', boxShadow: '0 0 8px rgba(124,255,0,0.9)' }}
          />
          <span className="text-[10px] font-bold tracking-[0.28em] uppercase" style={{ color: 'rgba(139,255,62,0.75)' }}>
            Free security checkup
          </span>
        </motion.div>

        {/* Heading */}
        <motion.h1
          className="font-bold leading-[1.05] tracking-[-0.025em] mb-4 text-white"
          style={{ fontSize: 'clamp(2rem, 4.4vw, 3.3rem)' }}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.05 }}
        >
          Enter your website URL.
        </motion.h1>
        <motion.p
          className="text-[16px] mb-9 max-w-[520px] leading-[1.6]"
          style={{ color: 'rgba(255,255,255,0.62)' }}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.12 }}
        >
          We’ll scan it in under two minutes and show you what we
          found in plain English.{' '}
          <span style={{ color: 'rgba(255,255,255,0.42)' }}>
            No credit card. No signup yet — save your report after.
          </span>
        </motion.p>

        {/* Form */}
        <motion.form
          onSubmit={submit}
          className="flex flex-col gap-3 mb-5"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          <div className="flex flex-col sm:flex-row gap-3">
            <input
              id="scan-url-input"
              type="text"
              inputMode="url"
              autoComplete="url"
              spellCheck={false}
              placeholder="yourwebsite.com"
              value={url}
              onChange={(e) => { setUrl(e.target.value); setErrorMessage(null) }}
              disabled={isSubmitting}
              aria-label="Website URL"
              className="flex-1 px-5 py-4 rounded-[10px] text-[15px] font-medium text-white placeholder:text-[rgba(255,255,255,0.32)] focus:outline-none transition-all duration-200"
              style={{
                background: 'rgba(8,12,22,0.85)',
                border: '1px solid rgba(255,255,255,0.10)',
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = 'rgba(124,255,0,0.5)'
                e.currentTarget.style.boxShadow = '0 0 0 3px rgba(124,255,0,0.08)'
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = 'rgba(255,255,255,0.10)'
                e.currentTarget.style.boxShadow = 'none'
              }}
            />
            <button
              type="submit"
              disabled={isSubmitting || !url.trim()}
              className="inline-flex items-center justify-center gap-2 px-6 py-4 rounded-[10px] text-[14px] font-semibold text-[#020617] transition-all duration-200 hover:shadow-[0_8px_28px_rgba(124,255,0,0.45)] hover:-translate-y-px disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:shadow-none whitespace-nowrap"
              style={{
                background: '#7CFF00',
                boxShadow: '0 4px 18px rgba(124,255,0,0.28)',
              }}
            >
              {isSubmitting ? 'Starting your scan…' : 'Scan My Website'}
              {!isSubmitting && <ArrowRight className="w-4 h-4" />}
            </button>
          </div>

          {errorMessage && (
            <motion.div
              role="alert"
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex items-start gap-2 px-4 py-3 rounded-[8px]"
              style={{
                background: 'rgba(239,68,68,0.07)',
                border: '1px solid rgba(239,68,68,0.28)',
              }}
            >
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-px" style={{ color: '#ef4444' }} />
              <span className="text-[13px] leading-[1.5]" style={{ color: 'rgba(254,202,202,0.9)' }}>
                {errorMessage}
              </span>
            </motion.div>
          )}
        </motion.form>

        {/* Trust badges (G1) */}
        <motion.div
          className="flex flex-wrap gap-x-6 gap-y-2"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.28 }}
        >
          {[
            { Icon: Eye,         label: 'Read-only' },
            { Icon: Lock,        label: 'No credentials required' },
            { Icon: ShieldCheck, label: 'Public information only' },
          ].map(({ Icon, label }) => (
            <div key={label} className="inline-flex items-center gap-2">
              <Icon className="w-3.5 h-3.5" style={{ color: 'rgba(139,255,62,0.7)' }} />
              <span className="text-[12px]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                {label}
              </span>
            </div>
          ))}
        </motion.div>

        {/* Footer note */}
        <motion.p
          className="mt-10 text-[11.5px]"
          style={{ color: 'rgba(255,255,255,0.32)' }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.36 }}
        >
          By scanning a website you confirm you own it or are
          authorised to scan it.{' '}
          <a
            href="/security"
            className="underline transition-colors hover:text-white"
            style={{ color: 'rgba(139,255,62,0.75)' }}
          >
            How WebHound scans safely
          </a>
        </motion.p>
      </div>
    </section>
  )
}
