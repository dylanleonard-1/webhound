'use client'

import { Suspense, useRef, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import Image from 'next/image'
import {
  ArrowRight, Loader2, ShieldCheck, AlertTriangle,
  CheckCircle2, Lock,
} from 'lucide-react'
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

// The 4 most consequential rules — surfaced even for users who don't
// scroll, so the legal foundation is impossible to miss.
const TOP_RULES = [
  {
    icon: ShieldCheck,
    title: 'Only scan what you own',
    body: 'You may only run scans against websites you own or have explicit written authorisation to test. Unauthorised scanning may violate the CFAA, the Computer Misuse Act, and similar laws worldwide.',
  },
  {
    icon: AlertTriangle,
    title: 'You are responsible for your activity',
    body: 'WebHound is a tool. The legal responsibility for every scan you initiate rests with you. We log every scan with your account ID and may share that data with law enforcement on a valid request.',
  },
  {
    icon: Lock,
    title: "WebHound output isn't a guarantee of security",
    body: 'A clean scan does not mean your site is secure. Findings are heuristic — false positives and false negatives both happen. Treat WebHound as one signal among many in your security programme.',
  },
  {
    icon: CheckCircle2,
    title: 'You can leave at any time',
    body: 'Delete your account from Settings → Account, or email privacy@webhoundsecurity.com. Your scan data is removed within 30 days; billing records are retained per US tax / GDPR requirements.',
  },
]

// Condensed AUP body — the user must scroll through this before the
// checkbox unlocks. Full canonical version lives at /acceptable-use.
const AUP_TEXT = `WebHound Acceptable Use Policy — Summary

The following is a summary of the WebHound Acceptable Use Policy. The full version is available at /acceptable-use and forms part of your agreement with WebHound Security.

1. Authorisation is mandatory.
You may submit a domain, IP address, or URL to WebHound only if (a) you own the system, (b) you have explicit written authorisation from the owner, or (c) it is a WebHound-owned demonstration target. Scanning without authorisation may violate the Computer Fraud and Abuse Act (USA), the Computer Misuse Act (UK), EU Directive 2013/40/EU, or equivalent legislation. We have zero tolerance for unauthorised scanning.

2. Prohibited activities.
You may not use WebHound to conduct denial-of-service or volumetric attacks. You may not weaponise findings against systems you do not control — WebHound is a passive scanner; what you do with its output is your responsibility. You may not scan critical infrastructure (utilities, hospitals, traffic systems, emergency services) without explicit written authorisation from the system operator. You may not use WebHound output to defame, extort, harass, or shake down third parties. You may not resell or white-label WebHound output without an enterprise agreement.

3. Domain ownership verification.
WebHound verifies domain ownership through DNS TXT records, HTML meta tags, or file uploads before enabling deep scans, continuous monitoring, or large scan budgets. Submitting a verification token to a domain you do not actually control — for example, exploiting a subdomain takeover or social-engineering the owner — constitutes unauthorised scanning under Section 1.

4. Reporting vulnerabilities you find.
If a WebHound scan reveals a vulnerability on a system you are authorised to test, you are responsible for reporting it through the asset owner's preferred channel. WebHound does not auto-notify third parties. Do not publicly disclose vulnerabilities without giving the affected party a reasonable opportunity to remediate (industry norm: 90 days).

5. Compliance with local law.
Security testing law varies by country. You are responsible for compliance with the law in (a) your jurisdiction, (b) the location of the target system, and (c) the location of any user data on that target.

6. Limitation of liability.
WebHound is provided "AS IS" without warranties. Our total cumulative liability is limited to the amount you paid us in the twelve months preceding any claim. For free-tier users, that amount is zero dollars.

7. Enforcement.
We may suspend or terminate access without notice if we have a good-faith belief that you have violated this policy. Severe violations — particularly unauthorised scanning of critical infrastructure — will be reported to law enforcement along with all account, billing, and scan logs we hold. Customers terminated for AUP violations are not entitled to refunds.

8. Reporting abuse.
If you believe a WebHound user is scanning your systems without authorisation, contact abuse@webhoundsecurity.com with the affected domain, timestamps, and any access logs you can share. We investigate within 2 business days.

By clicking the checkbox below, you confirm you have read this summary, understand the rules, and agree to be bound by them.`

function AgreementInner() {
  const router = useRouter()
  const params = useSearchParams()
  const { refresh } = useAuth()
  const [agreed, setAgreed] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [scrolledToBottom, setScrolledToBottom] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  const nextPath = safeNext(params?.get('next'))

  function handleScroll() {
    const el = scrollRef.current
    if (!el) return
    // Treat "within 16px of bottom" as scrolled — accounts for sub-pixel
    // rounding and gives keyboard-arrow users a tolerance window.
    const remaining = el.scrollHeight - el.scrollTop - el.clientHeight
    if (remaining <= 16 && !scrolledToBottom) {
      setScrolledToBottom(true)
    }
  }

  async function handleSubmit() {
    if (!agreed || !scrolledToBottom) return
    setSubmitting(true)
    try {
      await api.auth.acceptTerms()
      await refresh()
      router.replace(nextPath)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Could not record agreement.'
      toast.error(msg)
      setSubmitting(false)
    }
  }

  const canSubmit = agreed && scrolledToBottom && !submitting

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center px-4 py-10"
      style={{ background: '#020617' }}
    >
      <div className="w-full max-w-2xl">
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
          className="rounded-[14px] p-6 sm:p-7"
          style={{
            background: 'rgba(8,12,22,0.95)',
            border: '1px solid rgba(255,255,255,0.06)',
          }}
        >
          {/* Header */}
          <div className="flex items-start gap-3 mb-5">
            <div
              className="w-10 h-10 rounded-[10px] flex items-center justify-center flex-shrink-0"
              style={{
                background: 'rgba(139,255,62,0.1)',
                border: '1px solid rgba(139,255,62,0.25)',
              }}
            >
              <ShieldCheck className="w-5 h-5" style={{ color: '#8BFF3E' }} />
            </div>
            <div>
              <h1 className="text-[18px] font-bold text-white mb-1">
                Before you scan: please read this
              </h1>
              <p className="text-[12.5px] leading-relaxed"
                 style={{ color: 'rgba(255,255,255,0.55)' }}>
                WebHound is a security tool. The legal responsibility for every scan
                you run rests with you. We need you to read the rules and agree —
                this is the one place we don&apos;t let you click past.
              </p>
            </div>
          </div>

          {/* Top rules — always visible */}
          <div className="space-y-2.5 mb-5">
            {TOP_RULES.map(r => (
              <div
                key={r.title}
                className="flex items-start gap-2.5 rounded-[10px] p-3"
                style={{
                  background: 'rgba(255,255,255,0.02)',
                  border: '1px solid rgba(255,255,255,0.06)',
                }}
              >
                <r.icon
                  className="w-4 h-4 flex-shrink-0 mt-0.5"
                  style={{ color: '#8BFF3E' }}
                />
                <div>
                  <p className="text-[12.5px] font-semibold text-white mb-0.5">
                    {r.title}
                  </p>
                  <p className="text-[11.5px] leading-relaxed"
                     style={{ color: 'rgba(255,255,255,0.5)' }}>
                    {r.body}
                  </p>
                </div>
              </div>
            ))}
          </div>

          {/* Scrollable AUP body */}
          <div className="mb-1">
            <p className="text-[10px] uppercase tracking-[0.18em] font-bold mb-2"
               style={{ color: 'rgba(255,255,255,0.35)' }}>
              Acceptable Use Policy — full summary
            </p>
            <div
              ref={scrollRef}
              onScroll={handleScroll}
              className="rounded-[10px] p-4 overflow-y-auto"
              style={{
                background: 'rgba(2,6,23,0.6)',
                border: scrolledToBottom
                  ? '1px solid rgba(139,255,62,0.3)'
                  : '1px solid rgba(255,255,255,0.08)',
                height: 240,
                scrollbarWidth: 'thin',
              }}
            >
              <pre
                className="text-[11.5px] leading-relaxed whitespace-pre-wrap font-sans"
                style={{ color: 'rgba(255,255,255,0.62)' }}
              >
                {AUP_TEXT}
              </pre>
            </div>
            <p
              className="text-[10.5px] mt-2 flex items-center gap-1.5"
              style={{
                color: scrolledToBottom
                  ? 'rgba(139,255,62,0.8)'
                  : 'rgba(255,255,255,0.4)',
              }}
            >
              {scrolledToBottom ? (
                <>
                  <CheckCircle2 className="w-3 h-3" />
                  You&apos;ve read the full summary.
                </>
              ) : (
                <>Scroll to the bottom of the box above to enable the checkbox.</>
              )}
            </p>
          </div>

          {/* Checkbox — locked until scroll completes */}
          <label
            htmlFor="agreed"
            className="flex items-start gap-2.5 select-none rounded-xl px-3.5 py-3 transition-colors mt-4"
            style={{
              background: agreed
                ? 'rgba(139,255,62,0.06)'
                : 'rgba(255,255,255,0.02)',
              border: agreed
                ? '1px solid rgba(139,255,62,0.3)'
                : '1px solid rgba(255,255,255,0.08)',
              cursor: scrolledToBottom ? 'pointer' : 'not-allowed',
              opacity: scrolledToBottom ? 1 : 0.55,
            }}
          >
            <input
              id="agreed"
              type="checkbox"
              checked={agreed}
              disabled={!scrolledToBottom}
              onChange={e => setAgreed(e.target.checked)}
              className="mt-0.5 flex-shrink-0 w-4 h-4 rounded"
              style={{
                accentColor: '#8BFF3E',
                cursor: scrolledToBottom ? 'pointer' : 'not-allowed',
              }}
            />
            <span className="text-[12.5px] leading-relaxed"
                  style={{ color: 'rgba(255,255,255,0.72)' }}>
              I&apos;ve read the rules above, and the full{' '}
              <Link href="/terms" target="_blank" className="hover:underline" style={{ color: '#8BFF3E' }}>
                Terms of Service
              </Link>,{' '}
              <Link href="/privacy" target="_blank" className="hover:underline" style={{ color: '#8BFF3E' }}>
                Privacy Policy
              </Link>, and{' '}
              <Link href="/acceptable-use" target="_blank" className="hover:underline" style={{ color: '#8BFF3E' }}>
                Acceptable Use Policy
              </Link>.
              I agree to be bound by them. I will only scan websites I own or am
              authorised to test.
            </span>
          </label>

          {/* Submit */}
          <button
            type="button"
            onClick={handleSubmit}
            disabled={!canSubmit}
            className="flex items-center justify-center gap-2 w-full h-[44px] rounded-xl text-[13.5px] font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed mt-4"
            style={{
              background: '#8BFF3E', color: '#020617',
              boxShadow: canSubmit ? '0 0 20px rgba(139,255,62,0.22)' : undefined,
            }}
          >
            {submitting
              ? <Loader2 className="w-4 h-4 animate-spin" />
              : <>Agree &amp; continue to dashboard <ArrowRight className="w-4 h-4" /></>}
          </button>

          <p className="text-[10.5px] text-center mt-4"
             style={{ color: 'rgba(255,255,255,0.32)' }}>
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
