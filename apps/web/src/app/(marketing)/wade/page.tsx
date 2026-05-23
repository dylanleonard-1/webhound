import type { Metadata } from 'next'
import Link from 'next/link'
import { ArrowRight, Brain, Eye, GitBranch, Network, Zap } from 'lucide-react'

export const metadata: Metadata = {
  title: 'WADE — your website’s AI baseline',
  description:
    'WADE learns what your website normally looks like and alerts you when something changes that traditional scanners miss.',
}

interface Detect {
  icon: React.FC<{ className?: string }>
  title: string
  body: string
}

const DETECTS: Detect[] = [
  {
    icon: GitBranch,
    title: 'Silent supply-chain changes',
    body:
      'Your CMS, ad network, or analytics vendor pushes an update. The new code does something the old code didn’t. WADE noticed; you didn’t.',
  },
  {
    icon: Network,
    title: 'New third-party connections',
    body:
      'A script you’ve loaded forever suddenly starts talking to a domain you’ve never seen. That’s often how data exfiltration begins.',
  },
  {
    icon: Eye,
    title: 'Quiet redirects and rewrites',
    body:
      'An attacker who gets in often doesn’t change much — they just add one redirect on one page. WADE sees the diff and flags it.',
  },
  {
    icon: Zap,
    title: 'Content that shouldn’t change',
    body:
      'Your checkout page, login form, and admin entry haven’t changed in months. The moment they do, WADE wakes up.',
  },
]

export default function WadePage() {
  return (
    <div className="bg-[#020617] text-white">

      <section className="relative px-6 sm:px-12 xl:px-20 pt-32 pb-20 lg:pt-40 lg:pb-28">
        <div className="max-w-4xl mx-auto">
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-4" style={{ color: 'rgba(167,139,250,0.85)' }}>
            The AI baseline
          </p>
          <h1
            className="font-bold leading-[1] tracking-[-0.03em] mb-7"
            style={{ fontSize: 'clamp(2.4rem, 5vw, 4.4rem)' }}
          >
            Some attacks
            <span className="block" style={{ color: 'rgba(255,255,255,0.55)' }}>don’t break the lock.</span>
            <span className="block mt-2" style={{ color: '#a78bfa' }}>
              WADE finds the rest.
            </span>
          </h1>
          <p
            className="text-[16.5px] leading-[1.65] max-w-[640px]"
            style={{ color: 'rgba(255,255,255,0.6)' }}
          >
            Most attacks don&apos;t break a lock — they walk in through a door you
            didn&apos;t know was there. WADE is the AI that learns what your website
            normally looks like, then flags anomalies traditional scanners would
            never catch.
          </p>

          <div className="mt-9 flex flex-col sm:flex-row items-start sm:items-center gap-3">
            <Link href="/register">
              <button
                className="inline-flex items-center gap-2 px-6 py-3 rounded-[10px] text-[14px] font-semibold text-[#020617] transition-all duration-300 hover:shadow-[0_0_30px_rgba(124,255,0,0.4)] hover:scale-[1.02]"
                style={{ background: '#7CFF00', boxShadow: '0 0 18px rgba(124,255,0,0.22)' }}
              >
                Start Free Scan
                <ArrowRight className="w-4 h-4" />
              </button>
            </Link>
            <span className="text-[12.5px]" style={{ color: 'rgba(255,255,255,0.32)' }}>
              WADE turns on after your first monitoring run
            </span>
          </div>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20 lg:py-28" style={{ background: '#02060f' }}>
        <div className="max-w-4xl mx-auto">
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(167,139,250,0.7)' }}>
            How WADE learns
          </p>
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em] mb-6"
            style={{ fontSize: 'clamp(1.7rem, 3.2vw, 2.6rem)' }}
          >
            It watches you, so it can spot what isn&apos;t you.
          </h2>
          <p className="text-[15px] leading-[1.75] mb-5" style={{ color: 'rgba(255,255,255,0.65)' }}>
            For the first two weeks, WADE quietly records every script, every redirect,
            every external service your website talks to. It learns your normal —
            the rhythms of your CDN, the timing of your auto-deploys, the third parties
            you trust.
          </p>
          <p className="text-[15px] leading-[1.75]" style={{ color: 'rgba(255,255,255,0.65)' }}>
            After that, anything that doesn&apos;t fit becomes a signal. Not noise — a signal.
            A new domain. A script that grew an extra 14KB overnight. A redirect that
            wasn&apos;t there yesterday. WADE flags it before it ends up on a blocklist anyone
            else would recognize.
          </p>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20 lg:py-28">
        <div className="max-w-5xl mx-auto">
          <div
            className="rounded-[16px] p-8 lg:p-10"
            style={{ background: 'rgba(167,139,250,0.05)', border: '1px solid rgba(167,139,250,0.22)' }}
          >
            <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(167,139,250,0.85)' }}>
              A real catch
            </p>
            <p className="text-[18px] leading-[1.6] mb-5 font-semibold">
              &ldquo;Your site started loading a tracking script from an obscure server in Russia
              at 2:11 AM Tuesday.&rdquo;
            </p>
            <p className="text-[14px] leading-[1.7]" style={{ color: 'rgba(255,255,255,0.65)' }}>
              The script wasn&apos;t on any blocklist yet. Antivirus tools couldn&apos;t see it.
              Your CMS thought it was a normal vendor update. But WADE knew your baseline —
              and that script wasn&apos;t in it. We flagged it 14 minutes after it appeared,
              before it had a chance to harvest a single visitor session.
            </p>
          </div>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20 lg:py-28" style={{ background: '#02060f' }}>
        <div className="max-w-6xl mx-auto">
          <div className="mb-12 max-w-[680px]">
            <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(167,139,250,0.7)' }}>
              What WADE detects
            </p>
            <h2
              className="font-bold leading-[1.05] tracking-[-0.02em]"
              style={{ fontSize: 'clamp(1.7rem, 3.2vw, 2.4rem)' }}
            >
              Four classes of attack that scanners miss.
            </h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {DETECTS.map(d => {
              const Icon = d.icon
              return (
                <div
                  key={d.title}
                  className="rounded-[14px] p-6"
                  style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(255,255,255,0.06)' }}
                >
                  <div className="flex items-center gap-3 mb-3">
                    <div
                      className="w-9 h-9 rounded-[9px] flex items-center justify-center flex-shrink-0"
                      style={{ background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(167,139,250,0.22)' }}
                    >
                      <Icon className="w-4 h-4" style={{ color: '#a78bfa' }} />
                    </div>
                    <h3 className="text-[15.5px] font-bold leading-tight">{d.title}</h3>
                  </div>
                  <p className="text-[13.5px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                    {d.body}
                  </p>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20 lg:py-28 text-center">
        <div className="max-w-3xl mx-auto">
          <div className="inline-flex items-center justify-center mb-6">
            <div
              className="w-14 h-14 rounded-2xl flex items-center justify-center"
              style={{ background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(167,139,250,0.25)' }}
            >
              <Brain className="w-6 h-6" style={{ color: '#a78bfa' }} />
            </div>
          </div>
          <h2
            className="font-bold leading-[1.1] tracking-[-0.02em] mb-6"
            style={{ fontSize: 'clamp(1.7rem, 3.2vw, 2.6rem)' }}
          >
            Your website&apos;s second pair of eyes.
          </h2>
          <Link href="/register">
            <button
              className="inline-flex items-center gap-2 px-7 py-3.5 rounded-[10px] text-[14px] font-semibold text-[#020617] transition-all duration-300 hover:shadow-[0_0_30px_rgba(124,255,0,0.4)] hover:scale-[1.02]"
              style={{ background: '#7CFF00', boxShadow: '0 0 20px rgba(124,255,0,0.22)' }}
            >
              Start Free Scan
              <ArrowRight className="w-4 h-4" />
            </button>
          </Link>
          <div className="mt-12 pt-9" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <p className="text-[12px] tracking-wider uppercase mb-3" style={{ color: 'rgba(255,255,255,0.32)' }}>
              Next chapter
            </p>
            <Link
              href="/pricing"
              className="inline-flex items-center gap-1.5 text-[14.5px] font-semibold"
              style={{ color: '#7CFF00' }}
            >
              See what it costs.
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

    </div>
  )
}
