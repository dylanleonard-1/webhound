import type { Metadata } from 'next'
import Link from 'next/link'
import { ArrowRight, Activity, AlertTriangle, Mail, MessageSquare, Webhook, Clock } from 'lucide-react'

export const metadata: Metadata = {
  title: 'Continuous monitoring',
  description:
    'One scan tells you what is wrong today. Monitoring watches every day after, and tells you the moment something changes.',
}

interface AlertChannel {
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  name: string
  desc: string
}

const CHANNELS: AlertChannel[] = [
  { icon: Mail,          name: 'Email',   desc: 'A clear summary, no jargon, sent the moment we find something new.' },
  { icon: MessageSquare, name: 'Slack',   desc: 'Drops into your security or engineering channel with severity badges.' },
  { icon: Webhook,       name: 'Webhook', desc: 'Pipe alerts into PagerDuty, Linear, Jira, or your custom incident system.' },
]

interface Catch {
  hour: string
  body: string
}

const CATCHES: Catch[] = [
  {
    hour: '7:04 AM',
    body:
      'Your developer pushed code last night that accidentally exposed an admin login page. We told you at 7:04 AM. You patched it before your team got to the office.',
  },
  {
    hour: '2:11 AM',
    body:
      'A tracking script you load from a vendor was updated. The new version sends data to a server in a country your privacy policy doesn’t mention. You caught it before legal did.',
  },
  {
    hour: '11:42 PM',
    body:
      'Your SSL certificate auto-renewal failed silently. We noticed eight days before it would have expired and turned your website red.',
  },
]

export default function MonitoringPage() {
  return (
    <div className="bg-[#020617] text-white">

      <section className="relative px-6 sm:px-12 xl:px-20 pt-32 pb-20 lg:pt-40 lg:pb-28">
        <div className="max-w-4xl mx-auto">
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-4" style={{ color: 'rgba(79,156,249,0.75)' }}>
            What happens after the scan
          </p>
          <h1
            className="font-bold leading-[1] tracking-[-0.03em] mb-7"
            style={{ fontSize: 'clamp(2.4rem, 5vw, 4.4rem)' }}
          >
            One scan is a snapshot.
            <span className="block mt-2" style={{ color: '#4F9CF9' }}>
              WebHound watches.
            </span>
          </h1>
          <p
            className="text-[16.5px] leading-[1.65] max-w-[640px]"
            style={{ color: 'rgba(255,255,255,0.6)' }}
          >
            Your website doesn&apos;t stand still. Developers ship code. Hosting providers
            rotate certificates. New vulnerabilities get disclosed every week. A single
            scan tells you what&apos;s wrong today — and nothing about tomorrow.
            Monitoring closes that gap.
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
              Monitoring turns on automatically after your first scan
            </span>
          </div>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20 lg:py-28" style={{ background: '#02060f' }}>
        <div className="max-w-6xl mx-auto">
          <div className="mb-12 max-w-[680px]">
            <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(79,156,249,0.65)' }}>
              How it works
            </p>
            <h2
              className="font-bold leading-[1.05] tracking-[-0.02em]"
              style={{ fontSize: 'clamp(1.7rem, 3.2vw, 2.6rem)' }}
            >
              Re-scan. Compare. Alert only when something matters.
            </h2>
            <p className="text-[14.5px] leading-[1.65] mt-4" style={{ color: 'rgba(255,255,255,0.5)' }}>
              We don&apos;t flood your inbox with the same findings every day. Monitoring builds a
              baseline of your website and only tells you about <span className="text-white">changes</span>:
              new vulnerabilities, new scripts, new exposed paths, certificates about to expire.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div
              className="rounded-[14px] p-6"
              style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(255,255,255,0.06)' }}
            >
              <div
                className="w-10 h-10 rounded-[10px] flex items-center justify-center mb-4"
                style={{ background: 'rgba(79,156,249,0.08)', border: '1px solid rgba(79,156,249,0.25)' }}
              >
                <Clock className="w-4 h-4" style={{ color: '#4F9CF9' }} />
              </div>
              <h3 className="text-[15.5px] font-bold mb-2">Daily re-scan</h3>
              <p className="text-[13.5px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                Every 24 hours, the same six-area sweep runs again in the background. You don&apos;t
                trigger it. You don&apos;t pay extra. It just happens.
              </p>
            </div>

            <div
              className="rounded-[14px] p-6"
              style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(255,255,255,0.06)' }}
            >
              <div
                className="w-10 h-10 rounded-[10px] flex items-center justify-center mb-4"
                style={{ background: 'rgba(79,156,249,0.08)', border: '1px solid rgba(79,156,249,0.25)' }}
              >
                <Activity className="w-4 h-4" style={{ color: '#4F9CF9' }} />
              </div>
              <h3 className="text-[15.5px] font-bold mb-2">Compare to baseline</h3>
              <p className="text-[13.5px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                Each scan is compared against the last known-good state of your website. Anything
                different is a candidate for an alert.
              </p>
            </div>

            <div
              className="rounded-[14px] p-6"
              style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(255,255,255,0.06)' }}
            >
              <div
                className="w-10 h-10 rounded-[10px] flex items-center justify-center mb-4"
                style={{ background: 'rgba(79,156,249,0.08)', border: '1px solid rgba(79,156,249,0.25)' }}
              >
                <AlertTriangle className="w-4 h-4" style={{ color: '#4F9CF9' }} />
              </div>
              <h3 className="text-[15.5px] font-bold mb-2">Alert when it matters</h3>
              <p className="text-[13.5px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                You pick the severity threshold. A new critical finding pages you at 2am.
                A medium issue can wait until the morning digest.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20 lg:py-28">
        <div className="max-w-5xl mx-auto">
          <div className="mb-10 max-w-[680px]">
            <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(79,156,249,0.65)' }}>
              Where alerts go
            </p>
            <h2
              className="font-bold leading-[1.05] tracking-[-0.02em]"
              style={{ fontSize: 'clamp(1.7rem, 3.2vw, 2.4rem)' }}
            >
              Where your team already lives.
            </h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {CHANNELS.map(c => {
              const Icon = c.icon
              return (
                <div
                  key={c.name}
                  className="rounded-[14px] p-6"
                  style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(255,255,255,0.06)' }}
                >
                  <Icon className="w-5 h-5 mb-4" style={{ color: '#4F9CF9' }} />
                  <h3 className="text-[15px] font-bold mb-2">{c.name}</h3>
                  <p className="text-[13px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                    {c.desc}
                  </p>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20 lg:py-28" style={{ background: '#02060f' }}>
        <div className="max-w-4xl mx-auto">
          <div className="mb-10">
            <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(79,156,249,0.65)' }}>
              What we catch
            </p>
            <h2
              className="font-bold leading-[1.05] tracking-[-0.02em]"
              style={{ fontSize: 'clamp(1.7rem, 3.2vw, 2.4rem)' }}
            >
              Real catches, real timing.
            </h2>
          </div>
          <div className="space-y-3">
            {CATCHES.map(c => (
              <div
                key={c.hour}
                className="rounded-[12px] p-5 flex items-start gap-5"
                style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(255,255,255,0.06)' }}
              >
                <span
                  className="text-[12.5px] font-mono font-bold flex-shrink-0 px-2 py-1 rounded-md"
                  style={{ background: 'rgba(79,156,249,0.08)', color: '#4F9CF9', border: '1px solid rgba(79,156,249,0.2)' }}
                >
                  {c.hour}
                </span>
                <p className="text-[14px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.65)' }}>
                  {c.body}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20 lg:py-28 text-center">
        <div className="max-w-3xl mx-auto">
          <h2
            className="font-bold leading-[1.1] tracking-[-0.02em] mb-6"
            style={{ fontSize: 'clamp(1.7rem, 3.2vw, 2.6rem)' }}
          >
            Sleep tonight. We&apos;ll be watching.
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
              href="/wade"
              className="inline-flex items-center gap-1.5 text-[14.5px] font-semibold"
              style={{ color: '#a78bfa' }}
            >
              Some changes aren&apos;t obvious. See how WADE uses AI to spot them.
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

    </div>
  )
}
