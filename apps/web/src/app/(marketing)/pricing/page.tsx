import type { Metadata } from 'next'
import Link from 'next/link'
import { ArrowRight, Check, Minus } from 'lucide-react'

export const metadata: Metadata = {
  title: 'Pricing',
  description:
    'A free scan. Daily monitoring. Multi-site teams. WebHound plans in plain English.',
}

interface Tier {
  name: string
  tagline: string
  price: string
  priceNote: string
  cta: { label: string; href: string }
  highlight: boolean
  features: string[]
}

const TIERS: Tier[] = [
  {
    name: 'Free',
    tagline: 'See what’s exposed right now.',
    price: '$0',
    priceNote: 'forever, no card',
    cta: { label: 'Start free scan', href: '/register' },
    highlight: false,
    features: [
      'One full scan',
      'Six-area sweep, thousands of checks',
      'Plain-English report by email',
      'Severity-ranked findings with remediation',
    ],
  },
  {
    name: 'Pro',
    tagline: 'Watch every day. Sleep at night.',
    price: '$29',
    priceNote: 'per site / month',
    cta: { label: 'Start free, upgrade later', href: '/register' },
    highlight: true,
    features: [
      'Everything in Free',
      'Daily automatic re-scans',
      'WADE anomaly detection',
      'Email & Slack alerts',
      'Severity thresholds you control',
      'Up to 5 sites',
    ],
  },
  {
    name: 'Business',
    tagline: 'For teams, agencies, and portfolios.',
    price: '$129',
    priceNote: 'per month · billed annually',
    cta: { label: 'Start free, upgrade later', href: '/register' },
    highlight: false,
    features: [
      'Everything in Pro',
      'Unlimited sites',
      'Team accounts with roles',
      'Webhook integrations (PagerDuty, Linear, Jira)',
      'SARIF / CSV / Markdown exports',
      'Priority support',
    ],
  },
]

interface Row {
  feature: string
  free: boolean | string
  pro: boolean | string
  business: boolean | string
}

const COMPARE: Row[] = [
  { feature: 'How often we scan',         free: 'Once',   pro: 'Daily',     business: 'Daily + on demand' },
  { feature: 'Sites you can monitor',     free: '1',      pro: 'Up to 5',   business: 'Unlimited' },
  { feature: 'WADE anomaly detection',    free: false,    pro: true,        business: true },
  { feature: 'Slack / webhook alerts',    free: false,    pro: true,        business: true },
  { feature: 'Team accounts',             free: false,    pro: false,       business: true },
  { feature: 'Export findings (SARIF/CSV)', free: false,  pro: false,       business: true },
]

interface FAQItem { q: string; a: string }

const FAQ: FAQItem[] = [
  {
    q: 'Will a scan break my site?',
    a: 'No. WebHound is passive — we read public information the same way a search engine does. We never log in, submit forms, or attempt exploits.',
  },
  {
    q: 'Do you store my passwords?',
    a: 'Never. We don’t need them and we don’t want them. Passive scanning means we look at your website from the outside — like an attacker would, before they break anything.',
  },
  {
    q: 'Can I cancel anytime?',
    a: 'Yes. Cancel from your dashboard in two clicks. We don’t hold your data hostage or hide a "contact sales" wall.',
  },
  {
    q: 'What if my scan finds nothing?',
    a: 'Then your website is in good shape today — and Pro will keep checking every day so you find out the moment that changes.',
  },
  {
    q: 'Do you offer annual discounts or non-profit pricing?',
    a: 'Annual billing is included on the Business plan. For non-profits and educational institutions, email support@webhoundsecurity.com.',
  },
]

function Cell({ value, accent }: { value: boolean | string; accent: string }) {
  if (typeof value === 'string') {
    return <span className="text-[13.5px] text-white">{value}</span>
  }
  return value
    ? <Check className="w-4 h-4" style={{ color: accent }} />
    : <Minus className="w-4 h-4" style={{ color: 'rgba(255,255,255,0.18)' }} />
}

export default function PricingPage() {
  return (
    <div className="bg-[#020617] text-white">

      <section className="relative px-6 sm:px-12 xl:px-20 pt-32 pb-16 lg:pt-40 lg:pb-20 text-center">
        <div className="max-w-3xl mx-auto">
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-4" style={{ color: 'rgba(139,255,62,0.7)' }}>
            Pricing
          </p>
          <h1
            className="font-bold leading-[1.05] tracking-[-0.03em] mb-6"
            style={{ fontSize: 'clamp(2.4rem, 5vw, 4.4rem)' }}
          >
            Start with a free scan.
          </h1>
          <p className="text-[16.5px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.6)' }}>
            Upgrade when you want WebHound watching every day. No contracts, no setup calls.
          </p>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 pb-16">
        <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-4">
          {TIERS.map(t => (
            <div
              key={t.name}
              className="rounded-[16px] p-7 flex flex-col"
              style={{
                background: t.highlight ? 'rgba(124,255,0,0.04)' : 'rgba(8,12,22,0.95)',
                border: t.highlight ? '1px solid rgba(124,255,0,0.32)' : '1px solid rgba(255,255,255,0.07)',
                boxShadow: t.highlight ? '0 0 36px rgba(124,255,0,0.08)' : 'none',
              }}
            >
              {t.highlight && (
                <div
                  className="self-start mb-4 px-2 py-0.5 rounded-full text-[9px] font-black tracking-[0.16em] uppercase"
                  style={{ background: '#7CFF00', color: '#020617' }}
                >
                  Most popular
                </div>
              )}
              <h2 className="text-[20px] font-bold mb-1">{t.name}</h2>
              <p className="text-[13px] mb-6" style={{ color: 'rgba(255,255,255,0.5)' }}>{t.tagline}</p>

              <div className="flex items-baseline gap-2 mb-1">
                <span className="text-[34px] font-bold tracking-[-0.02em]">{t.price}</span>
                <span className="text-[12.5px]" style={{ color: 'rgba(255,255,255,0.4)' }}>{t.priceNote}</span>
              </div>

              <ul className="mt-6 space-y-2.5 flex-1">
                {t.features.map(f => (
                  <li key={f} className="flex items-start gap-2.5 text-[13.5px]" style={{ color: 'rgba(255,255,255,0.7)' }}>
                    <Check className="w-3.5 h-3.5 mt-1 flex-shrink-0" style={{ color: t.highlight ? '#7CFF00' : 'rgba(255,255,255,0.55)' }} />
                    <span>{f}</span>
                  </li>
                ))}
              </ul>

              <Link href={t.cta.href} className="mt-7">
                <button
                  className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 rounded-[10px] text-[13.5px] font-semibold transition-all"
                  style={
                    t.highlight
                      ? { background: '#7CFF00', color: '#020617', boxShadow: '0 0 18px rgba(124,255,0,0.22)' }
                      : { background: 'rgba(255,255,255,0.05)', color: 'white', border: '1px solid rgba(255,255,255,0.1)' }
                  }
                >
                  {t.cta.label}
                  <ArrowRight className="w-4 h-4" />
                </button>
              </Link>
            </div>
          ))}
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-16" style={{ background: '#02060f' }}>
        <div className="max-w-4xl mx-auto">
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em] mb-8"
            style={{ fontSize: 'clamp(1.5rem, 2.8vw, 2rem)' }}
          >
            What&apos;s actually different?
          </h2>
          <div
            className="rounded-[14px] overflow-hidden"
            style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
          >
            <table className="w-full text-left">
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                  <th className="px-5 py-3 text-[11px] font-bold uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.4)' }}></th>
                  <th className="px-5 py-3 text-[11px] font-bold uppercase tracking-wider text-center" style={{ color: 'rgba(255,255,255,0.55)' }}>Free</th>
                  <th className="px-5 py-3 text-[11px] font-bold uppercase tracking-wider text-center" style={{ color: '#7CFF00' }}>Pro</th>
                  <th className="px-5 py-3 text-[11px] font-bold uppercase tracking-wider text-center" style={{ color: 'rgba(255,255,255,0.55)' }}>Business</th>
                </tr>
              </thead>
              <tbody>
                {COMPARE.map((row, i) => (
                  <tr key={row.feature} style={{ borderBottom: i < COMPARE.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none' }}>
                    <td className="px-5 py-3 text-[13.5px]" style={{ color: 'rgba(255,255,255,0.7)' }}>{row.feature}</td>
                    <td className="px-5 py-3 text-center"><div className="inline-flex"><Cell value={row.free}     accent="rgba(255,255,255,0.55)" /></div></td>
                    <td className="px-5 py-3 text-center"><div className="inline-flex"><Cell value={row.pro}      accent="#7CFF00" /></div></td>
                    <td className="px-5 py-3 text-center"><div className="inline-flex"><Cell value={row.business} accent="rgba(255,255,255,0.55)" /></div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20">
        <div className="max-w-3xl mx-auto">
          <h2
            className="font-bold leading-[1.05] tracking-[-0.02em] mb-8"
            style={{ fontSize: 'clamp(1.5rem, 2.8vw, 2rem)' }}
          >
            Questions people are afraid to ask.
          </h2>
          <div className="space-y-3">
            {FAQ.map(item => (
              <div
                key={item.q}
                className="rounded-[12px] p-5"
                style={{ background: 'rgba(8,12,22,0.95)', border: '1px solid rgba(255,255,255,0.06)' }}
              >
                <h3 className="text-[14.5px] font-bold mb-2">{item.q}</h3>
                <p className="text-[13.5px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.55)' }}>{item.a}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20 text-center" style={{ background: '#02060f' }}>
        <div className="max-w-3xl mx-auto">
          <h2
            className="font-bold leading-[1.1] tracking-[-0.02em] mb-6"
            style={{ fontSize: 'clamp(1.7rem, 3.2vw, 2.6rem)' }}
          >
            See what&apos;s on your site first.
          </h2>
          <p className="text-[15px] leading-[1.7] mb-9" style={{ color: 'rgba(255,255,255,0.55)' }}>
            The free scan answers the only question that matters: do you have something to fix?
          </p>
          <Link href="/register">
            <button
              className="inline-flex items-center gap-2 px-7 py-3.5 rounded-[10px] text-[14px] font-semibold text-[#020617] transition-all duration-300 hover:shadow-[0_0_30px_rgba(124,255,0,0.4)] hover:scale-[1.02]"
              style={{ background: '#7CFF00', boxShadow: '0 0 20px rgba(124,255,0,0.22)' }}
            >
              Start Free Scan
              <ArrowRight className="w-4 h-4" />
            </button>
          </Link>
        </div>
      </section>

    </div>
  )
}
