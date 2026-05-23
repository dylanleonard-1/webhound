import type { Metadata } from 'next'
import Link from 'next/link'
import { ArrowRight, MapPin, Lock, FileCode, Globe2, Database, Cookie, ShieldCheck, ScanLine } from 'lucide-react'

export const metadata: Metadata = {
  title: 'How a WebHound scan works',
  description:
    'A scan is a security checkup for your website. We look at it the same way an attacker would — but we never touch anything.',
}

interface Category {
  icon: React.FC<{ className?: string }>
  label: string
  analogy: string
  body: string
}

const CATEGORIES: Category[] = [
  {
    icon: MapPin,
    label: 'Where you live online',
    analogy: 'Like checking the address on your mailbox.',
    body:
      'We confirm your domain points where you think it does, that no one has set up a lookalike, and that your SPF / DMARC email records actually protect your inbox.',
  },
  {
    icon: Lock,
    label: 'The lock on your door',
    analogy: 'Like making sure the deadbolt is rated and not about to fail.',
    body:
      'We test your SSL certificate, the encryption it uses, and the protocols your server still accepts. If a browser would refuse to load your site next month, you find out today.',
  },
  {
    icon: FileCode,
    label: 'What your site tells the world',
    analogy: 'Like reading the signs on the outside of the building.',
    body:
      'HTTP headers tell every browser how to behave around your site — whether to allow framing, run scripts from external domains, or trust content from your servers. Misconfigured headers are how most clickjacking and XSS attacks succeed.',
  },
  {
    icon: Globe2,
    label: 'Who you’re connected to',
    analogy: 'Like checking who has keys to your office.',
    body:
      'Every external script, image host, ad network, and analytics tool you load is a potential entry point. We map every third party your site reaches out to and flag the risky ones.',
  },
  {
    icon: Database,
    label: 'What you’ve left lying around',
    analogy: 'Like checking the filing cabinets aren’t unlocked.',
    body:
      'Old admin pages, exposed backups, public git folders, and forgotten staging URLs are how breaches usually start. We hunt the obvious doors and the not-so-obvious ones.',
  },
  {
    icon: Cookie,
    label: 'How you handle your visitors',
    analogy: 'Like checking that the consent forms actually work.',
    body:
      'Cookies, tracking scripts, and analytics often violate GDPR / CCPA without you knowing. We audit every cookie your site sets and every domain it talks to before consent.',
  },
]

export default function ScannerPage() {
  return (
    <div className="bg-[#020617] text-white">

      <section className="relative px-6 sm:px-12 xl:px-20 pt-32 pb-20 lg:pt-40 lg:pb-28">
        <div className="max-w-4xl mx-auto">
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-4" style={{ color: 'rgba(139,255,62,0.7)' }}>
            How a scan works
          </p>
          <h1
            className="font-bold leading-[1] tracking-[-0.03em] mb-7"
            style={{ fontSize: 'clamp(2.4rem, 5vw, 4.4rem)' }}
          >
            A security checkup
            <span className="block mt-2" style={{ color: '#7CFF00' }}>
              for your website.
            </span>
          </h1>
          <p
            className="text-[16.5px] leading-[1.65] max-w-[640px]"
            style={{ color: 'rgba(255,255,255,0.6)' }}
          >
            Think of a WebHound scan like the security check a hotel does on
            every door in the building. We look at your website the same way an
            attacker would — but we only read what&apos;s already public. Nothing on
            your site changes. Nothing breaks. You just learn what&apos;s exposed.
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
              No credit card · results in under 2 minutes
            </span>
          </div>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20 lg:py-28" style={{ background: '#02060f' }}>
        <div className="max-w-6xl mx-auto">
          <div className="mb-12 max-w-[640px]">
            <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-3" style={{ color: 'rgba(139,255,62,0.65)' }}>
              What we look at
            </p>
            <h2
              className="font-bold leading-[1.05] tracking-[-0.02em]"
              style={{ fontSize: 'clamp(1.7rem, 3.2vw, 2.6rem)' }}
            >
              Six areas. Thousands of checks. One report.
            </h2>
            <p className="text-[14.5px] leading-[1.65] mt-4" style={{ color: 'rgba(255,255,255,0.5)' }}>
              Every scan runs the same complete sweep. You don&apos;t have to know what to look for — that&apos;s our job.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {CATEGORIES.map((c) => {
              const Icon = c.icon
              return (
                <div
                  key={c.label}
                  className="rounded-[14px] p-6"
                  style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(255,255,255,0.06)' }}
                >
                  <div className="flex items-center gap-3 mb-4">
                    <div
                      className="w-9 h-9 rounded-[9px] flex items-center justify-center flex-shrink-0"
                      style={{ background: 'rgba(124,255,0,0.06)', border: '1px solid rgba(124,255,0,0.18)' }}
                    >
                      <Icon className="w-4 h-4" style={{ color: '#7CFF00' }} />
                    </div>
                    <h3 className="text-[15.5px] font-bold leading-tight">{c.label}</h3>
                  </div>
                  <p className="text-[12.5px] italic mb-3" style={{ color: 'rgba(139,255,62,0.65)' }}>
                    {c.analogy}
                  </p>
                  <p className="text-[13.5px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.55)' }}>
                    {c.body}
                  </p>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20 lg:py-28">
        <div className="max-w-5xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-8">
          <div
            className="rounded-[14px] p-8"
            style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(124,255,0,0.18)' }}
          >
            <div
              className="w-11 h-11 rounded-[10px] flex items-center justify-center mb-5"
              style={{ background: 'rgba(124,255,0,0.08)', border: '1px solid rgba(124,255,0,0.25)' }}
            >
              <ShieldCheck className="w-5 h-5" style={{ color: '#7CFF00' }} />
            </div>
            <h3 className="text-[19px] font-bold mb-3">Is this safe to run?</h3>
            <p className="text-[14px] leading-[1.7]" style={{ color: 'rgba(255,255,255,0.6)' }}>
              Yes. WebHound is <span className="text-white font-semibold">passive</span> — we read the same
              public information your visitors see. We never log in, never submit forms, never try exploits.
              It&apos;s the difference between reading a sign on a building and trying to pick the lock.
            </p>
          </div>

          <div
            className="rounded-[14px] p-8"
            style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(79,156,249,0.18)' }}
          >
            <div
              className="w-11 h-11 rounded-[10px] flex items-center justify-center mb-5"
              style={{ background: 'rgba(79,156,249,0.08)', border: '1px solid rgba(79,156,249,0.25)' }}
            >
              <ScanLine className="w-5 h-5" style={{ color: '#4F9CF9' }} />
            </div>
            <h3 className="text-[19px] font-bold mb-3">How long does it take?</h3>
            <p className="text-[14px] leading-[1.7]" style={{ color: 'rgba(255,255,255,0.6)' }}>
              Most scans finish in under two minutes. Large sites with many pages take a few minutes longer.
              You can close the tab — we&apos;ll email the report when it&apos;s done.
            </p>
          </div>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 py-20 lg:py-28 text-center" style={{ background: '#02060f' }}>
        <div className="max-w-3xl mx-auto">
          <h2
            className="font-bold leading-[1.1] tracking-[-0.02em] mb-6"
            style={{ fontSize: 'clamp(1.7rem, 3.2vw, 2.6rem)' }}
          >
            Ready to see what&apos;s exposed?
          </h2>
          <p className="text-[15px] leading-[1.7] mb-9" style={{ color: 'rgba(255,255,255,0.55)' }}>
            One free scan. No card. Results in under two minutes.
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
          <div className="mt-12 pt-9" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <p className="text-[12px] tracking-wider uppercase mb-3" style={{ color: 'rgba(255,255,255,0.32)' }}>
              Next chapter
            </p>
            <Link
              href="/monitoring"
              className="inline-flex items-center gap-1.5 text-[14.5px] font-semibold transition-colors"
              style={{ color: '#4F9CF9' }}
            >
              One scan is a snapshot. See how monitoring keeps watching.
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

    </div>
  )
}
