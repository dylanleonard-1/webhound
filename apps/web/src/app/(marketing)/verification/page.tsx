import type { Metadata } from 'next'
import Link from 'next/link'

export const metadata: Metadata = {
  title: 'Domain ownership verification',
  description:
    'How WebHound verifies you control a domain before advanced scanning — DNS TXT, meta tag, .well-known, and provider connection.',
}

const METHODS = [
  {
    name: 'DNS TXT record',
    body: 'Add a TXT record (_webhound-verify) containing the token we give you. The most robust method and our default recommendation.',
  },
  {
    name: 'Meta tag',
    body: 'Add a <meta> tag with your verification token to your homepage HTML. Convenient for hosted site builders where editing DNS is harder.',
  },
  {
    name: '.well-known file',
    body: 'Upload a small text file to /.well-known/webhound-verify.txt containing your token.',
  },
  {
    name: 'Provider connection',
    body: 'Connect a supported hosting or DNS provider to confirm ownership automatically. Arriving with trusted scanner access.',
  },
]

export default function VerificationPage() {
  return (
    <div className="bg-[#020617] text-white">
      <section className="relative px-6 sm:px-12 xl:px-20 pt-32 pb-16 lg:pt-40 lg:pb-20">
        <div className="max-w-4xl mx-auto">
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-4" style={{ color: 'rgba(139,255,62,0.7)' }}>
            Trust &amp; safety
          </p>
          <h1 className="font-bold leading-[1.02] tracking-[-0.03em] mb-6" style={{ fontSize: 'clamp(2.2rem, 4.6vw, 3.8rem)' }}>
            Proving you own the domain
          </h1>
          <p className="text-[16px] leading-[1.65] max-w-[680px]" style={{ color: 'rgba(255,255,255,0.6)' }}>
            Before WebHound runs advanced or recurring scans on a site, we confirm you
            actually control it. This protects site owners from unwanted scanning and
            keeps WebHound a trustworthy, authorized scanner.
          </p>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 pb-24" style={{ background: '#02060f' }}>
        <div className="max-w-4xl mx-auto pt-16">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {METHODS.map((m) => (
              <div key={m.name} className="rounded-[14px] p-6" style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(255,255,255,0.06)' }}>
                <h2 className="text-[16px] font-bold mb-2">{m.name}</h2>
                <p className="text-[13.5px] leading-[1.65]" style={{ color: 'rgba(255,255,255,0.55)' }}>{m.body}</p>
              </div>
            ))}
          </div>

          <div className="rounded-[14px] p-7 mt-6" style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(124,255,0,0.18)' }}>
            <h2 className="text-[18px] font-bold mb-3">Why ownership is required first</h2>
            <p className="text-[14px] leading-[1.7]" style={{ color: 'rgba(255,255,255,0.6)' }}>
              Deep scans, continuous monitoring, and baseline tracking are powerful — so
              we gate them behind verified ownership. An unverified domain can run a
              basic one-off look, but advanced scanning, monitoring, and trusted scanner
              access only unlock once ownership is proven.
            </p>
          </div>

          <div className="flex flex-wrap gap-5 pt-8">
            <Link href="/scanner" className="text-[14px] font-semibold" style={{ color: '#7CFF00' }}>← Scanner identity</Link>
            <Link href="/ip-ranges" className="text-[14px] font-semibold" style={{ color: '#4F9CF9' }}>IP ranges →</Link>
          </div>
        </div>
      </section>
    </div>
  )
}
