import type { Metadata } from 'next'
import Link from 'next/link'

export const metadata: Metadata = {
  title: 'WebHound scanner IP ranges',
  description:
    'How to recognize and allowlist legitimate WebHound scanner traffic. Static IP ranges are coming soon.',
}

export default function IpRangesPage() {
  return (
    <div className="bg-[#020617] text-white">
      <section className="relative px-6 sm:px-12 xl:px-20 pt-32 pb-16 lg:pt-40 lg:pb-20">
        <div className="max-w-4xl mx-auto">
          <p className="text-[10px] font-bold tracking-[0.28em] uppercase mb-4" style={{ color: 'rgba(139,255,62,0.7)' }}>
            Scanner identity
          </p>
          <h1 className="font-bold leading-[1.02] tracking-[-0.03em] mb-6" style={{ fontSize: 'clamp(2.2rem, 4.6vw, 3.8rem)' }}>
            WebHound IP ranges
          </h1>
          <p className="text-[16px] leading-[1.65] max-w-[660px]" style={{ color: 'rgba(255,255,255,0.6)' }}>
            How to recognize legitimate WebHound scanner traffic so you can allowlist
            us with confidence.
          </p>
        </div>
      </section>

      <section className="relative px-6 sm:px-12 xl:px-20 pb-24" style={{ background: '#02060f' }}>
        <div className="max-w-4xl mx-auto pt-16 space-y-6">
          <div className="rounded-[14px] p-7" style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(124,255,0,0.18)' }}>
            <h2 className="text-[18px] font-bold mb-3">Static IP ranges — coming soon</h2>
            <p className="text-[14px] leading-[1.7]" style={{ color: 'rgba(255,255,255,0.6)' }}>
              WebHound currently scans from managed cloud infrastructure with dynamic
              egress addresses, so we do not publish a fixed IP allowlist yet —
              listing addresses we don&apos;t exclusively control would be inaccurate.
              Dedicated static scanner IP ranges are planned, and this page will
              publish them the moment they are live.
            </p>
          </div>

          <div className="rounded-[14px] p-7" style={{ background: 'rgba(8,12,22,0.9)', border: '1px solid rgba(255,255,255,0.06)' }}>
            <h2 className="text-[18px] font-bold mb-3">How to verify WebHound today</h2>
            <p className="text-[14px] leading-[1.7] mb-4" style={{ color: 'rgba(255,255,255,0.6)' }}>
              Until static IPs are published, the reliable signal is our honest,
              consistent User-Agent — we never spoof a browser:
            </p>
            <pre className="rounded-[10px] p-4 text-[13px] overflow-x-auto" style={{ background: '#020617', border: '1px solid rgba(255,255,255,0.08)', color: '#7CFF00' }}>
              WebHoundScanner/1.0 (+https://webhoundsecurity.com/scanner)
            </pre>
            <p className="text-[13.5px] leading-[1.7] mt-4" style={{ color: 'rgba(255,255,255,0.5)' }}>
              A machine-readable identity document is served at{' '}
              <span style={{ color: '#4F9CF9' }}>/scanner/identity</span> on our API.
            </p>
          </div>

          <div className="flex flex-wrap gap-5 pt-2">
            <Link href="/scanner" className="text-[14px] font-semibold" style={{ color: '#7CFF00' }}>← Scanner identity</Link>
            <Link href="/verification" className="text-[14px] font-semibold" style={{ color: '#4F9CF9' }}>Ownership verification →</Link>
          </div>
        </div>
      </section>
    </div>
  )
}
