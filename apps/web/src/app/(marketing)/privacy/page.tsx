import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Privacy Policy',
  description: 'How WebHound collects, uses, and protects your data.',
}

const LAST_UPDATED = 'May 13, 2025'

const sections = [
  {
    title: '1. Information We Collect',
    body: [
      'Account information you provide when registering: name, email address, and password.',
      'Scan targets you submit: domain names and URLs you authorize WebHound to scan.',
      'Usage data: pages visited, features used, scan frequency, and session duration.',
      'Technical data: IP address, browser type, operating system, and device identifiers.',
      'Payment information: billing address and payment method details, processed by our payment provider. We do not store raw card numbers.',
    ],
  },
  {
    title: '2. How We Use Your Information',
    body: [
      'To operate and deliver the WebHound scanning service.',
      'To generate security reports and remediation recommendations for your submitted targets.',
      'To send transactional emails: scan completion notifications, alert feeds, and certificate expiry warnings.',
      'To improve our detection accuracy, scan engine, and threat intelligence feeds.',
      'To process payments and manage your subscription.',
      'To comply with legal obligations and enforce our Terms of Service.',
    ],
  },
  {
    title: '3. Scanning and Target Data',
    body: [
      'WebHound only scans domains and URLs you explicitly submit and authorize. We do not initiate scans against third-party targets without your instruction.',
      'Scan results, findings, and reports are stored on your behalf and are private to your account.',
      'We may use anonymized, aggregated scan statistics (e.g., "percentage of sites with TLS 1.0 enabled") to improve our product and publish research. No individual scan results are shared.',
    ],
  },
  {
    title: '4. Data Sharing and Third Parties',
    body: [
      'We do not sell your personal data.',
      'We share data with service providers who help us operate WebHound: cloud infrastructure (AWS), payment processing (Stripe), and analytics (privacy-preserving, no cross-site tracking).',
      'We may disclose data if required by law, court order, or to protect the rights and safety of our users or the public.',
      'If WebHound is acquired, your data may be transferred to the acquirer, subject to the same privacy commitments.',
    ],
  },
  {
    title: '5. Data Retention',
    body: [
      'Account data is retained for the lifetime of your account and for up to 90 days after deletion.',
      'Scan results and reports are retained per your subscription plan. Free tier: 30 days. Pro tier: 12 months. Enterprise: custom.',
      'You may request deletion of your data at any time by contacting us at privacy@webhoundsecurity.com.',
    ],
  },
  {
    title: '6. Your Rights',
    body: [
      'Access: You may request a copy of the personal data we hold about you.',
      'Correction: You may update inaccurate data through your account settings or by contacting us.',
      'Deletion: You may request deletion of your account and associated data.',
      'Portability: You may export your scan reports in PDF, CSV, or JSON format at any time.',
      'Objection: You may opt out of non-essential communications at any time via account settings.',
      'If you are in the EU or UK, you have additional rights under GDPR including the right to lodge a complaint with your supervisory authority.',
    ],
  },
  {
    title: '7. Security',
    body: [
      'All data is encrypted in transit using TLS 1.3 and at rest using AES-256.',
      'Access to production systems is restricted to authorized personnel and requires multi-factor authentication.',
      'We conduct regular security audits and penetration tests of our own infrastructure.',
      'To report a security vulnerability in WebHound, please contact security@webhoundsecurity.com.',
    ],
  },
  {
    title: '8. Cookies',
    body: [
      'We use strictly necessary cookies for authentication and session management.',
      'We use functional cookies to remember your preferences.',
      'We do not use third-party advertising cookies or cross-site tracking.',
      'You can manage cookie preferences in your browser settings.',
    ],
  },
  {
    title: '9. Changes to This Policy',
    body: [
      'We may update this Privacy Policy from time to time. We will notify you of material changes via email or a prominent notice in the dashboard at least 14 days before the change takes effect.',
      'Continued use of WebHound after changes constitutes acceptance of the updated policy.',
    ],
  },
  {
    title: '10. Contact',
    body: [
      'For privacy questions, data requests, or complaints, contact us at privacy@webhoundsecurity.com.',
      'WebHound Security · privacy@webhoundsecurity.com',
    ],
  },
]

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-[#020617]">
      {/* Header */}
      <div className="border-b border-[rgba(139,255,62,0.07)] bg-[#020617]">
        <div className="max-w-3xl mx-auto px-6 py-16 sm:py-20">
          <div className="inline-flex items-center gap-2 mb-6">
            <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
            <span className="text-[10px] font-bold text-[#8BFF3E] tracking-[0.22em] uppercase">Legal</span>
            <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
          </div>
          <h1 className="text-4xl sm:text-5xl font-bold text-white tracking-tight mb-4">
            Privacy Policy
          </h1>
          <p className="text-[rgba(255,255,255,0.44)] text-base">
            Last updated: {LAST_UPDATED}
          </p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-3xl mx-auto px-6 py-14 sm:py-20">
        <p className="text-[rgba(255,255,255,0.55)] text-base leading-relaxed mb-12">
          WebHound ("we", "our", or "us") is committed to protecting your privacy. This Policy
          explains what information we collect, how we use it, and your rights regarding that
          information when you use the WebHound web application security scanning service.
        </p>

        <div className="flex flex-col gap-12">
          {sections.map((s) => (
            <div key={s.title}>
              <h2 className="text-xl font-bold text-white mb-4">{s.title}</h2>
              <ul className="flex flex-col gap-3">
                {s.body.map((item, i) => (
                  <li key={i} className="flex items-start gap-3">
                    <span className="w-1 h-1 rounded-full bg-[rgba(139,255,62,0.5)] mt-2 flex-shrink-0" />
                    <span className="text-[rgba(255,255,255,0.52)] text-sm leading-relaxed">{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Footer note */}
        <div
          className="mt-14 rounded-[14px] border border-[rgba(139,255,62,0.1)] px-6 py-5"
          style={{ background: 'rgba(139,255,62,0.03)' }}
        >
          <p className="text-[rgba(255,255,255,0.38)] text-sm leading-relaxed">
            This document is provided for informational purposes. For enterprise data processing
            agreements or GDPR Data Processing Addendums, contact{' '}
            <a href="mailto:privacy@webhoundsecurity.com" className="text-[#8BFF3E] hover:underline">
              privacy@webhoundsecurity.com
            </a>.
          </p>
        </div>
      </div>
    </div>
  )
}
