import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Terms of Service',
  description: 'The terms and conditions governing your use of the WebHound security scanning service.',
}

const LAST_UPDATED = 'May 13, 2025'

const sections = [
  {
    title: '1. Acceptance of Terms',
    body: [
      'By accessing or using WebHound ("the Service"), you agree to be bound by these Terms of Service. If you do not agree, do not use the Service.',
      'These Terms apply to all users including free tier, paid subscribers, and enterprise customers.',
      'We reserve the right to update these Terms at any time. Material changes will be communicated at least 14 days in advance via email or in-app notice.',
    ],
  },
  {
    title: '2. Description of Service',
    body: [
      'WebHound is a web application security scanning platform. It performs passive and active security analysis of domains and web applications you explicitly authorize.',
      'The Service includes vulnerability detection, DNS analysis, SSL/TLS auditing, dependency scanning, threat intelligence correlation, and automated report generation.',
      'Features available depend on your subscription plan.',
    ],
  },
  {
    title: '3. Authorized Use',
    body: [
      'You may only submit domains and targets that you own or have explicit written authorization to scan.',
      'By submitting a scan target, you represent and warrant that you have lawful authority to authorize security testing of that target.',
      'WebHound is a security tool for authorized testing. Any use against targets you do not own or have permission to scan is strictly prohibited and may violate applicable law.',
    ],
  },
  {
    title: '4. Prohibited Use',
    body: [
      'Using the Service to scan systems without authorization.',
      'Attempting to disrupt, overload, or interfere with any part of the Service or its infrastructure.',
      'Reverse engineering, decompiling, or extracting the scanning engine or threat intelligence feeds.',
      'Reselling or redistributing the Service or scan results without a written enterprise agreement.',
      'Using the Service for any illegal purpose or in violation of any applicable law or regulation.',
      'Sharing account credentials or circumventing access controls.',
    ],
  },
  {
    title: '5. Account Responsibilities',
    body: [
      'You are responsible for maintaining the confidentiality of your account credentials.',
      'You are responsible for all activity that occurs under your account.',
      'You must notify us immediately of any unauthorized use of your account at security@webhoundsecurity.com.',
      'You must provide accurate and complete registration information and keep it up to date.',
    ],
  },
  {
    title: '6. Subscription and Payment',
    body: [
      'Paid subscriptions are billed in advance on a monthly or annual basis.',
      'All fees are non-refundable except as required by law or at our discretion within 14 days of the billing date.',
      'We reserve the right to change pricing with 30 days notice to existing subscribers.',
      'Failure to pay may result in suspension or termination of your account.',
    ],
  },
  {
    title: '7. Intellectual Property',
    body: [
      'WebHound and its scanning engine, threat intelligence feeds, and report formats are the intellectual property of WebHound, Inc.',
      'Scan results and reports generated for your targets are your data. You retain ownership of your submitted targets and generated reports.',
      'You grant us a limited license to process your scan targets solely to deliver the Service.',
    ],
  },
  {
    title: '8. Disclaimer of Warranties',
    body: [
      'THE SERVICE IS PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, EXPRESS OR IMPLIED.',
      'WE DO NOT WARRANT THAT THE SERVICE WILL BE UNINTERRUPTED, ERROR-FREE, OR THAT IT WILL DETECT ALL VULNERABILITIES IN YOUR TARGET SYSTEMS.',
      'SCAN RESULTS SHOULD NOT BE RELIED UPON AS THE SOLE BASIS FOR SECURITY DECISIONS. ENGAGE A QUALIFIED SECURITY PROFESSIONAL FOR COMPREHENSIVE ASSESSMENTS.',
    ],
  },
  {
    title: '9. Limitation of Liability',
    body: [
      'TO THE MAXIMUM EXTENT PERMITTED BY LAW, WEBHOUND SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES.',
      'OUR TOTAL LIABILITY ARISING OUT OF OR RELATED TO THESE TERMS SHALL NOT EXCEED THE AMOUNT YOU PAID TO US IN THE TWELVE MONTHS PRECEDING THE CLAIM.',
    ],
  },
  {
    title: '10. Termination',
    body: [
      'You may cancel your account at any time through your account settings.',
      'We may suspend or terminate your account immediately if you violate these Terms, particularly the Authorized Use provisions.',
      'Upon termination, your access to the Service will cease. Scan data may be retained for up to 90 days before deletion.',
    ],
  },
  {
    title: '11. Governing Law',
    body: [
      'These Terms are governed by the laws of the State of Delaware, United States, without regard to conflict of law principles.',
      'Any disputes arising from these Terms shall be resolved through binding arbitration in accordance with the American Arbitration Association rules.',
    ],
  },
  {
    title: '12. Contact',
    body: [
      'For questions about these Terms, contact us at legal@webhoundsecurity.com.',
      'WebHound Security · legal@webhoundsecurity.com',
    ],
  },
]

export default function TermsPage() {
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
            Terms of Service
          </h1>
          <p className="text-[rgba(255,255,255,0.44)] text-base">
            Last updated: {LAST_UPDATED}
          </p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-3xl mx-auto px-6 py-14 sm:py-20">
        <p className="text-[rgba(255,255,255,0.55)] text-base leading-relaxed mb-12">
          These Terms of Service govern your access to and use of WebHound's web application
          security scanning platform. Please read them carefully before using the Service.
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
            These Terms were written to be clear and fair. If something is unclear or you have
            a specific legal question, reach out to{' '}
            <a href="mailto:legal@webhoundsecurity.com" className="text-[#8BFF3E] hover:underline">
              legal@webhoundsecurity.com
            </a>{' '}
            before using the Service.
          </p>
        </div>
      </div>
    </div>
  )
}
