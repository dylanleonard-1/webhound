import type { Metadata } from 'next'
import { LegalPage, type LegalSection } from '@/components/marketing/legal-page'

export const metadata: Metadata = {
  title: 'Data Retention Policy',
  description: 'How long WebHound keeps your data, and how to delete it.',
}

const LAST_UPDATED = 'May 24, 2026'

const sections: LegalSection[] = [
  {
    title: '1. What We Store',
    body: [
      'Account data: email, name, hashed password, plan tier, billing customer ID. Stored for the life of the account.',
      'Scan inputs: domain names and URLs you submit, plus any verification artifacts you generate.',
      'Scan outputs: findings, evidence snippets (redacted where they contain secrets), engine diagnostics, scan timings, generated reports (JSON, CSV, SARIF, Markdown, PDF).',
      'WADE baselines: snapshots of your sites used for behavioral-anomaly comparison across scans.',
      'Usage logs: API request timestamps, authentication events, IP address (truncated to /24 for IPv4, /48 for IPv6 after 30 days).',
      'Billing records: Stripe customer ID, subscription history, invoice metadata. Stripe stores payment-method details — we do not.',
    ],
  },
  {
    title: '2. How Long We Keep Each Category',
    body: [
      'Scan history: limited by your plan — Free retains 7 days, Starter retains 90 days, Pro retains 365 days, Enterprise is custom. After the retention window, scan findings and reports are deleted permanently.',
      'WADE baselines: we retain the three most recent baselines per website indefinitely while the website is monitored. Older baselines are deleted automatically.',
      'Authentication logs: 12 months. Used for security investigations and account-recovery support.',
      'Email and password-reset tokens: 24 hours from issuance, regardless of use.',
      'Billing records: 7 years from the date of the transaction (US tax and GDPR / payment-processor record-keeping requirements).',
      'Account-deletion grace period: when you delete your account, scan data is removed immediately; account metadata is retained for 30 days in case you change your mind, after which all PII is deleted.',
    ],
  },
  {
    title: '3. Backups',
    body: [
      'We take encrypted database backups daily. Backups are retained for 30 days.',
      'When you delete data from your account, the deletion is reflected in production immediately. Backup copies are purged on the regular 30-day rotation; we do not selectively scrub backups for individual users.',
      'In the event we restore from a backup that pre-dates a user-requested deletion, we will re-execute the deletion against the restored data.',
    ],
  },
  {
    title: '4. How to Delete Your Data',
    body: [
      'In-app: Settings → Account → Delete account. This is the fastest path; the deletion runs immediately.',
      'By email: send a deletion request to privacy@webhoundsecurity.com from the email address registered on the account. We will verify the request and complete it within 30 days (GDPR statutory window).',
      'Per-resource deletion: you can delete individual websites, scan results, or baselines from the dashboard at any time. Cascading deletes remove all dependent data.',
      'Right to data export: before deletion, you can request a copy of all data we hold on you by emailing privacy@webhoundsecurity.com. We provide it in machine-readable JSON within 30 days at no cost.',
    ],
  },
  {
    title: '5. Third-Party Data Sharing',
    body: [
      'Stripe (payment processor): receives billing email, customer ID, subscription tier. Stripe\'s retention policy applies to payment-method data; we never see card numbers.',
      'VirusTotal / URLhaus (optional, opt-in): receive the hostnames you submit to WebHound for threat-intel enrichment. They do not receive scan findings or your account information.',
      'Resend (transactional email): receives your email address for delivery of scan notifications, verification codes, and password-reset links.',
      'Twilio (SMS, if enabled): receives your phone number for 2FA verification codes.',
      'Cloud infrastructure (Railway, Vercel): hosts our application stack. Data at rest is encrypted with provider-managed keys.',
      'Law enforcement: only on receipt of a valid subpoena, warrant, or equivalent legal process. We will notify you unless legally prohibited.',
    ],
  },
  {
    title: '6. Anonymization for Product Improvement',
    body: [
      'Aggregated, fully anonymized scan statistics (e.g. "75% of WordPress sites scanned in May expose readme.html") may be used to improve detection heuristics and to publish industry research.',
      'Anonymization removes: account identifiers, hostnames, IP addresses, user-supplied content. Only category counts and engine-level signals are retained.',
      'You may opt out of even-anonymized aggregation by emailing privacy@webhoundsecurity.com. Opt-out has no effect on the service you receive.',
    ],
  },
  {
    title: '7. International Transfers',
    body: [
      'WebHound is operated from the United States. If you are in the EU, UK, or another jurisdiction that restricts international data transfers, your data will be transferred to the US for processing.',
      'We rely on the EU\'s Standard Contractual Clauses (SCCs) for EU-to-US transfers and the UK International Data Transfer Addendum for UK-to-US transfers. For enterprise customers, we will execute a Data Processing Addendum on request.',
    ],
  },
  {
    title: '8. Changes to This Policy',
    body: [
      'We may update this policy. Material changes (shorter retention windows, new data categories, new processors) will be communicated by email and in-app notice at least 14 days in advance.',
      'Material reductions in your rights will not apply retroactively without your consent.',
    ],
  },
]

export default function DataRetentionPage() {
  return (
    <LegalPage
      title="Data Retention"
      subtitle="What we keep, for how long, and how to make us forget."
      lastUpdated={LAST_UPDATED}
      sections={sections}
      footerNote={
        <>
          For a Data Processing Addendum or a copy of our Standard Contractual Clauses,
          contact{' '}
          <a href="mailto:privacy@webhoundsecurity.com" className="text-[#8BFF3E] hover:underline">
            privacy@webhoundsecurity.com
          </a>.
        </>
      }
    />
  )
}
