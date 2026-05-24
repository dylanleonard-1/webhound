import type { Metadata } from 'next'
import { LegalPage, type LegalSection } from '@/components/marketing/legal-page'

export const metadata: Metadata = {
  title: 'Acceptable Use Policy',
  description:
    'You may only scan systems you own or are authorized to test. Read the rules before running a scan.',
}

const LAST_UPDATED = 'May 24, 2026'

const sections: LegalSection[] = [
  {
    title: '1. Who This Policy Applies To',
    body: [
      'This Acceptable Use Policy ("AUP") applies to every user of WebHound — free tier, paid subscribers, trial users, and enterprise customers — and forms part of your agreement with us.',
      'By using WebHound you confirm that you have read this AUP and agree to scan only systems you are legally authorized to test.',
    ],
  },
  {
    title: '2. Authorization — Read This First',
    body: [
      'You may submit a domain, IP address, or URL for scanning ONLY if at least one of the following is true:',
      '(a) You own the system being scanned, or your employer / client owns it and has given you written or in-platform authority to commission security testing on their behalf.',
      '(b) You have explicit, written authorization from the owner — for example, a signed Statement of Work, a Penetration Test Authorization Letter, an executed Master Services Agreement that includes security testing, or a bug-bounty program that lists the asset in scope.',
      '(c) You are testing a domain that WebHound itself owns and has authorized for demonstration (e.g. webhoundsecurity.com, scan-me.webhoundsecurity.com).',
      'Scanning without authorization may violate the Computer Fraud and Abuse Act (USA), the Computer Misuse Act (UK), the EU Directive 2013/40/EU, or equivalent legislation in your jurisdiction. Penalties may include fines, civil damages, and criminal charges. We have zero tolerance for unauthorized scanning.',
    ],
  },
  {
    title: '3. Prohibited Activities',
    body: [
      'Scanning systems you do not own and do not have written authorization to test.',
      'Using WebHound to conduct denial-of-service or volumetric attacks. WebHound scans are rate-limited by design but you must not chain, distribute, or otherwise amplify the load against any target.',
      'Attempting to exploit, modify, or escalate access to vulnerabilities WebHound discovers. WebHound is a passive scanner — it identifies findings, it does not weaponize them. Acting on the findings against systems you do not control is your problem, not ours.',
      'Scanning critical infrastructure or systems whose disruption would create public-safety risk (utilities, hospitals, traffic systems, emergency services) without explicit written authorization from the system operator.',
      'Using WebHound output to defame, extort, harass, or shake down third parties.',
      'Reselling, white-labeling, or sublicensing WebHound output without an enterprise agreement that explicitly permits it.',
      'Submitting domains owned by competitors with the intent to obtain trade secrets or non-public information.',
      'Submitting login URLs, admin URLs, or pre-authenticated session URLs of services where you are not an authorized user.',
      'Using the WebHound API or web interface to scrape, crawl, or otherwise extract data from WebHound itself at a rate that interferes with normal service operation.',
      'Bypassing or circumventing WebHound\'s rate limits, plan quotas, or domain-ownership verification mechanisms.',
      'Creating multiple accounts to evade plan limits or to circumvent a previous suspension.',
    ],
  },
  {
    title: '4. Domain Ownership Verification',
    body: [
      'WebHound verifies domain ownership through DNS TXT records, HTML meta tags, or file uploads before allowing deep scans, continuous monitoring, or large scan budgets. Verification is the legal and technical attestation that you control the target — bypassing it puts both you and us at risk.',
      'For one-off scans against domains you do not control (e.g. testing webhoundsecurity.com to evaluate the service), only the default lightweight scan profile is available. Continuous monitoring, alerts, and exports require verification.',
      'Submitting a verification token to a domain you do not actually control — for example, exploiting a subdomain takeover, posting the token to a third-party file-upload service, or social-engineering the actual owner — constitutes unauthorized scanning under Section 3.',
    ],
  },
  {
    title: '5. Reporting Vulnerabilities You Find',
    body: [
      'If a WebHound scan reveals a vulnerability on a third-party system that you are authorized to test, you are responsible for reporting it through the asset owner\'s preferred channel (a public security.txt entry, a bug bounty program, or a direct contact). WebHound does not auto-notify third parties.',
      'If a WebHound scan reveals a vulnerability that puts non-customer-controlled systems at risk (a supply-chain compromise, a leaked credential affecting an unrelated organization), notify both the affected party and us at security@webhoundsecurity.com so we can coordinate disclosure.',
      'Do not disclose vulnerabilities publicly without giving the affected party a reasonable opportunity to remediate (industry norm: 90 days, with shorter windows for actively exploited issues).',
    ],
  },
  {
    title: '6. Compliance With Local Law',
    body: [
      'Security testing law varies by country. You are responsible for compliance with the law of every jurisdiction in which (a) you operate, (b) the target system is located, and (c) the user data on that target resides.',
      'WebHound is operated from the United States and serves a global customer base. Use of WebHound from sanctioned regions identified by OFAC or equivalent authorities is prohibited.',
      'If you are a security researcher acting under the Computer Fraud and Abuse Act\'s "good faith security research" carve-out (US, post-2022 DOJ memo), document your authorization and stay within the bounds of that authorization.',
    ],
  },
  {
    title: '7. Enforcement',
    body: [
      'We may suspend or terminate access without notice if we have a good-faith belief that you have violated this AUP.',
      'Severe violations — particularly unauthorized scanning of critical infrastructure or evidence of coordinated abuse — will be reported to the appropriate law-enforcement agency along with all account, billing, and scan logs we hold.',
      'We may share information about abuse with affected parties, registrars, hosting providers, and other security services where doing so reduces ongoing harm.',
      'Customers terminated for AUP violations are not entitled to refunds for unused subscription time.',
    ],
  },
  {
    title: '8. Reporting Abuse',
    body: [
      'If you believe a WebHound user is scanning your systems without authorization, contact abuse@webhoundsecurity.com with: (a) the affected domain or IP, (b) timestamps of the suspicious activity, and (c) any logs (User-Agent, source IP) you can share.',
      'WebHound publishes a User-Agent containing "WebHound" in every scan request so legitimate operators can correlate access logs.',
      'We will investigate and respond within 2 business days. Confirmed AUP violations lead to immediate account suspension.',
    ],
  },
  {
    title: '9. Changes to This Policy',
    body: [
      'We may update this AUP from time to time. Material changes will be communicated by email and via an in-product notice at least 14 days before they take effect.',
      'Continued use of WebHound after the effective date of an updated AUP constitutes acceptance of the revised terms.',
    ],
  },
]

export default function AcceptableUsePage() {
  return (
    <LegalPage
      title="Acceptable Use Policy"
      subtitle="The rules every WebHound user agrees to. The single most important rule: you may only scan systems you own or are explicitly authorized to test."
      lastUpdated={LAST_UPDATED}
      sections={sections}
      footerNote={
        <>
          Questions about whether a specific use case is acceptable? Email{' '}
          <a href="mailto:abuse@webhoundsecurity.com" className="text-[#8BFF3E] hover:underline">
            abuse@webhoundsecurity.com
          </a>
          {' '}before running the scan. We&apos;d rather answer your question than process an abuse report.
        </>
      }
    />
  )
}
