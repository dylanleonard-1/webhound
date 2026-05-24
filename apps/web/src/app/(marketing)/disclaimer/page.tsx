import type { Metadata } from 'next'
import { LegalPage, type LegalSection } from '@/components/marketing/legal-page'

export const metadata: Metadata = {
  title: 'Disclaimer',
  description: 'WebHound scan output is best-effort information, not a guarantee of security.',
}

const LAST_UPDATED = 'May 24, 2026'

const sections: LegalSection[] = [
  {
    title: '1. No Guarantee of Security',
    body: [
      'WebHound performs automated security scanning. A scan that returns zero findings does NOT mean your site is secure — it means the scan engines did not find issues within the scope and depth of the specific scan profile that was run.',
      'Security is a continuous process, not a point-in-time certificate. New vulnerabilities are disclosed daily. A site that was clean yesterday may be vulnerable today.',
      'WebHound is not a substitute for: manual penetration testing by qualified professionals, ongoing security review of code changes, secure-by-design development practices, or a formal security program.',
    ],
  },
  {
    title: '2. Findings Are Best-Effort, Not Authoritative',
    body: [
      'WebHound\'s scanners are heuristic. They produce both false positives (flagging benign configurations) and false negatives (missing real vulnerabilities). The confidence score attached to each finding reflects our estimate of true-positive likelihood; it is not a guarantee.',
      'Severity scores (Critical / High / Medium / Low / Info) and CVSS values are calculated from standard formulas and our internal heuristics. The actual business risk of any finding depends on context only you have: data sensitivity, threat model, mitigating controls, exposure surface.',
      'Compliance framework references (PCI DSS, ISO 27001, SOC 2, HIPAA, OWASP, NIST) are intended as starting points for your auditors and compliance team. WebHound does not certify compliance with any framework; only authorized assessors can do that.',
    ],
  },
  {
    title: '3. Limitation of Liability',
    body: [
      'To the maximum extent permitted by law, WebHound is provided "AS IS" without warranties of any kind, express or implied, including but not limited to merchantability, fitness for a particular purpose, and non-infringement.',
      'WebHound, its operators, employees, and contractors are not liable for any damage, loss, or harm — including direct, indirect, incidental, consequential, special, punitive, or exemplary damages — arising from your use of the service or from acts taken (or not taken) based on WebHound output.',
      'Our total cumulative liability for any claim arising out of or relating to the Service is limited to the amount you paid us for the Service in the twelve months preceding the event giving rise to the claim. For free-tier users, that amount is zero dollars.',
      'These limitations apply even if we have been advised of the possibility of such damages.',
    ],
  },
  {
    title: '4. Scan Disruption Is Not Our Fault',
    body: [
      'WebHound scans are passive by design — they make GET and HEAD requests at conservative rates, do not submit forms, do not execute JavaScript, and do not attempt to exploit vulnerabilities.',
      'However, some systems are sensitive to even passive traffic — for example, custom WAF rules that block "scanner" User-Agents, or services with extremely low connection limits. If a scan triggers a temporary issue with your target system, we are not liable for the disruption.',
      'If you are scanning a production system, run the lightest scan profile first to validate that the target accepts WebHound traffic before scheduling continuous monitoring.',
    ],
  },
  {
    title: '5. Third-Party Data Sources',
    body: [
      'WebHound integrates with optional third-party threat intelligence providers (VirusTotal, abuse.ch URLhaus). When enabled, these providers receive the hostnames WebHound is scanning. Their accuracy, latency, and uptime are outside our control.',
      'Public WHOIS data, DNS records, and TLS certificate metadata that appear in WebHound reports are sourced from authoritative public services. We do not guarantee the accuracy of upstream data.',
      'Plugin / theme / framework version detection is heuristic — based on URL patterns, response headers, and file fingerprints. False positives are possible.',
    ],
  },
  {
    title: '6. Use of WebHound Output',
    body: [
      'WebHound output (reports, findings, recommendations) is your data. You may use it internally without restriction.',
      'If you incorporate WebHound output into a report you sell or otherwise distribute (e.g. a pentest report you deliver to your client), you may not represent WebHound output as your own original analysis. Attribute the source.',
      'Acting on WebHound findings against systems you do not own and do not have authorization to modify constitutes unauthorized access. See the Acceptable Use Policy.',
    ],
  },
  {
    title: '7. Service Availability',
    body: [
      'WebHound is hosted on third-party infrastructure (cloud, CDN, DNS). Outages of those services may make WebHound temporarily unavailable.',
      'Free-tier users have no SLA. Paid plans include the SLA published with the plan; see the order form / pricing page for details.',
      'Scheduled scans that are delayed or skipped due to infrastructure outages do not create liability — they will run at the next available opportunity.',
    ],
  },
  {
    title: '8. Indemnification',
    body: [
      'You agree to defend, indemnify, and hold harmless WebHound, its operators, employees, and contractors against any claim, loss, liability, or expense (including reasonable attorneys\' fees) arising from: (a) your use of the Service in violation of our Terms or Acceptable Use Policy; (b) your scanning of systems without proper authorization; (c) your handling of data WebHound provided you (especially findings and evidence that may be confidential to a third party).',
      'We will cooperate with you in defending such claims and may, at our option, assume exclusive defense and control of the matter.',
    ],
  },
]

export default function DisclaimerPage() {
  return (
    <LegalPage
      title="Disclaimer"
      subtitle="The limits of what a WebHound scan can tell you, and the limits of our liability for what it does tell you."
      lastUpdated={LAST_UPDATED}
      sections={sections}
      footerNote={
        <>
          This page should be read together with the{' '}
          <a href="/terms" className="text-[#8BFF3E] hover:underline">Terms of Service</a>{' '}
          and{' '}
          <a href="/acceptable-use" className="text-[#8BFF3E] hover:underline">
            Acceptable Use Policy
          </a>.
        </>
      }
    />
  )
}
