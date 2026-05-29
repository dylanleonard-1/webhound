import type { Metadata } from 'next'
import { Shield, Lock, Eye, Server, AlertCircle, Mail, Clock, ScrollText } from 'lucide-react'

export const metadata: Metadata = {
  title: 'Security & Trust — WebHound',
  description:
    'WebHound security policy, responsible disclosure programme, and how to report a vulnerability. A cybersecurity product treats its own security disclosure seriously.',
}

const PRINCIPLES = [
  {
    icon: Eye,
    title: 'Passive scanning only',
    desc: 'WebHound never modifies your site, exploits weaknesses, or makes authenticated requests. Every scan is read-only and safe to run against production.',
  },
  {
    icon: Lock,
    title: 'No credential storage',
    desc: 'We never store passwords, API keys, or session tokens. Scans are performed against the public-facing URL only.',
  },
  {
    icon: Shield,
    title: 'Authorized targets only',
    desc: 'By using WebHound you confirm you own or are authorized to scan the target URL. Scanning unauthorized targets violates our terms and potentially the law.',
  },
  {
    icon: Server,
    title: 'Data handling',
    desc: 'Scan results are stored securely and accessible only to your account. We do not sell or share scan data with third parties.',
  },
]

const RESPONSE_TIMES = [
  { sev: 'Critical', target: 'Acknowledged within 24 hours · resolved within 7 days',  color: '#ef4444' },
  { sev: 'High',     target: 'Acknowledged within 48 hours · resolved within 14 days', color: '#f97316' },
  { sev: 'Medium',   target: 'Acknowledged within 5 business days · resolved within 30 days', color: '#eab308' },
  { sev: 'Low',      target: 'Acknowledged within 10 business days · resolved on a best-effort basis', color: '#22d3ee' },
]

export default function SecurityPage() {
  return (
    <div className="max-w-4xl mx-auto px-5 py-20">
      {/* ── Header ───────────────────────────────────────────── */}
      <div className="text-center mb-14">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/25 bg-accent-green/[0.06] mb-5">
          <Shield className="w-3.5 h-3.5 text-accent-green" />
          <span className="text-xs font-medium text-accent-green tracking-wide">Security & Trust</span>
        </div>
        <h1 className="text-4xl font-semibold text-white mb-4 tracking-tight">
          Built with security in mind
        </h1>
        <p className="text-gray-400 max-w-lg mx-auto">
          WebHound is a passive, authorized website security platform. Here's how we
          operate safely and how to reach our security team if you find an issue with
          WebHound itself.
        </p>
      </div>

      {/* ── Security policy (operating principles) ───────────── */}
      <h2 className="text-[10px] font-bold tracking-[0.28em] uppercase mb-4 text-accent-green/70">
        Our security policy
      </h2>
      <div className="grid sm:grid-cols-2 gap-5 mb-14">
        {PRINCIPLES.map(({ icon: Icon, title, desc }) => (
          <div key={title} className="rounded-xl border border-white/[0.07] bg-[#111827] p-6">
            <div className="w-9 h-9 rounded-lg bg-accent-green/10 flex items-center justify-center mb-4">
              <Icon className="w-4.5 h-4.5 text-accent-green" />
            </div>
            <h3 className="text-sm font-semibold text-white mb-2">{title}</h3>
            <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
          </div>
        ))}
      </div>

      {/* ── Disclosure section — anchor target for the footer
            'Report a Vulnerability' link, per F1. ──────────── */}
      <div id="disclosure" className="scroll-mt-24">
        <h2 className="text-[10px] font-bold tracking-[0.28em] uppercase mb-4 text-accent-green/70">
          Responsible disclosure
        </h2>

        {/* How to report */}
        <div className="rounded-xl border border-white/[0.07] bg-[#111827] p-6 mb-5">
          <div className="flex items-center gap-2 mb-3">
            <Mail className="w-4 h-4 text-accent-green" />
            <h3 className="text-sm font-semibold text-white">How to report a vulnerability</h3>
          </div>
          <p className="text-xs text-gray-400 leading-relaxed mb-3">
            If you discover a security issue in WebHound, please report it privately
            before any public disclosure. Send a clear, reproducible report to:
          </p>
          <a
            href="mailto:security@webhoundsecurity.com"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-accent-green/30 bg-accent-green/[0.07] text-accent-green text-sm font-semibold hover:border-accent-green/50 transition-colors"
          >
            <Mail className="w-3.5 h-3.5" />
            security@webhoundsecurity.com
          </a>
          <p className="text-[11px] text-gray-500 leading-relaxed mt-4">
            Please include: a description of the issue, the affected component or URL,
            step-by-step reproduction, the impact you observed, and (if you have it)
            a proposed remediation. Encrypted submissions welcome — request our PGP
            key in your first message.
          </p>
        </div>

        {/* Response times */}
        <div className="rounded-xl border border-white/[0.07] bg-[#111827] p-6 mb-5">
          <div className="flex items-center gap-2 mb-3">
            <Clock className="w-4 h-4 text-accent-green" />
            <h3 className="text-sm font-semibold text-white">Expected response times</h3>
          </div>
          <p className="text-xs text-gray-400 leading-relaxed mb-4">
            We commit to triage and respond on the following targets. Severity is
            assessed using CVSS 3.1 alongside the operational impact on WebHound or
            our customers' data.
          </p>
          <div className="flex flex-col gap-2.5">
            {RESPONSE_TIMES.map(({ sev, target, color }) => (
              <div
                key={sev}
                className="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-white/[0.05]"
                style={{ background: 'rgba(255,255,255,0.015)' }}
              >
                <span
                  className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded flex-shrink-0"
                  style={{ background: `${color}1a`, color, border: `1px solid ${color}33` }}
                >
                  {sev}
                </span>
                <span className="text-[12px] text-gray-300 leading-snug">{target}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Safe harbor */}
        <div className="rounded-xl border border-white/[0.07] bg-[#111827] p-6 mb-5">
          <div className="flex items-center gap-2 mb-3">
            <ScrollText className="w-4 h-4 text-accent-green" />
            <h3 className="text-sm font-semibold text-white">Safe harbor</h3>
          </div>
          <p className="text-xs text-gray-400 leading-relaxed mb-3">
            We will not pursue or support legal action against you for security
            research conducted in good faith against WebHound, provided you:
          </p>
          <ul className="text-xs text-gray-400 leading-relaxed space-y-1.5 list-disc pl-5">
            <li>Make a good-faith effort to avoid privacy violations, degradation of service, and disruption to other users.</li>
            <li>Only test against your own WebHound account or accounts you are explicitly authorized to test.</li>
            <li>Do not exfiltrate, modify, or destroy data that is not yours.</li>
            <li>Give us a reasonable opportunity to address the issue before any public disclosure.</li>
            <li>Comply with all applicable laws.</li>
          </ul>
          <p className="text-[11px] text-gray-500 leading-relaxed mt-4">
            This safe-harbor commitment does not authorize testing against third-party
            services that WebHound integrates with. Each integrated service has its
            own disclosure policy and authorization rules.
          </p>
        </div>

        {/* Out of scope */}
        <div className="rounded-xl border border-white/[0.05] bg-[rgba(239,68,68,0.04)] p-5">
          <div className="flex items-center gap-2 mb-2">
            <AlertCircle className="w-4 h-4" style={{ color: '#ef4444' }} />
            <h3 className="text-sm font-semibold text-white">Out of scope</h3>
          </div>
          <p className="text-[11.5px] text-gray-400 leading-relaxed">
            Reports about social engineering, physical security, denial-of-service,
            spam, or issues that require an attacker to be in privileged network
            positions are generally out of scope. Reach out anyway if you're not
            sure — we'd rather hear about it.
          </p>
        </div>
      </div>
    </div>
  )
}
