import type { Metadata } from 'next'
import { Shield, Lock, Eye, Server } from 'lucide-react'

export const metadata: Metadata = {
  title: 'Security — WebHound',
  description: 'How WebHound keeps your data safe: passive scanning, no credential storage, responsible disclosure.',
}

const PRINCIPLES = [
  {
    icon: Eye,
    title: 'Passive scanning only',
    desc: 'WebHound never modifies your site, exploits vulnerabilities, or makes authenticated requests. Every scan is read-only and safe to run against production.',
  },
  {
    icon: Lock,
    title: 'No credential storage',
    desc: 'We never store passwords, API keys, or session tokens. Scans are performed against the public-facing URL only.',
  },
  {
    icon: Shield,
    title: 'Authorized targets only',
    desc: 'By using WebHound you confirm you own or are authorized to scan the target URL. Scanning unauthorized targets is a violation of our terms and potentially illegal.',
  },
  {
    icon: Server,
    title: 'Data handling',
    desc: 'Scan results are stored securely and accessible only to your account. We do not sell or share scan data with third parties.',
  },
]

export default function SecurityPage() {
  return (
    <div className="max-w-4xl mx-auto px-5 py-20">
      <div className="text-center mb-14">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/25 bg-accent-green/[0.06] mb-5">
          <Shield className="w-3.5 h-3.5 text-accent-green" />
          <span className="text-xs font-medium text-accent-green tracking-wide">Security & Trust</span>
        </div>
        <h1 className="text-4xl font-semibold text-white mb-4 tracking-tight">
          Built with security in mind
        </h1>
        <p className="text-gray-400 max-w-lg mx-auto">
          WebHound is a passive, authorized security monitoring tool. Here's how we operate safely
          and responsibly.
        </p>
      </div>

      <div className="grid sm:grid-cols-2 gap-5 mb-10">
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

      <div className="rounded-xl border border-white/[0.06] bg-[#111827] p-6">
        <h2 className="text-sm font-semibold text-white mb-2">Responsible Disclosure</h2>
        <p className="text-xs text-gray-500 leading-relaxed">
          If you discover a security vulnerability in WebHound, please report it responsibly.
          Do not publicly disclose issues before we have had a chance to address them.
          Contact us at{' '}
          <a href="mailto:security@webhound.io" className="text-accent-green hover:underline">
            security@webhound.io
          </a>
          .
        </p>
      </div>
    </div>
  )
}
