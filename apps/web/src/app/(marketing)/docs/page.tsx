import type { Metadata } from 'next'
import { BookOpen, Terminal, Zap, Shield } from 'lucide-react'
import Link from 'next/link'

export const metadata: Metadata = {
  title: 'Docs — WebHound',
  description: 'Documentation for WebHound: API reference, integration guides, and scanner configuration.',
}

const SECTIONS = [
  {
    icon: Zap,
    title: 'Getting Started',
    desc: 'Add your first website, run your first scan, and understand the results in under 5 minutes.',
    href: '#',
  },
  {
    icon: Terminal,
    title: 'API Reference',
    desc: 'Full REST API documentation. Authenticate, trigger scans programmatically, and fetch results.',
    href: '#',
  },
  {
    icon: Shield,
    title: 'Scanner Profiles',
    desc: 'Understand the difference between Standard and Deep scan profiles and what each checks.',
    href: '#',
  },
  {
    icon: BookOpen,
    title: 'WADE Guide',
    desc: 'How WADE behavioral baselines work, what triggers an anomaly, and how to tune alerts.',
    href: '#',
  },
]

export default function DocsPage() {
  return (
    <div className="max-w-4xl mx-auto px-5 py-20">
      <div className="text-center mb-14">
        <h1 className="text-4xl font-semibold text-white mb-4 tracking-tight">
          Documentation
        </h1>
        <p className="text-gray-400 max-w-md mx-auto">
          Everything you need to set up WebHound, run scans, and integrate results into your workflow.
        </p>
      </div>

      <div className="grid sm:grid-cols-2 gap-5 mb-14">
        {SECTIONS.map(({ icon: Icon, title, desc, href }) => (
          <Link
            key={title}
            href={href}
            className="rounded-xl border border-white/[0.07] bg-[#111827] p-6 hover:border-white/[0.14] transition-colors group"
          >
            <div className="w-9 h-9 rounded-lg bg-accent-green/10 flex items-center justify-center mb-4">
              <Icon className="w-4.5 h-4.5 text-accent-green" />
            </div>
            <h3 className="text-sm font-semibold text-white mb-2 group-hover:text-accent-green transition-colors">{title}</h3>
            <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
          </Link>
        ))}
      </div>

      <div className="rounded-xl border border-white/[0.06] bg-[#111827] p-6 text-center">
        <p className="text-sm text-gray-400 mb-1">Full documentation is coming soon.</p>
        <p className="text-xs text-gray-600">
          In the meantime,{' '}
          <Link href="/register" className="text-accent-green hover:underline">
            sign up
          </Link>{' '}
          and explore from the dashboard.
        </p>
      </div>
    </div>
  )
}
