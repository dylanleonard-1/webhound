import type { Metadata } from 'next'
import type { LucideIcon } from 'lucide-react'
import Link from 'next/link'
import {
  Shield, ShieldCheck, Lock, Eye, Code2, Globe, Search, Key,
  Layers, Cpu, FileText, Activity,
  AlertTriangle, CheckCircle, ArrowRight,
  GitCompare, Bell, Wrench,
} from 'lucide-react'

export const metadata: Metadata = {
  title: 'Features — WebHound',
  description: 'Passive security scanning, WADE anomaly detection, grouped findings, professional reports, and fix guidance — all in one dashboard.',
}

// ── Data ─────────────────────────────────────────────────────────────────────

interface FeatureCard {
  icon: LucideIcon
  title: string
  desc: string
  detail: string
}

const FEATURE_CARDS: FeatureCard[] = [
  {
    icon: Shield,
    title: 'Passive Website Scanning',
    desc: 'Safe, read-only analysis of your website\'s public surface. No credentials, no changes, no risk.',
    detail: 'Crawls linked pages, resources, and headers without executing JS or making authenticated requests.',
  },
  {
    icon: ShieldCheck,
    title: 'Security Headers & CSP',
    desc: 'Checks every response header that browsers use to protect users from XSS, clickjacking, and data leaks.',
    detail: 'Validates CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, and X-Content-Type-Options.',
  },
  {
    icon: Lock,
    title: 'TLS & DNS Security',
    desc: 'Confirms your site uses strong encryption and your email domain is protected against spoofing attacks.',
    detail: 'Certificate validity, cipher strength, HSTS preload, SPF, DKIM, DMARC, and DNSSEC presence.',
  },
  {
    icon: Eye,
    title: 'Cookie Security',
    desc: 'Audits every cookie your site sets and flags any missing protections that could expose user sessions.',
    detail: 'Checks Secure, HttpOnly, and SameSite attributes. Flags cookies visible to JavaScript that shouldn\'t be.',
  },
  {
    icon: Code2,
    title: 'JavaScript Risk Analysis',
    desc: 'Detects risky JavaScript patterns in inline scripts and loaded files without executing untrusted code.',
    detail: 'Scans for eval(), obfuscated code, document.write, credential exposure, and dangerous DOM APIs.',
  },
  {
    icon: Globe,
    title: 'Third-Party Domain Monitoring',
    desc: 'Maps every external source your website contacts — scripts, fonts, images, iframes, and API calls.',
    detail: 'Categorizes by type (CDN, Analytics, Tracking, Payments) and flags unrecognized domains for review.',
  },
  {
    icon: Search,
    title: 'Sensitive Path Discovery',
    desc: 'Checks whether common sensitive paths are publicly accessible — a frequent oversight on live sites.',
    detail: 'Probes for admin panels, .env files, backup archives, debug endpoints, phpinfo(), and similar.',
  },
  {
    icon: Key,
    title: 'Secret Pattern Detection',
    desc: 'Scans page source and loaded scripts for credential patterns that should never be publicly visible.',
    detail: 'Detects API keys, tokens, AWS credentials, private keys, and common secret formats in HTML and JS.',
  },
  {
    icon: Layers,
    title: 'Grouped Findings',
    desc: 'Findings are organized by engine category, severity, and fix priority — not a flat wall of alerts.',
    detail: 'Expandable rows show affected URLs, description, confidence score, and remediation per finding.',
  },
  {
    icon: Cpu,
    title: 'Engine Diagnostics',
    desc: 'Transparent reporting on exactly which scan engines ran, what they checked, and what they found.',
    detail: 'Per-engine timing, finding counts, and status so you always know the full scope of each scan.',
  },
  {
    icon: FileText,
    title: 'Professional Reports',
    desc: 'Export complete scan results in industry-standard formats, ready for developers, auditors, or clients.',
    detail: 'SARIF (GitHub/Azure DevOps), CSV (spreadsheet/ticketing), and Markdown (wiki/PR-ready).',
  },
  {
    icon: Activity,
    title: 'WADE Behavioral Monitoring',
    desc: 'Detects meaningful website changes between scans — new scripts, domains, forms, and structural shifts.',
    detail: 'Baseline fingerprinting with anomaly scoring. Filters CDN drift and minor changes from real signals.',
  },
]

interface WhyItem {
  problem: string
  impact: string
  solution: string
}

const SAFE_POINTS = [
  { icon: Shield, title: 'Passive scanning only', desc: 'Every analysis is read-only. We fetch publicly available content — exactly as a browser would.' },
  { icon: CheckCircle, title: 'No exploitation', desc: 'We don\'t probe for exploitable vulnerabilities, brute-force credentials, or attempt injection attacks.' },
  { icon: AlertTriangle, title: 'Authorized targets only', desc: 'You confirm you own or are authorized to scan every website before adding it to your account.' },
  { icon: Wrench, title: 'No destructive testing', desc: 'No fuzzing, no load testing, no rate-limit probing. Safe to run continuously against live production.' },
  { icon: GitCompare, title: 'Baseline-safe comparison', desc: 'WADE\'s change detection compares scan metadata — it never re-executes or modifies anything.' },
]

// ── Components ────────────────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2 text-[11px] font-semibold text-accent-green uppercase tracking-widest mb-4">
      <span className="w-4 h-px bg-accent-green/50" />
      {children}
      <span className="w-4 h-px bg-accent-green/50" />
    </span>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function FeaturesPage() {
  return (
    <div className="bg-[#0B0F19]">

      {/* ── Hero ────────────────────────────────────────────────────────────── */}
      <section className="relative pt-10 pb-20 px-5 text-center overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[700px] h-[400px] bg-accent-green/[0.035] rounded-full blur-3xl pointer-events-none" />

        <div className="relative max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/25 bg-accent-green/[0.06] mb-6">
            <Bell className="w-3 h-3 text-accent-green" />
            <span className="text-xs font-semibold text-accent-green tracking-wide">Powered by WADE</span>
          </div>

          <h1 className="text-4xl sm:text-5xl font-semibold text-white tracking-tight leading-[1.1] mb-5">
            Everything your website security team{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-accent-green to-accent-blue">
              would check
            </span>{' '}
            — automated, monitored, and explained.
          </h1>

          <p className="text-base sm:text-lg text-gray-400 leading-relaxed mb-8 max-w-2xl mx-auto">
            WebHound combines passive security scanning, website change monitoring, grouped findings,
            professional reports, and WADE-powered anomaly detection in one dashboard.
          </p>

          <div className="flex flex-col sm:flex-row justify-center gap-3">
            <Link
              href="/dashboard"
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors"
            >
              Start Free Scan
              <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              href="/wade"
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors"
            >
              See WADE Monitoring
            </Link>
          </div>
        </div>
      </section>

      {/* ── Feature grid ────────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <SectionLabel>All Features</SectionLabel>
            <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">
              12 capabilities, one dashboard
            </h2>
            <p className="text-gray-400 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">
              Each engine runs independently and reports findings with full context — no black boxes.
            </p>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {FEATURE_CARDS.map(({ icon: Icon, title, desc, detail }) => (
              <div
                key={title}
                className="rounded-xl border border-white/[0.07] bg-[#111827] p-6 flex flex-col hover:border-accent-green/20 transition-colors group"
              >
                <div className="w-10 h-10 rounded-lg bg-accent-green/10 flex items-center justify-center mb-4 group-hover:bg-accent-green/15 transition-colors flex-shrink-0">
                  <Icon className="w-4.5 h-4.5 text-accent-green" aria-hidden="true" />
                </div>
                <h3 className="text-sm font-semibold text-white mb-2">{title}</h3>
                <p className="text-xs text-gray-400 leading-relaxed mb-3 flex-1">{desc}</p>
                <p className="text-[11px] text-gray-600 leading-relaxed border-t border-white/[0.05] pt-3 font-mono">
                  {detail}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Inline nav nudge ────────────────────────────────────────────────── */}
      <div className="border-t border-white/[0.05] py-8 px-5">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-sm text-gray-500">
            Want to understand exactly how each engine works?
          </p>
          <div className="flex items-center gap-4 flex-shrink-0">
            <Link href="/how-it-works" className="inline-flex items-center gap-1.5 text-sm text-accent-green hover:underline">
              See how it works <ArrowRight className="w-3.5 h-3.5" />
            </Link>
            <Link href="/wade" className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-white transition-colors">
              WADE monitoring <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </div>

      {/* ── Safe monitoring ─────────────────────────────────────────────────── */}
      <section className="py-20 px-5 border-t border-white/[0.05]">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <SectionLabel>Safety First</SectionLabel>
            <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">
              Built for safe, responsible monitoring
            </h2>
            <p className="text-gray-400 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">
              WebHound is designed to be safe to run on any live site, as often as you need.
            </p>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {SAFE_POINTS.map(({ icon: Icon, title, desc }) => (
              <div key={title} className="rounded-xl border border-white/[0.07] bg-[#111827] p-5 flex gap-4">
                <div className="w-9 h-9 rounded-lg bg-accent-green/10 flex items-center justify-center flex-shrink-0">
                  <Icon className="w-4 h-4 text-accent-green" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white mb-1.5">{title}</h3>
                  <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 text-center">
            <Link href="/security" className="text-xs text-accent-green hover:underline inline-flex items-center gap-1">
              Read our security & responsible disclosure policy <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        </div>
      </section>

      {/* ── CTA ──────────────────────────────────────────────────────────────── */}
      <section className="py-24 px-5 border-t border-white/[0.05]">
        <div className="max-w-2xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-green/25 bg-accent-green/[0.06] mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
            <span className="text-xs font-semibold text-accent-green tracking-wide">Free to start</span>
          </div>

          <h2 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight mb-4">
            Start monitoring before attackers notice what changed.
          </h2>
          <p className="text-gray-400 mb-8 text-sm sm:text-base leading-relaxed max-w-lg mx-auto">
            Free scans. No installation. Passive, authorized monitoring from day one.
          </p>

          <div className="flex flex-col sm:flex-row justify-center gap-3">
            <Link
              href="/dashboard"
              className="inline-flex items-center justify-center gap-2 px-8 py-3.5 rounded-lg bg-accent-green text-app-bg font-semibold text-sm hover:bg-accent-green-dim transition-colors"
            >
              Start Free Scan
              <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              href="/pricing"
              className="inline-flex items-center justify-center px-8 py-3.5 rounded-lg border border-white/[0.12] text-gray-300 font-medium text-sm hover:border-white/[0.22] hover:text-white transition-colors"
            >
              View Pricing
            </Link>
          </div>

          <div className="flex flex-wrap justify-center gap-x-6 gap-y-2 mt-8">
            {['Passive scanning', 'No exploitation', 'No installation', 'Authorized targets only'].map(t => (
              <div key={t} className="flex items-center gap-1.5 text-xs text-gray-600">
                <CheckCircle className="w-3 h-3 text-gray-700 flex-shrink-0" />
                {t}
              </div>
            ))}
          </div>
        </div>
      </section>

    </div>
  )
}
