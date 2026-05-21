import Link from 'next/link'
import { Logo } from './logo'

const FOOTER_LINKS = {
  Product: [
    { label: 'Features', href: '/features' },
    { label: 'Scanner', href: '/scanner' },
    { label: 'WADE Monitoring', href: '/wade' },
    { label: 'Reports', href: '/reports' },
    { label: 'Pricing', href: '/pricing' },
  ],
  Developers: [
    { label: 'Documentation', href: '/docs'     },
    { label: 'Security',      href: '/security' },
  ],
  Legal: [
    { label: 'Privacy Policy',   href: '/privacy' },
    { label: 'Terms of Service', href: '/terms'   },
  ],
  Platform: [
    { label: 'Dashboard', href: '/dashboard' },
    { label: 'Sign In', href: '/login' },
    { label: 'Register', href: '/register' },
  ],
}

export function PublicFooter() {
  return (
    <footer className="border-t border-white/[0.06] bg-[#080C14]">
      <div className="max-w-6xl mx-auto px-5 py-12">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-10">
          {/* Brand column */}
          <div className="col-span-2 md:col-span-1">
            <Logo size="sm" className="mb-3" />
            <p className="text-xs text-gray-500 leading-relaxed max-w-[200px]">
              Passive, safe, authorized website security monitoring. Powered by WADE.
            </p>
          </div>

          {/* Link columns */}
          {Object.entries(FOOTER_LINKS).map(([group, links]) => (
            <div key={group}>
              <p className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-3">
                {group}
              </p>
              <ul className="space-y-2">
                {links.map(link => (
                  <li key={link.href}>
                    <Link
                      href={link.href}
                      className="text-sm text-gray-500 hover:text-gray-300 transition-colors"
                    >
                      {link.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Cert badge strip */}
        <div className="flex flex-wrap justify-center gap-2.5 mb-6">
          {[
            { label: 'SOC 2 Aligned',   color: '#4F9CF9' },
            { label: 'GDPR Safe',       color: '#8BFF3E' },
            { label: 'OWASP Coverage',  color: '#a78bfa' },
            { label: 'Passive Only',    color: '#22d3ee' },
          ].map(({ label, color }) => (
            <span
              key={label}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[10px] font-semibold tracking-wide"
              style={{
                background: `${color}0d`,
                border: `1px solid ${color}20`,
                color: `${color}b3`,
              }}
            >
              {label}
            </span>
          ))}
        </div>

        {/* Bottom bar */}
        <div className="border-t border-white/[0.05] pt-6 flex flex-col sm:flex-row items-center justify-between gap-3">
          <p className="text-xs text-gray-600">
            © {new Date().getFullYear()} WebHound. All rights reserved.
          </p>
          <p className="text-xs text-gray-600 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-green inline-block" />
            Passive scanning only · No exploitation · Authorized targets only
          </p>
        </div>
      </div>
    </footer>
  )
}
