'use client'

import Link from 'next/link'
import { Shield } from 'lucide-react'

const COLS = [
  {
    heading: 'Product',
    links: [
      { label: 'Features',     href: '/features'     },
      { label: 'Scanner',      href: '/scanner'      },
      { label: 'Reports',      href: '/reports'      },
      { label: 'Monitoring',   href: '/monitoring'   },
      { label: 'Pricing',      href: '/pricing'      },
    ],
  },
  {
    heading: 'Resources',
    links: [
      { label: 'How It Works', href: '/how-it-works' },
      { label: 'Documentation',href: '/docs'         },
      { label: 'Dashboard',    href: '/dashboard'    },
      { label: 'Security',     href: '/security'     },
    ],
  },
  {
    heading: 'Company',
    links: [
      { label: 'Privacy Policy',   href: '/privacy'  },
      { label: 'Terms of Service', href: '/terms'    },
      { label: 'Security',         href: '/security' },
      { label: 'Contact',          href: 'mailto:hello@webhoundsecurity.com' },
    ],
  },
]

export function Footer() {
  return (
    <footer style={{ background: '#020617', borderTop: '1px solid rgba(139,255,62,0.06)' }}>
      <div className="max-w-[1280px] mx-auto px-6 sm:px-10 xl:px-16 py-16 sm:py-20">

        {/* Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-10 mb-14">

          {/* Brand */}
          <div className="col-span-2 sm:col-span-1">
            <Link href="/" className="flex items-center gap-2.5 mb-4 group w-fit">
              <div
                className="w-[30px] h-[30px] rounded-[9px] flex items-center justify-center flex-shrink-0 transition-all duration-300 group-hover:shadow-[0_0_18px_rgba(139,255,62,0.5)]"
                style={{ background: '#8BFF3E', boxShadow: '0 0 12px rgba(139,255,62,0.28)' }}
              >
                <Shield className="w-[15px] h-[15px] text-[#020617]" strokeWidth={2.5} />
              </div>
              <span className="text-white font-bold text-sm tracking-[0.14em] uppercase">WebHound</span>
            </Link>
            <p className="text-[13px] leading-relaxed max-w-[200px]" style={{ color: 'rgba(255,255,255,0.32)' }}>
              AI-powered attack surface intelligence. Find vulnerabilities before attackers do.
            </p>
            <div className="mt-5">
              <span
                className="text-[10px] font-bold tracking-[0.15em] uppercase px-2.5 py-1 rounded-full"
                style={{
                  background: 'rgba(139,255,62,0.07)',
                  border: '1px solid rgba(139,255,62,0.18)',
                  color: 'rgba(139,255,62,0.7)',
                }}
              >
                webhoundsecurity.com
              </span>
            </div>
            <div className="mt-5">
              <Link
                href="/dashboard"
                className="inline-flex items-center px-4 py-2 rounded-full text-[12px] font-bold transition-all duration-300 hover:shadow-[0_0_20px_rgba(139,255,62,0.4)]"
                style={{ background: '#8BFF3E', color: '#020617', boxShadow: '0 0 12px rgba(139,255,62,0.2)' }}
              >
                Start Free Scan
              </Link>
            </div>
          </div>

          {/* Link columns */}
          {COLS.map(col => (
            <div key={col.heading}>
              <h3 className="text-[10px] font-black tracking-[0.18em] uppercase mb-4" style={{ color: 'rgba(255,255,255,0.3)' }}>
                {col.heading}
              </h3>
              <ul className="flex flex-col gap-2.5">
                {col.links.map(link => (
                  <li key={link.label}>
                    <Link
                      href={link.href}
                      className="text-[13px] transition-colors duration-200"
                      style={{ color: 'rgba(255,255,255,0.4)' }}
                      onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.85)')}
                      onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.4)')}
                    >
                      {link.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom bar */}
        <div
          className="pt-7 flex flex-col sm:flex-row items-center justify-between gap-4"
          style={{ borderTop: '1px solid rgba(139,255,62,0.05)' }}
        >
          <span className="text-[12px]" style={{ color: 'rgba(255,255,255,0.18)' }}>
            © {new Date().getFullYear()} WebHound Security. All rights reserved.
          </span>
          <div className="flex items-center gap-6">
            {[
              { label: 'Security', href: '/security' },
              { label: 'Privacy', href: '/privacy' },
              { label: 'Terms', href: '/terms' },
            ].map(({ label, href }) => (
              <Link
                key={label}
                href={href}
                className="text-[12px] transition-colors duration-200"
                style={{ color: 'rgba(255,255,255,0.18)' }}
                onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.5)')}
                onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.18)')}
              >
                {label}
              </Link>
            ))}
          </div>
        </div>

      </div>
    </footer>
  )
}
