import type { Metadata, Viewport } from 'next'
import type { ReactNode } from 'react'
import { Inter, JetBrains_Mono } from 'next/font/google'
import { AuthProvider } from '@/contexts/auth'
import { PageTransition } from '@/components/effects/page-transition'
import { HomepageNav } from '@/components/layout/homepage-nav'
import { QueryProvider } from '@/providers/query'
import { Toaster } from 'sonner'
import { Analytics } from '@vercel/analytics/next'
import { JsonLd } from '@/components/seo/json-ld'
import './globals.css'

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
})

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains',
  display: 'swap',
})

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? 'https://webhoundsecurity.com'
const TITLE = 'WebHound — Web Application Security Scanner'
const DESCRIPTION =
  'WebHound scans your entire attack surface — DNS, SSL, APIs, and cloud infrastructure — running security checks and returning a risk-scored report with actionable remediation.'

// Site-wide structured data. Organization + SoftwareApplication, linked via
// @graph so crawlers see them as one connected entity. Plan price range
// mirrors apps/api/billing/plans.py (Free $0 → Managed Review $129).
const STRUCTURED_DATA = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'Organization',
      '@id': `${SITE_URL}/#organization`,
      name: 'WebHound',
      url: SITE_URL,
      logo: `${SITE_URL}/logo.png`,
      description: DESCRIPTION,
      sameAs: ['https://x.com/webhoundsecurity'],
    },
    {
      '@type': 'SoftwareApplication',
      '@id': `${SITE_URL}/#software`,
      name: 'WebHound',
      applicationCategory: 'SecurityApplication',
      operatingSystem: 'Web',
      url: SITE_URL,
      description: DESCRIPTION,
      publisher: { '@id': `${SITE_URL}/#organization` },
      offers: {
        '@type': 'AggregateOffer',
        priceCurrency: 'USD',
        lowPrice: '0',
        highPrice: '129',
        offerCount: 4,
      },
    },
  ],
}

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: TITLE,
    template: '%s | WebHound',
  },
  description: DESCRIPTION,
  keywords: [
    'web application security scanner', 'attack surface management',
    'vulnerability scanner', 'OWASP testing', 'CVE scanning',
    'DNS security', 'SSL audit', 'WebHound',
  ],
  authors: [{ name: 'WebHound' }],
  creator: 'WebHound',
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: SITE_URL,
    siteName: 'WebHound',
    title: TITLE,
    description: DESCRIPTION,
  },
  twitter: {
    card: 'summary_large_image',
    title: TITLE,
    description: DESCRIPTION,
    creator: '@webhoundsecurity',
  },
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true },
  },
  alternates: { canonical: SITE_URL },
}

export const viewport: Viewport = {
  themeColor: '#020617',
  colorScheme: 'dark',
  width: 'device-width',
  initialScale: 1,
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`dark ${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="font-sans bg-[#020617] text-gray-100 min-h-screen">
        <JsonLd data={STRUCTURED_DATA} />
        <QueryProvider>
          <AuthProvider>
            <HomepageNav />
            <PageTransition>{children}</PageTransition>
            <Toaster
              position="bottom-right"
              toastOptions={{
                style: {
                  background: 'rgba(8,12,22,0.97)',
                  border: '1px solid rgba(255,255,255,0.08)',
                  color: '#ffffff',
                  borderRadius: '10px',
                  fontSize: '13px',
                },
              }}
            />
          </AuthProvider>
        </QueryProvider>
        <Analytics />
      </body>
    </html>
  )
}
