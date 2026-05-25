import type { MetadataRoute } from 'next'

// Same base the layout uses for canonical/OG, so robots + sitemap stay
// consistent with the canonical domain.
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? 'https://webhoundsecurity.com'

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: '*',
      allow: '/',
      // Keep the app + auth surfaces out of the index — they're private,
      // gated, or have no standalone search value.
      disallow: [
        '/dashboard',
        '/login',
        '/register',
        '/forgot-password',
        '/reset-password',
        '/verify-email',
        '/callback',
        '/auth',
        '/agreement',
        '/api',
      ],
    },
    sitemap: `${SITE_URL}/sitemap.xml`,
    host: SITE_URL,
  }
}
