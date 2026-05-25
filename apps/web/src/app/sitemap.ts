import type { MetadataRoute } from 'next'

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? 'https://webhoundsecurity.com'

// Public, indexable routes. Dashboard/auth pages are intentionally excluded
// (see robots.ts). Ordered roughly by importance; priorities are hints only.
const ROUTES: { path: string; priority: number; changeFrequency: MetadataRoute.Sitemap[number]['changeFrequency'] }[] = [
  { path: '',                priority: 1.0, changeFrequency: 'weekly' },
  { path: '/features',       priority: 0.9, changeFrequency: 'monthly' },
  { path: '/how-it-works',   priority: 0.9, changeFrequency: 'monthly' },
  { path: '/pricing',        priority: 0.9, changeFrequency: 'weekly' },
  { path: '/scanner',        priority: 0.8, changeFrequency: 'monthly' },
  { path: '/monitoring',     priority: 0.8, changeFrequency: 'monthly' },
  { path: '/wade',           priority: 0.7, changeFrequency: 'monthly' },
  { path: '/reports',        priority: 0.7, changeFrequency: 'monthly' },
  { path: '/security',       priority: 0.7, changeFrequency: 'monthly' },
  { path: '/docs',           priority: 0.6, changeFrequency: 'monthly' },
  { path: '/contact',        priority: 0.6, changeFrequency: 'monthly' },
  { path: '/terms',          priority: 0.3, changeFrequency: 'yearly' },
  { path: '/privacy',        priority: 0.3, changeFrequency: 'yearly' },
  { path: '/acceptable-use', priority: 0.3, changeFrequency: 'yearly' },
  { path: '/data-retention', priority: 0.3, changeFrequency: 'yearly' },
  { path: '/disclaimer',     priority: 0.3, changeFrequency: 'yearly' },
]

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date()
  return ROUTES.map(({ path, priority, changeFrequency }) => ({
    url: `${SITE_URL}${path}`,
    lastModified: now,
    changeFrequency,
    priority,
  }))
}
