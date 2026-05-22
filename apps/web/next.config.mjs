/** @type {import('next').NextConfig} */
const isProd = process.env.NODE_ENV === 'production'
const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'https://api.webhoundsecurity.com'

const nextConfig = {
  experimental: {
    optimizePackageImports: ['lucide-react', 'framer-motion'],
  },

  compress: true,

  async headers() {
    return [
      // Immutable static assets
      {
        source: '/_next/static/:path*',
        headers: [{ key: 'Cache-Control', value: 'public, max-age=31536000, immutable' }],
      },
      // Security headers for all routes
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Content-Type-Options',    value: 'nosniff' },
          { key: 'X-Frame-Options',           value: 'DENY' },
          { key: 'X-XSS-Protection',          value: '1; mode=block' },
          { key: 'Referrer-Policy',           value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy',        value: 'camera=(), microphone=(), geolocation=()' },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload',
          },
          // Permissive CSP — tighten per-route in production as needed
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
              "font-src 'self' https://fonts.gstatic.com",
              "img-src 'self' data: blob: https:",
              `connect-src 'self' ${apiUrl} ${apiUrl.replace('https://', 'wss://').replace('http://', 'ws://')}${isProd ? '' : ' http://localhost:8000 ws://localhost:8000'}`,
              "frame-ancestors 'none'",
            ].join('; '),
          },
        ],
      },
    ]
  },

  async redirects() {
    return [
      // Redirect bare API calls from old domain patterns (defensive)
      { source: '/api/:path*', destination: '/404', permanent: false },
    ]
  },
}

export default nextConfig
