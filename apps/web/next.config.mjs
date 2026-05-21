/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',

  experimental: {
    // Tree-shake barrel exports — prevents pulling in all icons / all of framer-motion
    optimizePackageImports: ['lucide-react', 'framer-motion'],
  },

  // Compress responses in production
  compress: true,

  // Cache immutable assets for 1 year
  async headers() {
    return [
      {
        source: '/_next/static/:path*',
        headers: [{ key: 'Cache-Control', value: 'public, max-age=31536000, immutable' }],
      },
    ]
  },
}

export default nextConfig
