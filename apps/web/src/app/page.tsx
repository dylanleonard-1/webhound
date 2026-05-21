import dynamic from 'next/dynamic'
import { Footer } from '@/components/layout/footer'
import { Hero } from '@/components/sections/hero'
import { PageReveal } from '@/components/effects/page-reveal'

// Below-fold sections: split into separate JS chunks so the initial bundle stays lean.
// HTML is still SSR'd for SEO; only the hydration JS loads lazily.
const TrustBar = dynamic(() =>
  import('@/components/sections/trust-bar').then(m => ({ default: m.TrustBar }))
)
const Intelligence = dynamic(() =>
  import('@/components/sections/intelligence').then(m => ({ default: m.Intelligence }))
)
const Coverage = dynamic(() =>
  import('@/components/sections/coverage').then(m => ({ default: m.Coverage }))
)
const Engine = dynamic(() =>
  import('@/components/sections/engine').then(m => ({ default: m.Engine }))
)
const Deliverables = dynamic(() =>
  import('@/components/sections/deliverables').then(m => ({ default: m.Deliverables }))
)
const Testimonials = dynamic(() =>
  import('@/components/sections/testimonials').then(m => ({ default: m.Testimonials }))
)
const LiveScan = dynamic(() =>
  import('@/components/sections/live-scan').then(m => ({ default: m.LiveScan }))
)

export default function HomePage() {
  return (
    <>
      <PageReveal />
      <Hero />
      <TrustBar />
      <Intelligence />
      <Coverage />
      <Engine />
      <Deliverables />
      <Testimonials />
      <LiveScan />
      <Footer />
    </>
  )
}
