import dynamic from 'next/dynamic'
import { Footer } from '@/components/layout/footer'
import { Hero } from '@/components/sections/hero'
import { PageReveal } from '@/components/effects/page-reveal'

// Below-fold sections: split into separate JS chunks so the initial bundle stays lean.
// Order is the narrative: hook → see it work → what we find → where to learn more →
// why it matters → social proof.
const LiveScan = dynamic(() =>
  import('@/components/sections/live-scan').then(m => ({ default: m.LiveScan }))
)
const ExampleFindings = dynamic(() =>
  import('@/components/sections/example-findings').then(m => ({ default: m.ExampleFindings }))
)
const ThreeDoors = dynamic(() =>
  import('@/components/sections/three-doors').then(m => ({ default: m.ThreeDoors }))
)
const WhyMatters = dynamic(() =>
  import('@/components/sections/why-matters').then(m => ({ default: m.WhyMatters }))
)
const Testimonials = dynamic(() =>
  import('@/components/sections/testimonials').then(m => ({ default: m.Testimonials }))
)

export default function HomePage() {
  return (
    <>
      <PageReveal />
      <Hero />
      <LiveScan />
      <ExampleFindings />
      <ThreeDoors />
      <WhyMatters />
      <Testimonials />
      <Footer />
    </>
  )
}
