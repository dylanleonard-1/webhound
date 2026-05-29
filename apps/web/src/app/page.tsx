import dynamic from 'next/dynamic'
import { Footer } from '@/components/layout/footer'
import { Hero } from '@/components/sections/hero'
import { PageReveal } from '@/components/effects/page-reveal'

// Below-fold sections: split into separate JS chunks so the initial
// bundle stays lean. Order is the SBO narrative arc:
//   hook (Hero) → see it work (LiveScan) → what we find
//   (ExampleFindings) → where to dig in (ThreeDoors) → why it
//   matters (WhyMatters) → footer.
//
// Slice 2: Testimonials section removed (Q2 approved). Placeholder
// initials-only testimonials on a security product damaged trust
// more than the section earned in conversion. Queued for re-add
// once verified customer quotes with headshots are procured.
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

export default function HomePage() {
  return (
    <>
      <PageReveal />
      <Hero />
      <LiveScan />
      <ExampleFindings />
      <ThreeDoors />
      <WhyMatters />
      <Footer />
    </>
  )
}
