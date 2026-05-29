import dynamic from 'next/dynamic'
import { Footer } from '@/components/layout/footer'
import { Hero } from '@/components/sections/hero'
import { PageReveal } from '@/components/effects/page-reveal'

// Below-fold sections: split into separate JS chunks so the initial
// bundle stays lean.
//
// Slice 6 narrative order (Cynet-density rebuild, all-dark):
//   Hero               — hook + primary CTA
//   LiveScan           — see it work (live SBO terminal)
//   ExampleFindings    — what a finding looks like
//   WebHoundAdvantage  — four pillars: what makes us different
//   PlatformStack      — five-feature platform breakdown
//   SolutionsGrid      — what we check (6 surfaces)
//   MetricsBanner      — verifiable numbers strip
//   ComplianceStrip    — frameworks we map findings to
//   ThreeDoors         — pick the part you're curious about
//   WhyMatters         — why this matters (breach stake)
//   ClosingCTA         — final ask
//   Footer
//
// Slice 2: Testimonials removed; awaiting verified quotes.
// Slice 6: Industry-recognition + blog placeholder omitted per
//   user (silence > fake validation).
const LiveScan = dynamic(() =>
  import('@/components/sections/live-scan').then(m => ({ default: m.LiveScan }))
)
const ExampleFindings = dynamic(() =>
  import('@/components/sections/example-findings').then(m => ({ default: m.ExampleFindings }))
)
const WebHoundAdvantage = dynamic(() =>
  import('@/components/sections/webhound-advantage').then(m => ({ default: m.WebHoundAdvantage }))
)
const PlatformStack = dynamic(() =>
  import('@/components/sections/platform-stack').then(m => ({ default: m.PlatformStack }))
)
const SolutionsGrid = dynamic(() =>
  import('@/components/sections/solutions-grid').then(m => ({ default: m.SolutionsGrid }))
)
const MetricsBanner = dynamic(() =>
  import('@/components/sections/metrics-banner').then(m => ({ default: m.MetricsBanner }))
)
const ComplianceStrip = dynamic(() =>
  import('@/components/sections/compliance-strip').then(m => ({ default: m.ComplianceStrip }))
)
const ThreeDoors = dynamic(() =>
  import('@/components/sections/three-doors').then(m => ({ default: m.ThreeDoors }))
)
const WhyMatters = dynamic(() =>
  import('@/components/sections/why-matters').then(m => ({ default: m.WhyMatters }))
)
const ClosingCTA = dynamic(() =>
  import('@/components/sections/closing-cta').then(m => ({ default: m.ClosingCTA }))
)

export default function HomePage() {
  return (
    <>
      <PageReveal />
      <Hero />
      <LiveScan />
      <ExampleFindings />
      <WebHoundAdvantage />
      <PlatformStack />
      <SolutionsGrid />
      <MetricsBanner />
      <ComplianceStrip />
      <ThreeDoors />
      <WhyMatters />
      <ClosingCTA />
      <Footer />
    </>
  )
}
