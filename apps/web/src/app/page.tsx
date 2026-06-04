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
// "What Attackers See" replaces LiveScan in the slot directly under the hero.
// (live-scan.tsx is kept in the tree, just no longer rendered here.)
const WhatAttackersSeeSection = dynamic(() =>
  import('@/components/sections/WhatAttackersSeeSection').then(m => ({
    default: m.WhatAttackersSeeSection,
  }))
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
      <WhatAttackersSeeSection />
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
