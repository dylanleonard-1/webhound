import { GlowBackground } from '@/components/effects/glow-background'
import { SectionContainer } from '@/components/layout/section-container'
import { AnimatedFadeIn } from '@/components/effects/animated-fade-in'
import { PrimaryButton } from '@/components/ui/primary-button'
import { SecondaryButton } from '@/components/ui/secondary-button'
import { GradientDivider } from '@/components/ui/gradient-divider'
import { InteractiveGlobe } from '@/components/sections/interactive-globe'

export function HeroShell() {
  return (
    <GlowBackground variant="hero" className="min-h-screen">

      <SectionContainer
        size="lg"
        className="pt-36 pb-20 sm:pt-44 sm:pb-28"
        as="div"
      >
        {/* Eyebrow */}
        <AnimatedFadeIn delay={0.1} className="flex justify-center mb-7">
          <div className="inline-flex items-center gap-2.5 px-4 py-2 rounded-full border border-[rgba(139,255,62,0.22)] bg-[rgba(139,255,62,0.05)]">
            <span
              aria-hidden
              className="w-1.5 h-1.5 rounded-full bg-[#8BFF3E] shadow-[0_0_6px_rgba(139,255,62,0.8)]"
              style={{ animation: 'pulse 2s cubic-bezier(0.4,0,0.6,1) infinite' }}
            />
            <span className="text-[11px] font-semibold text-[#8BFF3E] tracking-[0.2em] uppercase">
              Next-Generation Cybersecurity
            </span>
          </div>
        </AnimatedFadeIn>

        {/* Headline */}
        <AnimatedFadeIn delay={0.18} className="text-center mb-7">
          <h1 className="text-[clamp(3rem,8vw,6rem)] font-bold text-white leading-[0.93] tracking-[-0.03em]">
            Defend Your
            <br />
            <span className="text-[#8BFF3E]" style={{ textShadow: '0 0 60px rgba(139,255,62,0.25)' }}>
              Digital
            </span>{' '}
            Perimeter
          </h1>
        </AnimatedFadeIn>

        {/* Subheadline */}
        <AnimatedFadeIn delay={0.28} className="text-center mb-12">
          <p className="text-lg sm:text-xl text-[rgba(255,255,255,0.42)] leading-relaxed max-w-2xl mx-auto">
            Enterprise-grade threat intelligence and continuous security monitoring
            for modern security teams.
          </p>
        </AnimatedFadeIn>

        {/* CTA row */}
        <AnimatedFadeIn delay={0.36} className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-6">
          <PrimaryButton>Get Started Free</PrimaryButton>
          <SecondaryButton>View Live Demo</SecondaryButton>
        </AnimatedFadeIn>

        {/* Trust line */}
        <AnimatedFadeIn delay={0.42} className="flex items-center justify-center gap-6 text-[11px] text-[rgba(255,255,255,0.28)] font-medium tracking-wide mb-24">
          {['SOC 2 Type II', 'ISO 27001', 'Zero Exploitation', 'Passive Scanning'].map((item, i, arr) => (
            <span key={item} className="flex items-center gap-6">
              {item}
              {i < arr.length - 1 && (
                <span aria-hidden className="text-[rgba(139,255,62,0.2)]">·</span>
              )}
            </span>
          ))}
        </AnimatedFadeIn>

        {/* Divider before globe */}
        <GradientDivider glow className="mb-16 opacity-60" />

        {/* Globe placeholder */}
        <AnimatedFadeIn delay={0.52} direction="none" className="flex justify-center">
          <InteractiveGlobe size={560} />
        </AnimatedFadeIn>
      </SectionContainer>
    </GlowBackground>
  )
}
