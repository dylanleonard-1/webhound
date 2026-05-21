'use client'

import { useRef } from 'react'
import Link from 'next/link'
import { motion, useInView } from 'framer-motion'
import { SectionContainer } from '@/components/layout/section-container'
import { SecondaryButton } from '@/components/ui/secondary-button'
import { GradientDivider } from '@/components/ui/gradient-divider'
import { AnimatedFadeIn } from '@/components/effects/animated-fade-in'
import { ThreatDashboard } from './threat-dashboard'

const BULLETS = [
  'Vulnerability correlation against 200+ CVE feeds',
  'AI-ranked findings by exploitability and business impact',
  'Remediation playbooks with code-level fix guidance',
  'Continuous monitoring with real-time anomaly alerts',
]

// ── Background effects ────────────────────────────────────────────────────────

function Particles() {
  return (
    <>
      <style>{`@keyframes floatUpA{0%,100%{transform:translateY(0)}50%{transform:translateY(-22px);opacity:.02}}`}</style>
      <div aria-hidden className="absolute inset-0 overflow-hidden pointer-events-none">
        {Array.from({ length: 8 }, (_, i) => (
          <div
            key={i}
            className="absolute rounded-full bg-[#8BFF3E]"
            style={{
              left: `${11 + i * 11}%`,
              top: `${18 + (i % 4) * 20}%`,
              width: 1 + (i % 2) * 0.8,
              height: 1 + (i % 2) * 0.8,
              opacity: 0.07 + (i % 3) * 0.04,
              animation: `floatUpA ${4 + i * 0.65}s ease-in-out ${i * 0.72}s infinite`,
            }}
          />
        ))}
      </div>
    </>
  )
}

// ── Section ───────────────────────────────────────────────────────────────────

export function Intelligence() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section id="features" className="relative overflow-hidden bg-[#030712] py-28 sm:py-36 section-contain">
      {/* Top divider */}
      <GradientDivider className="absolute top-0 left-0 right-0" glow />

      {/* Animated cyber grid — promoted to GPU layer to avoid triggering section-wide repaints */}
      <div
        aria-hidden
        className="absolute inset-0 pointer-events-none opacity-[0.032] grid-anim-layer"
        style={{
          backgroundImage: `
            linear-gradient(rgba(139,255,62,1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(139,255,62,1) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
          animation: 'gridScroll 24s linear infinite',
        }}
      />

      {/* Scan line */}
      <div aria-hidden className="absolute inset-0 overflow-hidden pointer-events-none">
        <div
          className="absolute left-0 right-0 h-px"
          style={{
            background: 'linear-gradient(90deg, transparent 0%, rgba(139,255,62,0.18) 40%, rgba(139,255,62,0.18) 60%, transparent 100%)',
            animation: 'scanSweep 7s linear infinite',
          }}
        />
      </div>

      {/* Floating particles */}
      <Particles />

      {/* Right glow fog */}
      <div
        aria-hidden
        className="absolute top-1/2 right-[-10%] -translate-y-1/2 w-[700px] h-[700px] rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(139,255,62,0.04) 0%, transparent 65%)', filter: 'blur(40px)' }}
      />

      <SectionContainer size="xl">
        <div
          ref={ref}
          className="grid grid-cols-1 lg:grid-cols-[45fr_55fr] gap-14 xl:gap-20 items-center"
        >
          {/* ── Left ─────────────────────────────────────────────────────── */}
          <div>
            {/* Label */}
            <AnimatedFadeIn delay={0.08}>
              <div className="inline-flex items-center gap-2 mb-7">
                <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
                <span className="text-[10px] font-bold text-[#8BFF3E] tracking-[0.22em] uppercase">
                  Security Posture Analysis
                </span>
                <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
              </div>
            </AnimatedFadeIn>

            {/* Heading */}
            <AnimatedFadeIn delay={0.16}>
              <h2
                className="font-bold leading-[0.93] tracking-[-0.025em] mb-6"
                style={{ fontSize: 'clamp(2.4rem, 4.5vw, 4rem)' }}
              >
                <span className="text-white block">Intelligence That Drives</span>
                <span
                  className="block text-[#8BFF3E]"
                  style={{ textShadow: '0 0 48px rgba(139,255,62,0.28)' }}
                >
                  Stronger Defenses.
                </span>
              </h2>
            </AnimatedFadeIn>

            {/* Description */}
            <AnimatedFadeIn delay={0.24}>
              <p className="text-[rgba(255,255,255,0.44)] text-lg leading-relaxed max-w-[460px] mb-9">
                WebHound runs 42,000+ security checks across your entire attack surface — DNS, SSL,
                web application, APIs, cloud infrastructure, and dependencies — then delivers
                AI-prioritized findings with remediation guidance your team can act on immediately.
              </p>
            </AnimatedFadeIn>

            {/* Feature bullets */}
            <div className="flex flex-col gap-3.5 mb-10">
              {BULLETS.map((bullet, i) => (
                <motion.div
                  key={bullet}
                  className="flex items-center gap-3.5"
                  initial={{ opacity: 0, x: -18 }}
                  animate={inView ? { opacity: 1, x: 0 } : { opacity: 0, x: -18 }}
                  transition={{ delay: 0.32 + i * 0.09, duration: 0.45, ease: [0.25, 0.46, 0.45, 0.94] }}
                >
                  <div
                    className="w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0"
                    style={{
                      background: 'rgba(139,255,62,0.1)',
                      boxShadow: '0 0 8px rgba(139,255,62,0.12)',
                    }}
                  >
                    <div className="w-1.5 h-1.5 rounded-full bg-[#8BFF3E]" />
                  </div>
                  <span className="text-[rgba(255,255,255,0.72)] text-sm font-medium leading-snug">
                    {bullet}
                  </span>
                </motion.div>
              ))}
            </div>

            {/* CTA */}
            <AnimatedFadeIn delay={0.72}>
              <Link href="/dashboard" tabIndex={-1}>
                <SecondaryButton>View Live Demo</SecondaryButton>
              </Link>
            </AnimatedFadeIn>
          </div>

          {/* ── Right ────────────────────────────────────────────────────── */}
          <div className="w-full">
            <ThreatDashboard />
          </div>
        </div>
      </SectionContainer>

      {/* Bottom divider */}
      <GradientDivider className="absolute bottom-0 left-0 right-0" />
    </section>
  )
}
