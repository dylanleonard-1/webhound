'use client'

import { useRef, useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import { ChevronLeft, ChevronRight, RotateCcw } from 'lucide-react'
import { SectionContainer } from '@/components/layout/section-container'
import { PrimaryButton } from '@/components/ui/primary-button'
import { SecondaryButton } from '@/components/ui/secondary-button'
import { GradientDivider } from '@/components/ui/gradient-divider'
import { EngineStack, LAYER_THEMES } from './engine-stack'
import { EnginePanel } from './engine-panel'

// ── Workflow data ─────────────────────────────────────────────────────────────

const WORKFLOW = [
  { label: 'Discover Infrastructure',   desc: 'Map every asset, subdomain, and open port.' },
  { label: 'Analyze Technologies',      desc: 'Fingerprint frameworks and dependency versions.' },
  { label: 'Scan for Vulnerabilities',  desc: 'CVE correlation and OWASP Top 10 testing.' },
  { label: 'Correlate Intelligence',    desc: 'Cross-reference global threat feeds and breach data.' },
  { label: 'Generate Insights',         desc: 'Severity-ranked findings with remediation paths.' },
]

const TOTAL_LAYERS  = 8
const AUTO_INTERVAL = 1800

// ── Background streaks ────────────────────────────────────────────────────────

function ScanStreaks() {
  return (
    <>
      <style>{`@keyframes streakPulse{0%,100%{opacity:.28}50%{opacity:.65}}`}</style>
      <div aria-hidden className="absolute inset-0 overflow-hidden pointer-events-none">
        {([15, 35, 55, 75, 90] as const).map((left, i) => (
          <div
            key={i}
            className="absolute top-0 bottom-0 w-px"
            style={{
              left: `${left}%`,
              background: 'linear-gradient(to bottom, transparent 0%, rgba(139,255,62,0.06) 40%, rgba(139,255,62,0.06) 60%, transparent 100%)',
              animation: `streakPulse ${3 + i * 0.7}s ease-in-out ${i * 0.5}s infinite`,
            }}
          />
        ))}
      </div>
    </>
  )
}

// ── Section ───────────────────────────────────────────────────────────────────

export function Engine() {
  const sectionRef   = useRef<HTMLDivElement>(null)
  const intervalRef  = useRef<ReturnType<typeof setInterval> | null>(null)
  const touchXRef    = useRef<number | null>(null)

  const [activeLayer, setActiveLayer] = useState(0)
  const [autoPlay,    setAutoPlay]    = useState(true)
  const [isVisible,   setIsVisible]   = useState(false)
  const [isHovered,   setIsHovered]   = useState(false)

  const theme = LAYER_THEMES[activeLayer]

  // ── IntersectionObserver ──────────────────────────────────────────────────
  useEffect(() => {
    const el = sectionRef.current; if (!el) return
    const obs = new IntersectionObserver(
      ([entry]) => setIsVisible(entry.isIntersecting),
      { threshold: 0.25 },
    )
    obs.observe(el)
    return () => obs.disconnect()
  }, [])

  // ── Auto-advance interval ─────────────────────────────────────────────────
  useEffect(() => {
    if (!isVisible || isHovered || !autoPlay) {
      if (intervalRef.current) { clearInterval(intervalRef.current); intervalRef.current = null }
      return
    }
    intervalRef.current = setInterval(() => {
      setActiveLayer(prev => {
        if (prev >= TOTAL_LAYERS - 1) {
          if (intervalRef.current) { clearInterval(intervalRef.current); intervalRef.current = null }
          setAutoPlay(false)
          return prev
        }
        return prev + 1
      })
    }, AUTO_INTERVAL)
    return () => {
      if (intervalRef.current) { clearInterval(intervalRef.current); intervalRef.current = null }
    }
  }, [isVisible, isHovered, autoPlay])

  // ── Keyboard support ──────────────────────────────────────────────────────
  const stopAuto = useCallback(() => setAutoPlay(false), [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        stopAuto(); setActiveLayer(p => Math.min(TOTAL_LAYERS - 1, p + 1))
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        stopAuto(); setActiveLayer(p => Math.max(0, p - 1))
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [stopAuto])

  // ── Controls ──────────────────────────────────────────────────────────────
  const goNext  = () => { stopAuto(); setActiveLayer(p => Math.min(TOTAL_LAYERS - 1, p + 1)) }
  const goPrev  = () => { stopAuto(); setActiveLayer(p => Math.max(0, p - 1)) }
  const skip    = () => { stopAuto(); setActiveLayer(TOTAL_LAYERS - 1) }
  const replay  = () => { setActiveLayer(0); setAutoPlay(true) }

  const goToLayer = (i: number) => { stopAuto(); setActiveLayer(i) }

  // ── Touch / swipe ─────────────────────────────────────────────────────────
  const onTouchStart = (e: React.TouchEvent) => { touchXRef.current = e.touches[0].clientX }
  const onTouchEnd   = (e: React.TouchEvent) => {
    if (touchXRef.current === null) return
    const dx = e.changedTouches[0].clientX - touchXRef.current
    if (dx < -40) goNext()
    else if (dx > 40) goPrev()
    touchXRef.current = null
  }

  const activeStep = Math.min(4, Math.floor(activeLayer * 5 / 8))
  const isComplete = activeLayer === TOTAL_LAYERS - 1

  return (
    <section
      id="how-it-works"
      ref={sectionRef}
      className="relative overflow-hidden"
      style={{ zIndex: 1 }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onTouchStart={onTouchStart}
      onTouchEnd={onTouchEnd}
    >
      {/* Top divider */}
      <GradientDivider className="absolute top-0 left-0 right-0 z-10" glow />

      {/* Animated cyber grid */}
      <div
        aria-hidden
        className="absolute inset-0 pointer-events-none opacity-[0.025]"
        style={{
          backgroundImage: `
            linear-gradient(rgba(139,255,62,1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(139,255,62,1) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
          animation: 'gridScroll 28s linear infinite',
        }}
      />

      {/* Vertical scan streaks */}
      <ScanStreaks />

      {/* Center radial glow — color shifts with layer */}
      <div
        aria-hidden
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none"
        style={{
          width: 500,
          height: 500,
          background: `radial-gradient(circle, ${theme.glow.replace('0.35', '0.025')} 0%, transparent 60%)`,
          filter: 'blur(48px)',
          animation: 'breatheGlow 6s ease-in-out infinite',
          transition: 'background 0.6s ease',
        }}
      />

      {/* Bottom divider */}
      <GradientDivider className="absolute bottom-0 left-0 right-0 z-10" />

      <SectionContainer size="xl" className="relative z-10 py-20 lg:py-28">

        {/* ── Mobile header (hidden on desktop) ──────────────────────────── */}
        <div className="lg:hidden text-center mb-8 px-2">
          <div className="inline-flex items-center gap-2 mb-3">
            <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
            <span className="text-[9px] font-bold text-[#8BFF3E] tracking-[0.22em] uppercase">
              8-Layer Security Engine
            </span>
            <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
          </div>
          <h2 className="text-white font-bold text-2xl sm:text-3xl leading-tight mb-2">
            One Scanner. Eight Layers.<br />
            <span style={{ color: theme.color, transition: 'color 0.5s ease' }}>Complete Protection.</span>
          </h2>
        </div>

        {/* ── Main grid ──────────────────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_auto] gap-x-10 xl:gap-x-14 gap-y-10 items-center">

          {/* ── Left column — workflow ──────────────────────────────────── */}
          <div className="hidden lg:flex flex-col">
            {/* Section label */}
            <div className="inline-flex items-center gap-2 mb-7">
              <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
              <span className="text-[10px] font-bold text-[#8BFF3E] tracking-[0.22em] uppercase">
                The 8-Layer Security Engine
              </span>
              <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
            </div>

            {/* Heading */}
            <h2
              className="font-bold leading-[0.92] tracking-[-0.025em] mb-8"
              style={{ fontSize: 'clamp(1.9rem, 2.8vw, 2.8rem)' }}
            >
              <span className="text-white block">How WebHound</span>
              <span
                className="block"
                style={{ color: theme.color, textShadow: `0 0 40px ${theme.glow}`, transition: 'color 0.5s, text-shadow 0.5s' }}
              >
                Protects You.
              </span>
            </h2>

            {/* Workflow steps */}
            <div className="flex flex-col mb-9">
              {WORKFLOW.map((step, i) => {
                const isDone = activeStep > i
                const isCurr = activeStep === i
                return (
                  <div key={i} className="flex gap-4">
                    <div className="flex flex-col items-center flex-shrink-0">
                      <div
                        className="w-5 h-5 rounded-full border-2 flex items-center justify-center transition-all duration-500 flex-shrink-0"
                        style={{
                          borderColor: isCurr ? theme.color : isDone ? 'rgba(139,255,62,0.45)' : 'rgba(255,255,255,0.1)',
                          background:  isCurr ? `${theme.color}24` : isDone ? 'rgba(139,255,62,0.06)' : 'transparent',
                          boxShadow:   isCurr ? `0 0 10px ${theme.glow}` : 'none',
                        }}
                      >
                        {isDone ? (
                          <span className="text-[8px] font-black text-[rgba(139,255,62,0.7)]">✓</span>
                        ) : isCurr ? (
                          <span
                            className="w-1.5 h-1.5 rounded-full"
                            style={{ background: theme.color, animation: 'pulse 1.2s ease-in-out infinite', boxShadow: `0 0 5px ${theme.color}` }}
                          />
                        ) : (
                          <span className="text-[8px] font-bold text-[rgba(255,255,255,0.18)]">
                            {String(i + 1).padStart(2, '0')}
                          </span>
                        )}
                      </div>
                      {i < WORKFLOW.length - 1 && (
                        <div
                          className="w-px flex-1 min-h-[20px] transition-colors duration-700"
                          style={{ background: isDone ? 'rgba(139,255,62,0.22)' : 'rgba(255,255,255,0.06)' }}
                        />
                      )}
                    </div>
                    <div className="pb-5 min-w-0">
                      <span
                        className="text-[13px] font-semibold block transition-colors duration-500"
                        style={{
                          color: isCurr ? '#fff' : isDone ? 'rgba(255,255,255,0.5)' : 'rgba(255,255,255,0.22)',
                        }}
                      >
                        {step.label}
                      </span>
                      {(isCurr || isDone) && (
                        <p className="text-[11px] text-[rgba(255,255,255,0.36)] leading-relaxed mt-0.5 max-w-[280px]">
                          {step.desc}
                        </p>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>

            {/* Layer counter */}
            <div className="flex items-center gap-3 mb-6">
              <span className="text-[9px] font-mono tracking-wider" style={{ color: theme.color + '72' }}>
                Layer {activeLayer + 1} / 8 {autoPlay && !isHovered ? '· auto' : isHovered ? '· paused' : ''}
              </span>
              <div className="flex gap-1">
                {Array.from({ length: 8 }).map((_, i) => (
                  <div
                    key={i}
                    className="h-0.5 rounded-full"
                    style={{
                      width: i === activeLayer ? 16 : 4,
                      background: i <= activeLayer ? theme.color : 'rgba(139,255,62,0.15)',
                      transition: 'width 0.35s ease, background 0.35s ease',
                    }}
                  />
                ))}
              </div>
            </div>

            {/* CTAs */}
            <div className="flex items-center gap-3">
              <Link href="/dashboard" tabIndex={-1}>
                <PrimaryButton>Start Scanning</PrimaryButton>
              </Link>
              <Link href="/dashboard" tabIndex={-1}>
                <SecondaryButton>View Results</SecondaryButton>
              </Link>
            </div>
          </div>

          {/* ── Mobile: standalone engine stack ─────────────────────────── */}
          <div className="flex lg:hidden items-center justify-center">
            <EngineStack activeLayer={activeLayer} />
          </div>

          {/* ── Desktop: unified scanner engine container ────────────────── */}
          <div
            className="hidden lg:flex relative rounded-[18px] overflow-hidden"
            style={{
              background: 'rgba(5,8,16,0.97)',
              border: '1px solid rgba(255,255,255,0.10)',
              boxShadow: '0 0 0 1px rgba(255,255,255,0.04), 0 8px 48px rgba(0,0,0,0.6)',
            }}
          >
            {/* Ambient internal lighting — color shifts with active layer */}
            <div
              aria-hidden
              className="absolute inset-0 pointer-events-none"
              style={{
                background: `radial-gradient(ellipse 70% 40% at 50% 0%, ${theme.color}09 0%, transparent 70%)`,
                transition: 'background 0.6s ease',
              }}
            />
            {/* Top edge highlight */}
            <div
              aria-hidden
              className="absolute inset-x-0 top-0 h-px pointer-events-none"
              style={{
                background: `linear-gradient(to right, transparent, ${theme.color}35, transparent)`,
                transition: 'background 0.6s ease',
              }}
            />
            {/* Engine stack */}
            <div className="flex items-center justify-center px-6 py-8 relative z-10">
              <EngineStack activeLayer={activeLayer} />
            </div>
            {/* Vertical divider */}
            <div className="w-px self-stretch flex-shrink-0 relative z-10" style={{ background: 'rgba(255,255,255,0.07)' }} />
            {/* Info panel */}
            <div className="flex flex-col justify-center px-5 py-6 relative z-10" style={{ isolation: 'isolate' }}>
              <EnginePanel activeLayer={activeLayer} />
            </div>
          </div>
        </div>

        {/* ── Controls bar ───────────────────────────────────────────────── */}
        <div className="flex items-center justify-center gap-3 mt-10 flex-wrap">

          {/* Prev */}
          <button
            onClick={goPrev}
            disabled={activeLayer === 0}
            aria-label="Previous layer"
            className="w-9 h-9 rounded-full border flex items-center justify-center transition-all duration-200 disabled:opacity-25 disabled:cursor-not-allowed"
            style={{
              borderColor: 'rgba(139,255,62,0.15)',
              color: 'rgba(255,255,255,0.45)',
            }}
            onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = theme.color + '50'; (e.currentTarget as HTMLButtonElement).style.color = '#fff' }}
            onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'rgba(139,255,62,0.15)'; (e.currentTarget as HTMLButtonElement).style.color = 'rgba(255,255,255,0.45)' }}
          >
            <ChevronLeft className="w-4 h-4" />
          </button>

          {/* Layer dots */}
          <div className="flex items-center gap-1.5">
            {Array.from({ length: 8 }).map((_, i) => (
              <button
                key={i}
                onClick={() => goToLayer(i)}
                aria-label={`Go to layer ${i + 1}`}
                className="rounded-full transition-all duration-300 hover:opacity-80"
                style={{
                  width:      i === activeLayer ? 20 : 6,
                  height:     6,
                  background: i <= activeLayer ? theme.color : 'rgba(139,255,62,0.15)',
                  transition: 'width 0.35s ease, background 0.5s ease',
                }}
              />
            ))}
          </div>

          {/* Next */}
          <button
            onClick={goNext}
            disabled={activeLayer === TOTAL_LAYERS - 1}
            aria-label="Next layer"
            className="w-9 h-9 rounded-full border flex items-center justify-center transition-all duration-200 disabled:opacity-25 disabled:cursor-not-allowed"
            style={{
              borderColor: 'rgba(139,255,62,0.15)',
              color: 'rgba(255,255,255,0.45)',
            }}
            onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = theme.color + '50'; (e.currentTarget as HTMLButtonElement).style.color = '#fff' }}
            onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'rgba(139,255,62,0.15)'; (e.currentTarget as HTMLButtonElement).style.color = 'rgba(255,255,255,0.45)' }}
          >
            <ChevronRight className="w-4 h-4" />
          </button>

          {/* Auto-play indicator / skip / replay */}
          {isComplete ? (
            <button
              onClick={replay}
              className="flex items-center gap-1.5 ml-2 text-[10px] font-medium transition-colors duration-200"
              style={{ color: 'rgba(255,255,255,0.3)' }}
              onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = theme.color }}
              onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = 'rgba(255,255,255,0.3)' }}
            >
              <RotateCcw className="w-3 h-3" />
              Replay
            </button>
          ) : autoPlay ? (
            <div className="flex items-center gap-1.5 ml-2">
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ background: theme.color, animation: isHovered ? 'none' : 'pulse 1.4s ease-in-out infinite' }}
              />
              <span className="text-[9px] text-[rgba(255,255,255,0.3)] font-mono">
                {isHovered ? 'paused' : 'auto'}
              </span>
            </div>
          ) : (
            <button
              onClick={skip}
              className="ml-2 text-[10px] font-medium transition-colors duration-200"
              style={{ color: 'rgba(255,255,255,0.28)' }}
              onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = 'rgba(255,255,255,0.6)' }}
              onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = 'rgba(255,255,255,0.28)' }}
            >
              skip to end →
            </button>
          )}
        </div>

        {/* Mobile layer counter */}
        <div className="lg:hidden flex items-center justify-center gap-2 mt-5">
          <span className="text-[9px] text-[rgba(255,255,255,0.3)] font-mono">
            Layer {activeLayer + 1} / 8
            {autoPlay && !isHovered ? ' · auto' : isHovered ? ' · paused' : ''}
          </span>
        </div>

      </SectionContainer>
    </section>
  )
}
