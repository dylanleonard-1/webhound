'use client'

/* ────────────────────────────────────────────────────────────────────────
   WebHound — Standalone Hologram Prototype
   components/experiments/HologramPrototype.tsx

   A self-contained, full-screen holographic projection sandbox. NOT wired
   into the homepage / hero / nav — this is a lab to perfect the look before
   integration. Renders a futuristic projector generating a floating
   WebHound shield with beams, particles, scanlines and layered glow.

   • Pure CSS animation (transform / opacity only) — no canvas, no libs.
   • Respects prefers-reduced-motion.
   • Debug mode: add ?holo-debug to the URL, or press "D".
   • Live tuning panel appears in debug mode.
   ──────────────────────────────────────────────────────────────────────── */

import Image from 'next/image'
import { useEffect, useMemo, useRef, useState } from 'react'

/* ===========================================================================
   TUNABLE VARIABLES  — everything is easy to tweak from this one object.
   (All values are also live-editable from the debug panel.)
   =========================================================================== */
type HoloConfig = {
  shieldSize: number      // px — rendered size of the floating shield
  shieldOpacity: number   // 0–1 — base opacity of the shield
  beamHeight: number      // px — vertical distance the beams span (base → shield)
  beamWidth: number       // px — width of a single beam
  beamCount: number       // 5–12 — number of independent beams
  beamSpread: number      // px — horizontal fan width of the beam cone
  particleCount: number   // number of rising particles
  particleSpeed: number   // s — base travel duration (lower = faster)
  glowIntensity: number   // 0–2 — multiplier on every glow layer
  floatAmount: number     // px — how far the shield drifts up/down
  floatSpeed: number      // s — duration of one float cycle
  floatScale: number      // peak scale at top of float (e.g. 1.03)
  flickerStrength: number // 0–1 — depth of the opacity flicker
  scanlineOpacity: number // 0–1 — visibility of the holographic scanlines
  hue: number             // brand green hue source (#8BFF3E)
}

const DEFAULTS: HoloConfig = {
  shieldSize: 360,
  shieldOpacity: 0.88,
  beamHeight: 340,
  beamWidth: 30,
  beamCount: 9,
  beamSpread: 240,
  particleCount: 46,
  particleSpeed: 7,
  glowIntensity: 1,
  floatAmount: 12,
  floatSpeed: 6,
  floatScale: 1.03,
  flickerStrength: 0.18,
  scanlineOpacity: 0.1,
  hue: 95, // hsl hue close to #8BFF3E
}

// Brand palette derived once.
const GREEN = '#8BFF3E'
const GREEN_DIM = '#5fcc1a'
const GREEN_DEEP = '#2e7a08'

/**
 * @param embedded  When true the scene fills its positioned parent (instead
 *   of the viewport), uses a transparent/blended background, measures its own
 *   box for auto-fit, and disables the debug panel + "D" key listener. Use
 *   this for dropping the hologram into the hero. Default false = standalone
 *   full-screen sandbox.
 */
export default function HologramPrototype({
  embedded = false,
}: { embedded?: boolean } = {}) {
  const [cfg, setCfg] = useState<HoloConfig>(DEFAULTS)
  const [debug, setDebug] = useState(false)
  const [reduce, setReduce] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const enableDebug = !embedded

  // Debug from URL (?holo-debug) + "D" key toggle. Disabled when embedded
  // so the homepage never hijacks the "d" key or shows the tuning panel.
  useEffect(() => {
    if (typeof window === 'undefined' || !enableDebug) return
    const params = new URLSearchParams(window.location.search)
    if (params.has('holo-debug')) setDebug(true)

    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === 'd' && !e.metaKey && !e.ctrlKey) {
        setDebug((d) => !d)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [enableDebug])

  // prefers-reduced-motion
  useEffect(() => {
    if (typeof window === 'undefined') return
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const apply = () => setReduce(mq.matches)
    apply()
    mq.addEventListener('change', apply)
    return () => mq.removeEventListener('change', apply)
  }, [])

  // Auto-fit: center the whole projector→shield composition in the
  // viewport and scale it down if it would overflow, so the full
  // hologram is always visible at any window size / slider value.
  // anchorY is null until measured on the client, so the server and the
  // first client render emit an identical "62%" fallback (no hydration
  // mismatch). The real pixel anchor is applied after mount.
  const [fit, setFit] = useState<{ scale: number; anchorY: number | null }>({
    scale: 1,
    anchorY: null,
  })
  useEffect(() => {
    if (typeof window === 'undefined') return
    const el = rootRef.current
    const recompute = () => {
      // Measure the component's own box so this works identically whether
      // it fills the viewport (standalone) or a hero column (embedded).
      const rect = el?.getBoundingClientRect()
      const vw = rect?.width || window.innerWidth
      const vh = rect?.height || window.innerHeight
      // Distance from the projector baseline up to the top of the
      // shield (incl. its glow), and down to the floor reflection.
      const top = cfg.beamHeight + cfg.shieldSize * 1.04
      const bottom = 130
      const compH = top + bottom
      const compW = Math.max(cfg.shieldSize * 1.5, cfg.beamSpread * 1.4, 680)
      const scale = Math.min(1, (vh * 0.94) / compH, (vw * 0.94) / compW)
      // Baseline Y (px, box-local) that vertically centers the scaled scene.
      const baselineY = vh / 2 + (scale * (top - bottom)) / 2
      setFit({ scale, anchorY: baselineY })
    }
    recompute()
    const ro =
      el && 'ResizeObserver' in window ? new ResizeObserver(recompute) : null
    if (ro && el) ro.observe(el)
    window.addEventListener('resize', recompute)
    return () => {
      window.removeEventListener('resize', recompute)
      ro?.disconnect()
    }
  }, [cfg.beamHeight, cfg.shieldSize, cfg.beamSpread])

  // Pre-compute beam descriptors (positions / speeds / brightness vary).
  const beams = useMemo(() => {
    const n = cfg.beamCount
    return Array.from({ length: n }, (_, i) => {
      const t = n === 1 ? 0.5 : i / (n - 1) // 0..1 across the fan
      const x = (t - 0.5) * cfg.beamSpread // horizontal offset from center
      const edge = Math.abs(t - 0.5) * 2 // 0 center → 1 edges
      return {
        x,
        rotate: (t - 0.5) * 10, // slight cone fan
        width: cfg.beamWidth * (1 - edge * 0.45),
        brightness: 0.85 - edge * 0.5, // center beams brightest
        duration: 3.2 + (i % 5) * 0.9, // varied speeds
        delay: -(i * 0.6),
      }
    })
  }, [cfg.beamCount, cfg.beamSpread, cfg.beamWidth])

  // Pre-compute particle descriptors (randomized once).
  const particles = useMemo(() => {
    return Array.from({ length: cfg.particleCount }, (_, i) => {
      const r = (seed: number) => mulberry(i * 97 + seed)
      const band = cfg.beamSpread * 0.7
      return {
        x: (r(1) - 0.5) * band, // start x near base, biased to center
        size: 1 + r(2) * 2.5,
        rise: cfg.beamHeight * (0.9 + r(3) * 0.6),
        drift: (r(4) - 0.5) * 60,
        duration: cfg.particleSpeed * (0.7 + r(5) * 0.9),
        delay: -r(6) * cfg.particleSpeed,
        opacity: 0.25 + r(7) * 0.55,
      }
    })
  }, [cfg.particleCount, cfg.beamSpread, cfg.beamHeight, cfg.particleSpeed])

  // CSS custom properties driven by config.
  const rootStyle = {
    '--shield-size': `${cfg.shieldSize}px`,
    '--shield-opacity': cfg.shieldOpacity,
    '--beam-height': `${cfg.beamHeight}px`,
    '--beam-width': `${cfg.beamWidth}px`,
    '--float-amount': `${cfg.floatAmount}px`,
    '--float-speed': `${cfg.floatSpeed}s`,
    '--float-scale': cfg.floatScale,
    '--flicker-low': Math.max(0, cfg.shieldOpacity * (1 - cfg.flickerStrength)),
    '--scanline-opacity': cfg.scanlineOpacity,
    '--glow': cfg.glowIntensity,
    '--fit': fit.scale,
    '--anchor-y': fit.anchorY === null ? '62%' : `${fit.anchorY}px`,
    '--green': GREEN,
    '--green-dim': GREEN_DIM,
    '--green-deep': GREEN_DEEP,
  } as React.CSSProperties

  const noMotion = reduce

  return (
    <div
      ref={rootRef}
      className={`holo-root${embedded ? ' holo-embedded' : ''}${debug ? ' holo-debug' : ''}${noMotion ? ' holo-reduce' : ''}`}
      style={rootStyle}
    >
      <style>{CSS}</style>

      {/* Environmental ambient glow filling the scene */}
      <div className="holo-ambient" />

      {/* Cyber grid floor */}
      <div className="holo-grid" />
      <div className="holo-floor-glow" />

      {/* Centering stage. Everything is anchored to the projector center. */}
      <div className="holo-stage">
        {/* Beam-column glow behind the beams */}
        <div className="holo-beamglow" />

        {/* Beams (base → shield) */}
        <div className="holo-beams">
          {beams.map((b, i) => (
            <span
              key={i}
              className="holo-beam"
              style={
                {
                  '--bx': `${b.x}px`,
                  '--brot': `${b.rotate}deg`,
                  '--bw': `${b.width}px`,
                  '--bbright': b.brightness,
                  '--bdur': `${b.duration}s`,
                  '--bdelay': `${b.delay}s`,
                } as React.CSSProperties
              }
            />
          ))}
        </div>

        {/* Rising particles */}
        <div className="holo-particles">
          {particles.map((p, i) => (
            <span
              key={i}
              className="holo-particle"
              style={
                {
                  '--px': `${p.x}px`,
                  '--psize': `${p.size}px`,
                  '--prise': `${-p.rise}px`,
                  '--pdrift': `${p.drift}px`,
                  '--pdur': `${p.duration}s`,
                  '--pdelay': `${p.delay}s`,
                  '--pop': p.opacity,
                } as React.CSSProperties
              }
            />
          ))}
        </div>

        {/* Floating shield */}
        <div className="holo-shield-wrap">
          <div className="holo-shield-glow" />
          <div className="holo-shield-float">
            <div className="holo-shield-flicker">
              <div className="holo-shield-distort">
                <Image
                  src="/images/webhound-logo-1.png"
                  alt=""
                  width={cfg.shieldSize}
                  height={cfg.shieldSize}
                  className="holo-shield-img"
                  priority
                  draggable={false}
                />
                {/* Scanlines clipped to the shield */}
                <div className="holo-shield-scan" />
              </div>
            </div>
          </div>
        </div>

        {/* Projector base */}
        <div className="holo-base">
          <div className="holo-base-glow" />
          <div className="holo-ring holo-ring-3" />
          <div className="holo-ring holo-ring-2" />
          <div className="holo-ring holo-ring-1" />
          <div className="holo-core" />
          <div className="holo-core-pulse" />
        </div>

        {/* Reflection of the projection on the floor */}
        <div className="holo-reflection" />

        {/* Debug origin markers */}
        <div className="holo-dbg-origin" />
      </div>

      {/* Global scanlines drifting across the whole projection volume */}
      <div className="holo-global-scan" />

      {debug && <DebugPanel cfg={cfg} setCfg={setCfg} reduce={reduce} />}
    </div>
  )
}

/* ── Tiny deterministic PRNG so particle layout is stable across renders ── */
function mulberry(seed: number) {
  let t = (seed + 0x6d2b79f5) >>> 0
  t = Math.imul(t ^ (t >>> 15), t | 1)
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296
}

/* ===========================================================================
   Debug / live-tuning panel (only mounted in debug mode)
   =========================================================================== */
function DebugPanel({
  cfg,
  setCfg,
  reduce,
}: {
  cfg: HoloConfig
  setCfg: React.Dispatch<React.SetStateAction<HoloConfig>>
  reduce: boolean
}) {
  const rows: [keyof HoloConfig, number, number, number][] = [
    ['shieldSize', 120, 600, 1],
    ['shieldOpacity', 0, 1, 0.01],
    ['beamHeight', 150, 600, 1],
    ['beamWidth', 4, 80, 1],
    ['beamCount', 5, 12, 1],
    ['beamSpread', 60, 400, 1],
    ['particleCount', 0, 120, 1],
    ['particleSpeed', 2, 14, 0.5],
    ['glowIntensity', 0, 2, 0.05],
    ['floatAmount', 0, 40, 1],
    ['floatSpeed', 2, 14, 0.5],
    ['floatScale', 1, 1.12, 0.005],
    ['flickerStrength', 0, 1, 0.01],
    ['scanlineOpacity', 0, 0.4, 0.01],
  ]
  return (
    <div className="holo-panel">
      <div className="holo-panel-head">
        holo-debug {reduce && <span className="holo-panel-rm">· reduced-motion</span>}
      </div>
      {rows.map(([key, min, max, step]) => (
        <label key={key} className="holo-panel-row">
          <span>{key}</span>
          <input
            type="range"
            min={min}
            max={max}
            step={step}
            value={cfg[key]}
            onChange={(e) =>
              setCfg((c) => ({ ...c, [key]: parseFloat(e.target.value) }))
            }
          />
          <b>{cfg[key]}</b>
        </label>
      ))}
      <button className="holo-panel-reset" onClick={() => setCfg(DEFAULTS)}>
        reset
      </button>
      <div className="holo-panel-hint">press D to toggle</div>
    </div>
  )
}

/* ===========================================================================
   Styles — all transform/opacity driven for cheap compositing.
   =========================================================================== */
const CSS = `
.holo-root{
  position:absolute; inset:0; overflow:hidden;
  background:#000;
  background:
    radial-gradient(120% 90% at 50% 78%, #04140a 0%, #020806 45%, #000 100%);
  perspective:1100px;
  --gv: var(--glow);
}
.holo-root *{ pointer-events:none; }
/* Embedded in the hero: no opaque box — let the projection's own glow
   float over the hero background, with a soft dark-green pool for depth. */
.holo-embedded{
  background:radial-gradient(70% 70% at 55% 60%,
    rgba(4,20,10,0.55) 0%, rgba(2,6,23,0) 72%) !important;
}

/* ---------- environmental ambient ---------- */
.holo-ambient{
  position:absolute; inset:0;
  background:
    radial-gradient(60% 50% at 50% 60%,
      color-mix(in srgb, var(--green) 14%, transparent) 0%,
      transparent 70%);
  opacity:calc(0.9 * var(--gv));
  mix-blend-mode:screen;
  animation:holo-breathe 9s ease-in-out infinite;
}

/* ---------- cyber grid floor ---------- */
.holo-grid{
  position:absolute; left:50%; bottom:-6%;
  width:260vw; height:120vh;
  transform:translateX(-50%) rotateX(76deg);
  transform-origin:50% 0;
  background-image:
    linear-gradient(to right, color-mix(in srgb, var(--green) 26%, transparent) 1px, transparent 1px),
    linear-gradient(to bottom, color-mix(in srgb, var(--green) 26%, transparent) 1px, transparent 1px);
  background-size:64px 64px;
  -webkit-mask-image:radial-gradient(60% 60% at 50% 18%, #000 0%, transparent 72%);
  mask-image:radial-gradient(60% 60% at 50% 18%, #000 0%, transparent 72%);
  opacity:calc(0.5 * var(--gv));
  animation:holo-grid-pan 12s linear infinite;
}
.holo-floor-glow{
  position:absolute; left:50%; top:var(--anchor-y, 62%);
  width:680px; height:200px; transform:translate(-50%,-50%);
  background:radial-gradient(ellipse at center,
    color-mix(in srgb, var(--green) 32%, transparent) 0%, transparent 70%);
  filter:blur(22px);
  opacity:calc(0.7 * var(--gv));
}

/* ---------- centering stage ---------- */
.holo-stage{
  position:absolute; left:50%; top:var(--anchor-y, 62%);
  transform:translateX(-50%) scale(var(--fit, 1));
  transform-origin:50% 100%;
  width:0; height:0;
}

/* ---------- beams ---------- */
.holo-beams, .holo-particles{
  position:absolute; left:0; bottom:0; transform:translateX(-50%); width:0;
}
.holo-beamglow{
  position:absolute; left:50%; bottom:10px; transform:translateX(-50%);
  width:calc(var(--beam-width) * 6);
  height:var(--beam-height);
  background:linear-gradient(to top,
    color-mix(in srgb, var(--green) 40%, transparent) 0%,
    transparent 85%);
  filter:blur(26px);
  opacity:calc(0.65 * var(--gv));
  border-radius:50%;
}
.holo-beam{
  position:absolute; bottom:8px; left:0;
  width:var(--bw); height:var(--beam-height);
  margin-left:calc(var(--bx) - var(--bw)/2);
  transform-origin:50% 100%;
  transform:rotate(var(--brot)) scaleY(1);
  background:linear-gradient(to top,
    color-mix(in srgb, var(--green) 85%, white) 0%,
    color-mix(in srgb, var(--green) 55%, transparent) 28%,
    color-mix(in srgb, var(--green) 22%, transparent) 62%,
    transparent 100%);
  filter:blur(2px);
  opacity:calc(var(--bbright) * var(--gv));
  border-radius:50% 50% 0 0 / 14% 14% 0 0;
  animation:holo-beam-pulse var(--bdur) ease-in-out infinite;
  animation-delay:var(--bdelay);
  mix-blend-mode:screen;
}

/* ---------- particles ---------- */
.holo-particle{
  position:absolute; bottom:14px; left:0;
  width:var(--psize); height:var(--psize);
  margin-left:var(--px);
  border-radius:50%;
  background:radial-gradient(circle, #eafff0 0%, var(--green) 55%, transparent 100%);
  opacity:0;
  box-shadow:0 0 6px color-mix(in srgb, var(--green) 80%, transparent);
  animation:holo-particle var(--pdur) linear infinite;
  animation-delay:var(--pdelay);
}

/* ---------- shield ---------- */
.holo-shield-wrap{
  position:absolute; left:50%;
  bottom:calc(var(--beam-height) - var(--shield-size) * 0.18);
  transform:translateX(-50%);
  width:var(--shield-size); height:var(--shield-size);
  display:flex; align-items:center; justify-content:center;
}
.holo-shield-glow{
  position:absolute; inset:-22%;
  background:radial-gradient(circle at center,
    color-mix(in srgb, var(--green) 45%, transparent) 0%,
    color-mix(in srgb, var(--green) 14%, transparent) 42%,
    transparent 70%);
  filter:blur(26px);
  opacity:calc(0.85 * var(--gv));
  animation:holo-breathe 5s ease-in-out infinite;
}
.holo-shield-float{ animation:holo-float var(--float-speed) ease-in-out infinite; }
.holo-shield-flicker{ animation:holo-flicker 6s steps(1,end) infinite; opacity:var(--shield-opacity); }
.holo-shield-distort{ position:relative; animation:holo-distort 7s ease-in-out infinite; }
.holo-shield-img{
  display:block; width:var(--shield-size); height:var(--shield-size);
  object-fit:contain;
  filter:
    brightness(1.15) saturate(1.25)
    drop-shadow(0 0 14px color-mix(in srgb, var(--green) 75%, transparent))
    drop-shadow(0 0 36px color-mix(in srgb, var(--green) 45%, transparent));
}
.holo-shield-scan{
  position:absolute; inset:0;
  background:repeating-linear-gradient(
    0deg,
    transparent 0px,
    transparent 2px,
    color-mix(in srgb, var(--green) 60%, transparent) 3px,
    transparent 4px);
  mix-blend-mode:overlay;
  opacity:var(--scanline-opacity);
  -webkit-mask-image:url('/images/webhound-logo-1.png');
  mask-image:url('/images/webhound-logo-1.png');
  -webkit-mask-size:contain; mask-size:contain;
  -webkit-mask-repeat:no-repeat; mask-repeat:no-repeat;
  -webkit-mask-position:center; mask-position:center;
  animation:holo-scan-move 5s linear infinite;
}

/* ---------- projector base ---------- */
.holo-base{
  position:absolute; left:50%; bottom:0; transform:translateX(-50%);
  width:260px; height:80px;
  display:flex; align-items:center; justify-content:center;
}
.holo-base-glow{
  position:absolute; bottom:6px;
  width:300px; height:90px;
  background:radial-gradient(ellipse at center,
    color-mix(in srgb, var(--green) 55%, transparent) 0%, transparent 70%);
  filter:blur(16px);
  opacity:calc(0.9 * var(--gv));
}
.holo-ring{
  position:absolute; bottom:0; left:50%; transform:translateX(-50%) rotateX(72deg);
  border-radius:50%;
  border:1px solid color-mix(in srgb, var(--green) 70%, transparent);
  box-shadow:0 0 12px color-mix(in srgb, var(--green) 50%, transparent);
}
.holo-ring-1{ width:120px; height:120px; opacity:.95; animation:holo-ring-pulse 3s ease-in-out infinite; }
.holo-ring-2{ width:190px; height:190px; opacity:.6; animation:holo-ring-pulse 3s ease-in-out infinite .4s; }
.holo-ring-3{ width:260px; height:260px; opacity:.35; animation:holo-ring-pulse 3s ease-in-out infinite .8s; }
.holo-core{
  position:absolute; bottom:14px; left:50%; transform:translateX(-50%) rotateX(72deg);
  width:54px; height:54px; border-radius:50%;
  background:radial-gradient(circle, #f4ffe9 0%, var(--green) 40%, var(--green-deep) 100%);
  box-shadow:
    0 0 18px var(--green),
    0 0 48px color-mix(in srgb, var(--green) 70%, transparent);
  animation:holo-core-pulse 2.4s ease-in-out infinite;
}
.holo-core-pulse{
  position:absolute; bottom:14px; left:50%; transform:translateX(-50%) rotateX(72deg);
  width:54px; height:54px; border-radius:50%;
  border:1px solid var(--green);
  animation:holo-core-ripple 2.4s ease-out infinite;
}

/* ---------- floor reflection ---------- */
.holo-reflection{
  position:absolute; left:50%; bottom:-10px; transform:translateX(-50%) scaleY(-0.5);
  width:var(--shield-size); height:calc(var(--shield-size) * 0.5);
  background:radial-gradient(ellipse at top,
    color-mix(in srgb, var(--green) 22%, transparent) 0%, transparent 65%);
  filter:blur(10px);
  opacity:calc(0.4 * var(--gv));
}

/* ---------- global drifting scanlines ---------- */
.holo-global-scan{
  position:absolute; inset:0;
  background:repeating-linear-gradient(
    0deg, transparent 0px, transparent 3px,
    rgba(180,255,150,0.5) 4px, transparent 5px);
  opacity:calc(var(--scanline-opacity) * 0.6);
  mix-blend-mode:overlay;
  animation:holo-scan-move 9s linear infinite;
}

/* =========================== keyframes =========================== */
@keyframes holo-float{
  0%,100%{ transform:translateY(0) scale(1); }
  50%{ transform:translateY(calc(var(--float-amount) * -1)) scale(var(--float-scale)); }
}
@keyframes holo-flicker{
  0%,100%,40%,80%{ opacity:var(--shield-opacity); }
  42%{ opacity:var(--flicker-low); }
  43%{ opacity:var(--shield-opacity); }
  72%{ opacity:calc(var(--flicker-low) + 0.06); }
  73%{ opacity:var(--shield-opacity); }
  90%{ opacity:var(--flicker-low); }
  91%{ opacity:var(--shield-opacity); }
}
@keyframes holo-distort{
  0%,100%{ transform:skewX(0deg) translateX(0); }
  48%{ transform:skewX(0.5deg) translateX(0.5px); }
  50%{ transform:skewX(-0.8deg) translateX(-1px); }
  52%{ transform:skewX(0.4deg) translateX(0.5px); }
}
@keyframes holo-beam-pulse{
  0%,100%{ opacity:calc(var(--bbright) * 0.45 * var(--gv)); transform:rotate(var(--brot)) scaleY(0.97); }
  50%{ opacity:calc(var(--bbright) * var(--gv)); transform:rotate(var(--brot)) scaleY(1.02); }
}
@keyframes holo-particle{
  0%{ transform:translate(0,0); opacity:0; }
  12%{ opacity:var(--pop); }
  82%{ opacity:var(--pop); }
  100%{ transform:translate(var(--pdrift), var(--prise)); opacity:0; }
}
@keyframes holo-scan-move{
  0%{ background-position-y:0; }
  100%{ background-position-y:64px; }
}
@keyframes holo-breathe{
  0%,100%{ opacity:calc(0.6 * var(--gv)); }
  50%{ opacity:calc(1 * var(--gv)); }
}
@keyframes holo-grid-pan{
  0%{ background-position:0 0; }
  100%{ background-position:0 64px; }
}
@keyframes holo-ring-pulse{
  0%,100%{ opacity:.4; }
  50%{ opacity:.95; }
}
@keyframes holo-core-pulse{
  0%,100%{ transform:translateX(-50%) rotateX(72deg) scale(1); filter:brightness(1); }
  50%{ transform:translateX(-50%) rotateX(72deg) scale(1.12); filter:brightness(1.4); }
}
@keyframes holo-core-ripple{
  0%{ transform:translateX(-50%) rotateX(72deg) scale(1); opacity:.8; }
  100%{ transform:translateX(-50%) rotateX(72deg) scale(3.2); opacity:0; }
}

/* =========================== reduced motion =========================== */
.holo-reduce .holo-shield-float,
.holo-reduce .holo-shield-flicker,
.holo-reduce .holo-shield-distort,
.holo-reduce .holo-beam,
.holo-reduce .holo-particle,
.holo-reduce .holo-shield-scan,
.holo-reduce .holo-global-scan,
.holo-reduce .holo-grid,
.holo-reduce .holo-ambient,
.holo-reduce .holo-shield-glow,
.holo-reduce .holo-ring,
.holo-reduce .holo-core,
.holo-reduce .holo-core-pulse{
  animation:none !important;
}
.holo-reduce .holo-particle{ opacity:0 !important; }
.holo-reduce .holo-shield-flicker{ opacity:var(--shield-opacity); }
.holo-reduce .holo-beam{ opacity:calc(var(--bbright) * var(--gv)); }

/* =========================== debug mode =========================== */
.holo-debug .holo-shield-wrap{ outline:1px solid rgba(255,235,0,.9); }
.holo-debug .holo-beams{ outline:1px dashed rgba(0,170,255,.6); }
.holo-debug .holo-beam{ outline:1px solid rgba(0,170,255,.45); }
.holo-debug .holo-stage{ outline:1px solid rgba(0,120,255,.5); overflow:visible; }
.holo-dbg-origin{ display:none; }
.holo-debug .holo-dbg-origin{
  display:block; position:absolute; left:0; bottom:8px;
  width:10px; height:10px; margin-left:-5px; border-radius:50%;
  background:red; box-shadow:0 0 0 2px #fff;
  z-index:50;
}

/* =========================== debug panel =========================== */
.holo-panel{
  position:fixed; top:14px; right:14px; z-index:60;
  width:248px; padding:12px;
  font:11px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;
  color:#bdffa0; background:rgba(2,12,6,.86);
  border:1px solid color-mix(in srgb, ${GREEN} 40%, transparent);
  border-radius:10px; backdrop-filter:blur(8px);
  pointer-events:auto !important;
}
.holo-panel *{ pointer-events:auto !important; }
.holo-panel-head{ font-weight:700; letter-spacing:.08em; text-transform:uppercase; margin-bottom:8px; color:${GREEN}; }
.holo-panel-rm{ color:#ffd24d; font-weight:400; text-transform:none; }
.holo-panel-row{ display:grid; grid-template-columns:92px 1fr 38px; align-items:center; gap:6px; margin:3px 0; }
.holo-panel-row span{ opacity:.8; }
.holo-panel-row b{ text-align:right; color:#eafff0; font-weight:600; }
.holo-panel-row input[type=range]{ width:100%; accent-color:${GREEN}; }
.holo-panel-reset{
  margin-top:8px; width:100%; padding:5px; cursor:pointer;
  background:color-mix(in srgb, ${GREEN} 20%, transparent);
  color:#eafff0; border:1px solid color-mix(in srgb, ${GREEN} 45%, transparent);
  border-radius:6px; font:inherit;
}
.holo-panel-hint{ margin-top:6px; text-align:center; opacity:.5; }
`
