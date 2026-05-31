'use client'

/* ────────────────────────────────────────────────────────────────────────
   WebHound — components/sections/hero-tablet-dashboard.tsx

   A premium WebHound scan dashboard rendered INSIDE the empty tablet
   screen in the hero image. Hero-only; pins to the measured screen-glass
   perspective trapezoid via a matrix3d corner-pin homography.

   How it pins:
     • This component overlays the hero image box exactly (absolute inset-0
       inside the image layer, which is the offset parent).
     • It measures that box, derives the object-contain / center-bottom
       content box, then the 4 screen-glass corners (known % of the image),
       and computes a matrix3d that maps an authored DESIGN_W×DESIGN_H rect
       onto those 4 corners. A ResizeObserver keeps it pinned on resize.
     • pointer-events:none throughout — purely decorative product UI.

   Measured screen-glass quad (% of the natural 1672×941 image):
     TL 24.5,15.5 · TR 70.5,11.5 · BR 66.0,72.5 · BL 18.5,69.0
   ──────────────────────────────────────────────────────────────────────── */

import Image from 'next/image'
import type React from 'react'
import { useEffect, useMemo, useRef, useState } from 'react'

// Image natural aspect (1672×941) — matches object-contain math.
const NAT_AR = 1672 / 941

// Screen-glass quad as % of the rendered image content box.
// Corners read directly off the bezel highlight at 5× zoom per corner, so
// the matrix3d corner-pin reproduces the tablet's true perspective: top
// edge rises to the right, left side recedes (shorter), bottom widens.
const QUAD = {
  TL: [24.3, 13.0],
  TR: [69.6, 10.3],
  BR: [70.8, 72.8],
  BL: [16.6, 68.6],
} as const

// Inset the UI ~2.2% inside the quad — fills the glass while clearing
// the rounded bezel corners.
const INSET = 0.022

// Authored design space (the matrix maps this rect onto the quad).
const DESIGN_W = 725
const DESIGN_H = 500

type Corner = 'TL' | 'TR' | 'BR' | 'BL'
type Quad = Record<Corner, [number, number]>

export function HeroTabletDashboard() {
  const wrapRef = useRef<HTMLDivElement>(null)
  const [matrix, setMatrix] = useState<string | null>(null)
  const [reduce, setReduce] = useState(false)
  const [mounted, setMounted] = useState(false)

  // ── live corner tuner (temporary; enable with ?htd-tune) ──
  const [tune, setTune] = useState(false)
  const [quad, setQuad] = useState<Quad>(() => ({
    TL: [...QUAD.TL] as [number, number],
    TR: [...QUAD.TR] as [number, number],
    BR: [...QUAD.BR] as [number, number],
    BL: [...QUAD.BL] as [number, number],
  }))
  // Content-box geometry (viewport px) so the tuner maps px <-> image-%.
  const geomRef = useRef({ left: 0, top: 0, cx: 0, cy: 0, cw: 1, ch: 1 })

  useEffect(() => {
    if (typeof window === 'undefined') return
    if (new URLSearchParams(window.location.search).has('htd-tune')) setTune(true)
  }, [])

  // prefers-reduced-motion
  useEffect(() => {
    if (typeof window === 'undefined') return
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const apply = () => setReduce(mq.matches)
    apply()
    mq.addEventListener('change', apply)
    return () => mq.removeEventListener('change', apply)
  }, [])

  // Measure + compute the corner-pin matrix3d.
  useEffect(() => {
    if (typeof window === 'undefined') return
    const el = wrapRef.current
    if (!el) return

    const recompute = () => {
      const r = el.getBoundingClientRect()
      const w = r.width, h = r.height
      if (!w || !h) return
      // object-contain + object-position: center bottom.
      const elAR = w / h
      let cw, ch, cx, cy
      if (NAT_AR > elAR) { cw = w; ch = w / NAT_AR; cx = 0; cy = h - ch }
      else { ch = h; cw = h * NAT_AR; cy = 0; cx = (w - cw) / 2 }

      // Stash geometry for the tuner (viewport-relative).
      geomRef.current = { left: r.left, top: r.top, cx, cy, cw, ch }

      // Quad corners in px (relative to overlay top-left), with inset.
      const toPx = ([px, py]: readonly [number, number]) =>
        [cx + (px / 100) * cw, cy + (py / 100) * ch] as [number, number]
      let TL = toPx(quad.TL), TR = toPx(quad.TR), BR = toPx(quad.BR), BL = toPx(quad.BL)
      // Apply inset toward the quad centroid.
      const cX = (TL[0] + TR[0] + BR[0] + BL[0]) / 4
      const cY = (TL[1] + TR[1] + BR[1] + BL[1]) / 4
      const ins = (p: [number, number]): [number, number] =>
        [p[0] + (cX - p[0]) * INSET, p[1] + (cY - p[1]) * INSET]
      ;[TL, TR, BR, BL] = [ins(TL), ins(TR), ins(BR), ins(BL)]

      const m = cornerPin(DESIGN_W, DESIGN_H, TL, TR, BR, BL)
      setMatrix(m)
    }

    recompute()
    setMounted(true)
    const ro = 'ResizeObserver' in window ? new ResizeObserver(recompute) : null
    ro?.observe(el)
    window.addEventListener('resize', recompute)
    window.addEventListener('scroll', recompute, { passive: true })
    return () => {
      ro?.disconnect()
      window.removeEventListener('resize', recompute)
      window.removeEventListener('scroll', recompute)
    }
  }, [quad])

  // Count-up for the security score (respects reduced motion).
  const TARGET = 72
  const [score, setScore] = useState(reduce ? TARGET : 0)
  useEffect(() => {
    if (reduce || !mounted) { setScore(TARGET); return }
    let raf = 0
    const start = performance.now()
    const dur = 1300
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / dur)
      const eased = 1 - Math.pow(1 - t, 3)
      setScore(Math.round(eased * TARGET))
      if (t < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [reduce, mounted])

  const ring = useMemo(() => {
    const R = 42, C = 2 * Math.PI * R
    return { R, C, offset: C * (1 - score / 100) }
  }, [score])

  return (
    <>
    <div
      ref={wrapRef}
      aria-hidden
      className="absolute inset-0"
      style={{ pointerEvents: 'none', perspective: 1200 }}
    >
      <div
        className={`htd${reduce ? ' htd-reduce' : ''}`}
        style={{
          position: 'absolute',
          left: 0,
          top: 0,
          width: DESIGN_W,
          height: DESIGN_H,
          transformOrigin: '0 0',
          transform: matrix ?? 'translateZ(0)',
          opacity: matrix ? 1 : 0,
          transition: 'opacity .4s ease',
        }}
      >
        <style>{CSS}</style>

        {/* glass surface */}
        <div className="htd-glass">
          {/* top-edge LCD sheen (static — reads as a glossy screen) */}
          <div className="htd-sheen" />

          {/* ── header ── */}
          <div className="htd-header">
            <div className="htd-brand">
              <Image
                src="/images/webhound-logo-1.png"
                alt=""
                width={20}
                height={20}
                className="htd-logo"
                draggable={false}
              />
              WebHound
            </div>
            <div className="htd-scanning">
              Scanning: <span className="htd-domain">example.com</span>
            </div>
            <div className="htd-live">
              <span className="htd-live-dot" />
              Live Scan
            </div>
          </div>

          {/* ── body ── */}
          <div className="htd-body">
            {/* left column */}
            <div className="htd-col-left">
              {/* score card */}
              <div className="htd-card htd-score">
                <div className="htd-score-ring">
                  <svg viewBox="0 0 100 100" width="86" height="86">
                    <circle cx="50" cy="50" r={ring.R} className="htd-ring-bg" />
                    <circle
                      cx="50" cy="50" r={ring.R}
                      className="htd-ring-fg"
                      strokeDasharray={ring.C}
                      strokeDashoffset={ring.offset}
                      transform="rotate(-90 50 50)"
                    />
                  </svg>
                  <div className="htd-score-num">
                    <b>{score}</b>
                    <span>/100</span>
                  </div>
                </div>
                <div className="htd-score-meta">
                  <div className="htd-score-label">Security Score</div>
                  <div className="htd-risk">Risk: Needs attention</div>
                </div>
              </div>

              {/* finding counts */}
              <div className="htd-counts">
                {COUNTS.map((c) => (
                  <div key={c.label} className="htd-count">
                    <span className="htd-dot" style={{ background: c.color, boxShadow: `0 0 6px ${c.color}aa` }} />
                    <b>{c.n}</b>
                    <span className="htd-count-label">{c.label}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* right column */}
            <div className="htd-col-right">
              {/* scan progress */}
              <div className="htd-card htd-progress">
                <div className="htd-card-title">Scan in progress</div>
                <div className="htd-bar"><div className="htd-bar-fill" /></div>
                <ul className="htd-steps">
                  {STEPS.map((s, i) => (
                    <li key={s} className={i < 2 ? 'done' : i === 2 ? 'active' : ''}>
                      <span className="htd-step-ic" />
                      {s}
                    </li>
                  ))}
                </ul>
              </div>

              {/* recent findings */}
              <div className="htd-card htd-findings">
                <div className="htd-card-title">Recent findings</div>
                <ul>
                  {FINDINGS.map((f, i) => (
                    <li key={f.t} style={{ animationDelay: `${0.6 + i * 0.25}s` }}>
                      <span className="htd-dot" style={{ background: f.color, boxShadow: `0 0 6px ${f.color}aa` }} />
                      {f.t}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* ── footer row ── */}
          <div className="htd-footer">
            <div className="htd-wade">
              <span className="htd-wade-ic" />
              <span className="htd-wade-txt">Wade noticed <b>2 changes</b> since the last scan.</span>
            </div>
            <div className="htd-monitor">
              <span className="htd-mon-dot" />
              Monitoring: <b>Active</b>
              <span className="htd-mon-sep">·</span>
              Last checked 2 min ago
            </div>
          </div>
        </div>
      </div>
    </div>
    {tune && <TabletTuner quad={quad} setQuad={setQuad} geomRef={geomRef} />}
    </>
  )
}

/* ── live corner tuner overlay (temporary; ?htd-tune) ── */
function TabletTuner({
  quad,
  setQuad,
  geomRef,
}: {
  quad: Quad
  setQuad: React.Dispatch<React.SetStateAction<Quad>>
  geomRef: React.RefObject<{ left: number; top: number; cx: number; cy: number; cw: number; ch: number }>
}) {
  const [sel, setSel] = useState<Corner>('TL')
  const [, force] = useState(0)

  useEffect(() => {
    const f = () => force((n) => n + 1)
    window.addEventListener('resize', f)
    window.addEventListener('scroll', f, { passive: true })
    const id = setInterval(f, 250)
    return () => {
      window.removeEventListener('resize', f)
      window.removeEventListener('scroll', f)
      clearInterval(id)
    }
  }, [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const step = e.shiftKey ? 0.5 : 0.1
      const d: Record<string, [number, number]> = {
        ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step],
      }
      if (!d[e.key]) return
      e.preventDefault()
      setQuad((q) => ({ ...q, [sel]: [round(q[sel][0] + d[e.key][0]), round(q[sel][1] + d[e.key][1])] }))
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [sel, setQuad])

  const g = geomRef.current
  const toVp = (c: Corner): [number, number] => [
    g.left + g.cx + (quad[c][0] / 100) * g.cw,
    g.top + g.cy + (quad[c][1] / 100) * g.ch,
  ]
  const toPct = (x: number, y: number): [number, number] => [
    round(((x - g.left - g.cx) / g.cw) * 100),
    round(((y - g.top - g.cy) / g.ch) * 100),
  ]

  const startDrag = (c: Corner) => (e: React.PointerEvent) => {
    e.preventDefault()
    setSel(c)
    const move = (ev: PointerEvent) => setQuad((q) => ({ ...q, [c]: toPct(ev.clientX, ev.clientY) }))
    const up = () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }

  const corners: Corner[] = ['TL', 'TR', 'BR', 'BL']
  const code = `const QUAD = {\n  TL: [${quad.TL}],\n  TR: [${quad.TR}],\n  BR: [${quad.BR}],\n  BL: [${quad.BL}],\n} as const`

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 99999, pointerEvents: 'none' }}>
      <svg width="100%" height="100%" style={{ position: 'absolute', inset: 0 }}>
        <polygon
          points={corners.map((c) => toVp(c).join(',')).join(' ')}
          fill="rgba(0,224,255,0.06)" stroke="#00e0ff" strokeWidth={1.5}
        />
      </svg>
      {corners.map((c) => {
        const [x, y] = toVp(c)
        return (
          <div
            key={c}
            onPointerDown={startDrag(c)}
            title={c}
            style={{
              position: 'fixed', left: x - 11, top: y - 11, width: 22, height: 22,
              borderRadius: '50%', cursor: 'grab', pointerEvents: 'auto',
              background: sel === c ? '#ffd000' : '#00e0ff',
              border: '2px solid #000', boxShadow: '0 0 0 1px #fff',
            }}
          />
        )
      })}
      <div
        style={{
          position: 'fixed', top: 12, left: 12, zIndex: 100000, pointerEvents: 'auto',
          font: '11px ui-monospace, monospace', color: '#bdffa0',
          background: 'rgba(2,12,6,0.92)', border: '1px solid rgba(139,255,62,0.4)',
          borderRadius: 8, padding: 10, width: 250,
        }}
      >
        <div style={{ fontWeight: 700, color: '#8BFF3E', marginBottom: 6 }}>htd-tune · drag dots / arrows</div>
        {corners.map((c) => (
          <div
            key={c}
            onClick={() => setSel(c)}
            style={{ cursor: 'pointer', color: sel === c ? '#ffd000' : '#bdffa0', padding: '1px 0' }}
          >
            {sel === c ? '▶ ' : '  '}{c}: [{quad[c][0]}, {quad[c][1]}]
          </div>
        ))}
        <button
          onClick={() => navigator.clipboard?.writeText(code)}
          style={{
            marginTop: 8, width: '100%', padding: 5, cursor: 'pointer', font: 'inherit',
            background: 'rgba(139,255,62,0.2)', color: '#eafff0',
            border: '1px solid rgba(139,255,62,0.45)', borderRadius: 6,
          }}
        >
          copy QUAD
        </button>
        <div style={{ marginTop: 6, opacity: 0.55 }}>click row to select · ⇧ = bigger step</div>
      </div>
    </div>
  )
}

const round = (n: number) => Math.round(n * 10) / 10

/* ── data ── */
const COUNTS = [
  { label: 'Critical', n: 1, color: '#FF4D4D' },
  { label: 'High', n: 3, color: '#FF8A3D' },
  { label: 'Medium', n: 7, color: '#FFC53D' },
  { label: 'Low', n: 12, color: '#5AA0FF' },
]
const STEPS = [
  'Checking pages',
  'Reviewing scripts',
  'Finding exposed paths',
  'Building plain-English report',
]
const FINDINGS = [
  { t: 'Admin page exposed', color: '#FF4D4D' },
  { t: 'Certificate expires soon', color: '#FF8A3D' },
  { t: 'Tracking script sends visitor data', color: '#FFC53D' },
  { t: 'Missing browser protection setting', color: '#5AA0FF' },
]

/* ── matrix3d corner-pin (general 2D projection, Franklin Ta) ── */
type P = [number, number]
function cornerPin(w: number, h: number, TL: P, TR: P, BR: P, BL: P): string {
  const t = general2DProjection(
    0, 0, TL[0], TL[1],
    w, 0, TR[0], TR[1],
    0, h, BL[0], BL[1],
    w, h, BR[0], BR[1],
  )
  for (let i = 0; i < 9; i++) t[i] = t[i] / t[8]
  const m = [
    t[0], t[3], 0, t[6],
    t[1], t[4], 0, t[7],
    0, 0, 1, 0,
    t[2], t[5], 0, t[8],
  ]
  return `matrix3d(${m.join(',')})`
}
function adj(m: number[]) {
  return [
    m[4] * m[8] - m[5] * m[7], m[2] * m[7] - m[1] * m[8], m[1] * m[5] - m[2] * m[4],
    m[5] * m[6] - m[3] * m[8], m[0] * m[8] - m[2] * m[6], m[2] * m[3] - m[0] * m[5],
    m[3] * m[7] - m[4] * m[6], m[1] * m[6] - m[0] * m[7], m[0] * m[4] - m[1] * m[3],
  ]
}
function multmm(a: number[], b: number[]) {
  const c = Array(9)
  for (let i = 0; i < 3; i++)
    for (let j = 0; j < 3; j++) {
      let s = 0
      for (let k = 0; k < 3; k++) s += a[3 * i + k] * b[3 * k + j]
      c[3 * i + j] = s
    }
  return c
}
function multmv(m: number[], v: number[]) {
  return [
    m[0] * v[0] + m[1] * v[1] + m[2] * v[2],
    m[3] * v[0] + m[4] * v[1] + m[5] * v[2],
    m[6] * v[0] + m[7] * v[1] + m[8] * v[2],
  ]
}
function basisToPoints(x1: number, y1: number, x2: number, y2: number, x3: number, y3: number, x4: number, y4: number) {
  const m = [x1, x2, x3, y1, y2, y3, 1, 1, 1]
  const v = multmv(adj(m), [x4, y4, 1])
  return multmm(m, [v[0], 0, 0, 0, v[1], 0, 0, 0, v[2]])
}
function general2DProjection(
  x1s: number, y1s: number, x1d: number, y1d: number,
  x2s: number, y2s: number, x2d: number, y2d: number,
  x3s: number, y3s: number, x3d: number, y3d: number,
  x4s: number, y4s: number, x4d: number, y4d: number,
) {
  const s = basisToPoints(x1s, y1s, x2s, y2s, x3s, y3s, x4s, y4s)
  const d = basisToPoints(x1d, y1d, x2d, y2d, x3d, y3d, x4d, y4d)
  return multmm(d, adj(s))
}

/* ── styles (authored in the DESIGN_W×DESIGN_H space) ── */
const G = '#8BFF3E'
const CSS = `
.htd{ font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color:#EDEDED; }
.htd-glass{
  position:absolute; inset:0; border-radius:14px; overflow:hidden;
  padding:22px 24px;
  display:flex; flex-direction:column; gap:14px;
  /* Neutral near-black LCD — green is accent only, no projection tint. */
  background:
    linear-gradient(165deg, #0b0f16 0%, #070a10 55%, #05080c 100%);
  border:1px solid rgba(255,255,255,0.08);
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.06);
}
/* static top-edge sheen so it reads as a glossy 4K screen, not a hologram */
.htd-sheen{
  position:absolute; left:0; right:0; top:0; height:42%;
  background:linear-gradient(180deg, rgba(255,255,255,0.045), transparent 92%);
  pointer-events:none;
}
/* header */
.htd-header{ display:flex; align-items:center; gap:14px; }
.htd-brand{ display:flex; align-items:center; gap:8px; font-weight:700; font-size:16px; letter-spacing:-0.01em; }
.htd-logo{ width:20px; height:20px; object-fit:contain;
  filter:drop-shadow(0 0 5px rgba(139,255,62,0.35)); }
.htd-scanning{ font-size:12.5px; color:#9A9AA0; margin-left:2px; }
.htd-domain{ color:#EDEDED; font-weight:600; }
.htd-live{ margin-left:auto; display:flex; align-items:center; gap:7px;
  font-size:11.5px; font-weight:600; color:${G};
  padding:4px 10px; border-radius:999px; border:1px solid rgba(139,255,62,0.28);
  background:rgba(139,255,62,0.07); }
.htd-live-dot{ width:7px; height:7px; border-radius:50%; background:${G};
  box-shadow:0 0 8px ${G}; animation: htd-pulse 1.8s ease-in-out infinite; }
/* body */
.htd-body{ display:flex; gap:14px; flex:1; min-height:0; }
.htd-col-left{ width:248px; display:flex; flex-direction:column; gap:12px; }
.htd-col-right{ flex:1; display:flex; flex-direction:column; gap:12px; min-width:0; }
.htd-card{ background:rgba(255,255,255,0.025); border:1px solid rgba(255,255,255,0.07);
  border-radius:11px; padding:13px 14px; }
.htd-card-title{ font-size:11px; text-transform:uppercase; letter-spacing:0.1em;
  color:#6A6A70; margin-bottom:9px; font-weight:600; }
/* score */
.htd-score{ display:flex; align-items:center; gap:13px; }
.htd-score-ring{ position:relative; width:86px; height:86px; flex-shrink:0; }
.htd-ring-bg{ fill:none; stroke:rgba(255,255,255,0.08); stroke-width:7; }
.htd-ring-fg{ fill:none; stroke:${G}; stroke-width:7; stroke-linecap:round;
  filter:drop-shadow(0 0 4px rgba(139,255,62,0.5)); transition:stroke-dashoffset .2s linear; }
.htd-score-num{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; gap:1px; }
.htd-score-num b{ font-size:24px; font-weight:700; color:#fff; line-height:1; }
.htd-score-num span{ font-size:11px; color:#6A6A70; align-self:flex-end; margin-bottom:3px; }
.htd-score-label{ font-size:12.5px; font-weight:600; color:#EDEDED; }
.htd-risk{ font-size:11.5px; color:#FFC53D; margin-top:4px; }
/* counts */
.htd-counts{ flex:1; display:grid; grid-template-columns:1fr 1fr; gap:9px; }
.htd-count{ display:flex; align-items:center; gap:7px;
  background:rgba(255,255,255,0.025); border:1px solid rgba(255,255,255,0.06);
  border-radius:9px; padding:9px 11px; }
.htd-count b{ font-size:16px; font-weight:700; color:#fff; }
.htd-count-label{ font-size:11px; color:#9A9AA0; margin-left:auto; }
.htd-dot{ width:8px; height:8px; border-radius:50%; flex-shrink:0; }
/* progress */
.htd-bar{ height:5px; border-radius:3px; background:rgba(255,255,255,0.08); overflow:hidden; margin-bottom:11px; }
.htd-bar-fill{ height:100%; width:62%; border-radius:3px;
  background:linear-gradient(90deg, #5fcc1a, ${G});
  box-shadow:0 0 8px rgba(139,255,62,0.5); animation: htd-progress 4.5s ease-in-out infinite; }
.htd-steps{ list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:7px; }
.htd-steps li{ display:flex; align-items:center; gap:9px; font-size:12px; color:#6A6A70; }
.htd-steps li.done{ color:#9A9AA0; }
.htd-steps li.active{ color:#EDEDED; }
.htd-step-ic{ width:13px; height:13px; border-radius:50%; flex-shrink:0;
  border:1.5px solid rgba(255,255,255,0.18); }
.htd-steps li.done .htd-step-ic{ background:${G}; border-color:${G};
  box-shadow:0 0 6px rgba(139,255,62,0.5); }
.htd-steps li.active .htd-step-ic{ border-color:${G};
  border-top-color:transparent; animation: htd-spin 1s linear infinite; }
/* findings */
.htd-findings{ flex:1; min-height:0; }
.htd-findings ul{ list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:8px; }
.htd-findings li{ display:flex; align-items:center; gap:9px; font-size:12.5px; color:#EDEDED;
  opacity:0; transform:translateY(4px); animation: htd-fadein .5s ease forwards; }
/* footer */
.htd-footer{ display:flex; gap:12px; align-items:stretch; }
.htd-wade{ flex:1; display:flex; align-items:center; gap:9px;
  border-radius:10px; padding:10px 13px;
  border:1px solid rgba(139,255,62,0.22);
  background:linear-gradient(90deg, rgba(139,255,62,0.10), rgba(139,255,62,0.02));
  position:relative; overflow:hidden; }
.htd-wade::after{ content:''; position:absolute; inset:0;
  background:linear-gradient(110deg, transparent 30%, rgba(255,255,255,0.10) 50%, transparent 70%);
  transform:translateX(-100%); animation: htd-shimmer 4.5s ease-in-out infinite; }
.htd-wade-ic{ width:18px; height:18px; border-radius:50%; flex-shrink:0;
  background:radial-gradient(circle at 35% 30%, ${G}, #2e7a08);
  box-shadow:0 0 8px rgba(139,255,62,0.6); }
.htd-wade-txt{ font-size:12px; color:#D7E8C8; }
.htd-wade-txt b{ color:${G}; }
.htd-monitor{ display:flex; align-items:center; gap:6px; font-size:11px; color:#9A9AA0;
  border-radius:10px; padding:10px 13px;
  border:1px solid rgba(255,255,255,0.07); background:rgba(255,255,255,0.025); }
.htd-monitor b{ color:#EDEDED; font-weight:600; }
.htd-mon-dot{ width:7px; height:7px; border-radius:50%; background:${G};
  box-shadow:0 0 7px ${G}; animation: htd-pulse 2.4s ease-in-out infinite; }
.htd-mon-sep{ opacity:0.4; }

/* keyframes */
@keyframes htd-pulse{ 0%,100%{ opacity:1; transform:scale(1);} 50%{ opacity:0.45; transform:scale(0.82);} }
@keyframes htd-spin{ to{ transform:rotate(360deg);} }
@keyframes htd-fadein{ to{ opacity:1; transform:translateY(0);} }
@keyframes htd-progress{ 0%{ width:38%;} 50%{ width:74%;} 100%{ width:38%;} }
@keyframes htd-shimmer{ 0%,100%{ transform:translateX(-100%);} 55%,70%{ transform:translateX(100%);} }

/* reduced motion: hold everything in its resting/visible state */
.htd-reduce .htd-live-dot,
.htd-reduce .htd-mon-dot,
.htd-reduce .htd-bar-fill,
.htd-reduce .htd-steps li.active .htd-step-ic,
.htd-reduce .htd-wade::after{ animation:none !important; }
.htd-reduce .htd-findings li{ opacity:1 !important; transform:none !important; animation:none !important; }
.htd-reduce .htd-bar-fill{ width:62%; }
`
